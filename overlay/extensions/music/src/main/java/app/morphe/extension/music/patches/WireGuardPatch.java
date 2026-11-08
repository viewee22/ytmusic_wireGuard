package app.morphe.extension.music.patches;

import static app.morphe.extension.music.settings.Settings.PROXY_ALLOW_DIRECT_FALLBACK;
import static app.morphe.extension.music.settings.Settings.PROXY_AUTH_ENABLED;
import static app.morphe.extension.music.settings.Settings.PROXY_ENABLED;
import static app.morphe.extension.music.settings.Settings.PROXY_HOST;
import static app.morphe.extension.music.settings.Settings.PROXY_HTTPS;
import static app.morphe.extension.music.settings.Settings.PROXY_PORT;
import static app.morphe.extension.music.settings.Settings.WIREGUARD_CONFIG;
import static app.morphe.extension.music.settings.Settings.WIREGUARD_ENABLED;
import static app.morphe.extension.music.settings.Settings.WIREGUARD_MANAGES_PROXY;

import android.content.Context;
import android.content.res.AssetManager;
import android.os.Build;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import app.morphe.extension.shared.Logger;
import app.morphe.extension.shared.Utils;

/**
 * Runs a userspace WireGuard tunnel inside the app and points the
 * "Network proxy" patch at the local HTTP proxy the tunnel provides.
 * Only this app's Cronet traffic uses the tunnel; no VpnService is involved.
 */
@SuppressWarnings("unused")
public final class WireGuardPatch {
    private static final String LOCAL_HOST = "127.0.0.1";
    private static final int DEFAULT_PORT = 28765;
    private static final String ASSET_DIRECTORY = "morphe_wireguard";
    private static final String LIBRARY_NAME = "libwgproxy.so";

    private static volatile boolean initialized;

    private static native int nativeStart(String config, int port);

    private static native void nativeStop();

    private static native String nativeLastError();

    private WireGuardPatch() {
    }

    /**
     * Injection point. Called first in Application.onCreate, before any Cronet engine exists.
     */
    public static void initialize(Context context) {
        if (initialized) return;
        initialized = true;

        try {
            if (!Utils.isContextSet()) {
                Utils.setContext(context);
            }

            if (!WIREGUARD_ENABLED.get()) {
                releaseProxySettings();
                return;
            }

            // Fail closed: from here on the app only talks through the local proxy,
            // so if the tunnel cannot start nothing leaks out over the real network.
            routeThroughLocalProxy(DEFAULT_PORT);

            String config = WIREGUARD_CONFIG.get();
            if (config.trim().isEmpty()) {
                notifyFailure("WireGuard configuration is empty");
                return;
            }

            loadEngine(context.getApplicationContext() != null
                    ? context.getApplicationContext()
                    : context);

            final int port = nativeStart(config, DEFAULT_PORT);
            if (port <= 0) {
                notifyFailure(nativeLastError());
                return;
            }
            if (port != DEFAULT_PORT) {
                routeThroughLocalProxy(port);
            }
            Logger.printInfo(() -> "WireGuard tunnel started, local proxy port " + port);
        } catch (Throwable ex) {
            Logger.printException(() -> "WireGuard initialize failure", ex);
            notifyFailure(ex.getMessage());
        }
    }

    private static void routeThroughLocalProxy(int port) {
        WIREGUARD_MANAGES_PROXY.save(true);
        PROXY_ENABLED.save(true);
        PROXY_HOST.save(LOCAL_HOST);
        PROXY_PORT.save(port);
        PROXY_HTTPS.save(false);
        PROXY_AUTH_ENABLED.save(false);
        PROXY_ALLOW_DIRECT_FALLBACK.save(false);
    }

    /**
     * Undoes {@link #routeThroughLocalProxy(int)} once WireGuard is turned off,
     * leaving a proxy the user configured by hand alone.
     */
    private static void releaseProxySettings() {
        if (!WIREGUARD_MANAGES_PROXY.get()) return;
        WIREGUARD_MANAGES_PROXY.save(false);
        if (LOCAL_HOST.equals(PROXY_HOST.get().trim())) {
            PROXY_ENABLED.save(false);
            PROXY_HOST.save("");
        }
    }

    private static void notifyFailure(String reason) {
        final String message = "WireGuard VPN: " + (reason == null || reason.isEmpty() ? "unknown error" : reason);
        Logger.printException(() -> message);
        try {
            Utils.showToastLong(message);
        } catch (Throwable ignored) {
            // Toasts can fail this early on some devices; the log has the reason.
        }
    }

    /**
     * Extracts the engine bundled in the assets to app storage once per engine version and loads it.
     */
    private static void loadEngine(Context context) throws IOException {
        AssetManager assets = context.getAssets();
        String version = readAssetText(assets, ASSET_DIRECTORY + "/version").trim();

        String abi = null;
        for (String candidate : Build.SUPPORTED_ABIS) {
            try (InputStream ignored = assets.open(assetPath(candidate))) {
                abi = candidate;
                break;
            } catch (IOException ignored) {
                // Not bundled for this ABI.
            }
        }
        if (abi == null) {
            throw new IOException("No WireGuard engine for this device's CPU");
        }

        File directory = new File(context.getCodeCacheDir(), "morphe_wireguard");
        if (!directory.isDirectory() && !directory.mkdirs()) {
            throw new IOException("Cannot create " + directory);
        }
        File library = new File(directory, "libwgproxy-" + abi + "-" + version + ".so");

        if (!library.isFile()) {
            File[] old = directory.listFiles();
            if (old != null) {
                for (File file : old) {
                    //noinspection ResultOfMethodCallIgnored
                    file.delete();
                }
            }

            File temp = new File(directory, library.getName() + ".tmp");
            try (InputStream in = assets.open(assetPath(abi));
                 FileOutputStream out = new FileOutputStream(temp)) {
                byte[] buffer = new byte[64 * 1024];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
                out.getFD().sync();
            }
            if (!temp.renameTo(library)) {
                throw new IOException("Cannot write " + library);
            }
        }
        //noinspection ResultOfMethodCallIgnored
        library.setReadOnly();

        System.load(library.getAbsolutePath());
    }

    private static String assetPath(String abi) {
        return ASSET_DIRECTORY + "/" + abi + "/" + LIBRARY_NAME;
    }

    private static String readAssetText(AssetManager assets, String path) throws IOException {
        try (InputStream in = assets.open(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[256];
            int read;
            while ((read = in.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            return out.toString(StandardCharsets.UTF_8.name());
        }
    }
}
