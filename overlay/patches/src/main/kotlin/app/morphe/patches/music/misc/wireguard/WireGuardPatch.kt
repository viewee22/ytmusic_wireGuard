package app.morphe.patches.music.misc.wireguard

import app.morphe.patcher.extensions.InstructionExtensions.addInstruction
import app.morphe.patcher.patch.PatchException
import app.morphe.patcher.patch.listApkEntries
import app.morphe.patcher.patch.patch
import app.morphe.patcher.patch.resourceFile
import app.morphe.patches.all.misc.resources.addResourcesPatch
import app.morphe.patches.music.misc.extension.hooks.YouTubeMusicApplicationInitFingerprint
import app.morphe.patches.music.misc.extension.sharedExtensionPatch
import app.morphe.patches.music.misc.proxy.networkProxyPatch
import app.morphe.patches.music.misc.settings.PreferenceScreen
import app.morphe.patches.music.misc.settings.settingsPatch
import app.morphe.patches.music.shared.Constants.COMPATIBILITY_YOUTUBE_MUSIC
import app.morphe.patches.shared.misc.settings.preference.InputType
import app.morphe.patches.shared.misc.settings.preference.PreferenceScreenPreference
import app.morphe.patches.shared.misc.settings.preference.SwitchPreference
import app.morphe.patches.shared.misc.settings.preference.TextPreference
import app.morphe.util.inputStreamFromBundledResource
import java.security.MessageDigest

private const val EXTENSION_CLASS = "Lapp/morphe/extension/music/patches/WireGuardPatch;"

/** Where the engine is bundled in the patches, and where it is put in the APK. */
private const val BUNDLED_DIRECTORY = "wireguard"
private const val ASSET_DIRECTORY = "assets/morphe_wireguard"
private const val LIBRARY_NAME = "libwgproxy.so"

private val SUPPORTED_ABIS = listOf("arm64-v8a", "armeabi-v7a", "x86_64")

@Suppress("unused")
val wireGuardPatch = patch(
    name = "WireGuard VPN",
    description = "Adds a built-in WireGuard tunnel, such as a Proton VPN WireGuard configuration. " +
            "Only this app's network requests use the tunnel, and the system VPN stays free for other apps.",
    default = false,
) {
    dependsOn(
        sharedExtensionPatch,
        settingsPatch,
        addResourcesPatch,
        // Routes Cronet through the local proxy the WireGuard engine provides.
        networkProxyPatch,
    )

    compatibleWith(COMPATIBILITY_YOUTUBE_MUSIC)

    execute {
        // Bundle the engine for the ABIs the APK has native libraries for.
        val apkAbis = listApkEntries("lib/")
            .mapNotNull { it.split('/').getOrNull(1) }
            .filter { it.isNotEmpty() }
            .toSet()
        val targetAbis = SUPPORTED_ABIS.filter { apkAbis.isEmpty() || it in apkAbis }

        val digest = MessageDigest.getInstance("SHA-256")
        var bundled = 0
        targetAbis.forEach { abi ->
            val bytes = inputStreamFromBundledResource(BUNDLED_DIRECTORY, "$abi/$LIBRARY_NAME")
                ?.use { it.readBytes() }
                ?: return@forEach

            resourceFile("$ASSET_DIRECTORY/$abi/$LIBRARY_NAME", false).writeBytes(bytes)
            digest.update(abi.toByteArray())
            digest.update(bytes)
            bundled++
        }
        if (bundled == 0) {
            throw PatchException("The WireGuard engine is not bundled for any of: $targetAbis")
        }

        // Lets the extension tell whether the extracted engine is current.
        val version = digest.digest().joinToString("") { "%02x".format(it) }.take(16)
        resourceFile("$ASSET_DIRECTORY/version", false).writeText(version)

        PreferenceScreen.MISC.addPreferences(
            PreferenceScreenPreference(
                key = "morphe_music_wireguard_screen",
                sorting = PreferenceScreenPreference.Sorting.UNSORTED,
                preferences = setOf(
                    SwitchPreference("morphe_music_wireguard_enabled", summary = true),
                    TextPreference(
                        "morphe_music_wireguard_config",
                        inputType = InputType.TEXT_MULTI_LINE,
                    ),
                ),
            ),
        )

        // Runs first in Application.onCreate, before the Cronet engine is built.
        YouTubeMusicApplicationInitFingerprint.method.addInstruction(
            0,
            "invoke-static/range { p0 .. p0 }, $EXTENSION_CLASS->initialize(Landroid/content/Context;)V",
        )
    }
}
