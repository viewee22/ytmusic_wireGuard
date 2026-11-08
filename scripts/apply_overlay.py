#!/usr/bin/env python3
"""Adds the WireGuard VPN patch to a checkout of MorpheApp/morphe-patches.

Usage: apply_overlay.py <overlay repo dir> <morphe-patches dir>
"""
import shutil
import sys
from pathlib import Path

overlay_repo = Path(sys.argv[1]).resolve()
upstream = Path(sys.argv[2]).resolve()

# 1. New source files.
src = overlay_repo / "overlay"
for f in src.rglob("*"):
    if f.is_file():
        dest = upstream / f.relative_to(src)
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(f, dest)
        print("added", dest.relative_to(upstream))


def insert_once(path: Path, anchor: str, text: str, after: bool = True):
    content = path.read_text(encoding="utf-8")
    if text.strip() in content:
        return
    if content.count(anchor) != 1:
        sys.exit(f"{path}: expected the anchor exactly once: {anchor!r}")
    i = content.index(anchor)
    if after:
        i += len(anchor)
    path.write_text(content[:i] + text + content[i:], encoding="utf-8")
    print("patched", path.relative_to(upstream))


# 2. Settings.
insert_once(
    upstream / "extensions/music/src/main/java/app/morphe/extension/music/settings/Settings.java",
    "public class Settings extends SharedYouTubeSettings {\n",
    """
    // WireGuard VPN
    public static final BooleanSetting WIREGUARD_ENABLED = new BooleanSetting("morphe_music_wireguard_enabled", FALSE, true);
    public static final StringSetting WIREGUARD_CONFIG = new StringSetting("morphe_music_wireguard_config", "", true, false, null, parent(WIREGUARD_ENABLED));
    public static final BooleanSetting WIREGUARD_MANAGES_PROXY = new BooleanSetting("morphe_music_wireguard_manages_proxy", FALSE, false, false);
""",
)

# 3. Strings (English default, Korean translation).
STRINGS = {
    "values": {
        "morphe_music_wireguard_screen_title": "WireGuard VPN",
        "morphe_music_wireguard_screen_summary": "Built-in VPN tunnel for this app only",
        "morphe_music_wireguard_enabled_title": "Enable WireGuard VPN",
        "morphe_music_wireguard_enabled_summary": "\"Routes this app's network requests through the WireGuard tunnel. The system VPN is not used.\nWhile enabled, requests fail rather than bypass the tunnel if it cannot connect.\"",
        "morphe_music_wireguard_config_title": "WireGuard configuration",
        "morphe_music_wireguard_config_summary": "\"Paste the whole .conf file, for example one downloaded from your Proton VPN account ([Interface] and [Peer] sections)\"",
    },
    "values-ko-rKR": {
        "morphe_music_wireguard_screen_title": "WireGuard VPN",
        "morphe_music_wireguard_screen_summary": "이 앱에만 적용되는 내장 VPN 터널",
        "morphe_music_wireguard_enabled_title": "WireGuard VPN 사용",
        "morphe_music_wireguard_enabled_summary": "\"이 앱의 네트워크 요청을 WireGuard 터널로 보냅니다. 시스템 VPN은 사용하지 않습니다.\n켜져 있는 동안 터널에 연결하지 못하면 우회하지 않고 요청이 실패합니다.\"",
        "morphe_music_wireguard_config_title": "WireGuard 설정",
        "morphe_music_wireguard_config_summary": "\".conf 파일 내용 전체를 붙여넣으세요. 예: Proton VPN 계정에서 받은 파일 ([Interface], [Peer] 포함)\"",
    },
}
for folder, strings in STRINGS.items():
    path = upstream / "patches/src/main/resources/addresources" / folder / "music/strings.xml"
    lines = "\n    <!-- misc.wireguard.wireGuardPatch -->\n" + "".join(
        f'    <string name="{k}">{v}</string>\n' for k, v in strings.items()
    )
    insert_once(path, "</resources>", lines, after=False)

print("overlay applied")
