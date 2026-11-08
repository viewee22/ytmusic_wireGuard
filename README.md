# Morphe + WireGuard VPN (YouTube Music)

[Morphe patches](https://github.com/MorpheApp/morphe-patches)에 **WireGuard VPN** 패치를 추가해서 빌드하는 저장소입니다.
YouTube Music 앱 안에서만 WireGuard 터널(예: Proton VPN 무료/유료 서버)을 쓰고, 시스템 VPN은 그대로 비워 둡니다.

## 동작 방식

- 앱 안에 WireGuard 엔진(wireguard-go, userspace netstack)을 넣고, `127.0.0.1`에서 HTTP 프록시로 띄웁니다.
- Morphe의 기존 **Network proxy** 패치가 Cronet(유튜브 뮤직 네트워크 스택)을 그 프록시로 보냅니다.
- 터널이 연결되지 않으면 우회하지 않고 요청이 실패합니다(실제 IP 노출 방지).

## 빌드 (GitHub Actions)

1. 이 폴더의 내용 전체를 새 GitHub 저장소에 올립니다(`.github` 폴더 포함).
2. 저장소의 **Actions** 탭에서 `Build WireGuard patches`가 자동으로 실행됩니다(약 15~25분).
   - 다른 Morphe 버전으로 빌드하려면 **Run workflow**에서 태그(예: `v2.1.0`)를 입력합니다.
3. 끝나면 **Releases**에 `patches-2.1.0-wg.N.mpp`가 올라옵니다.

## 구성

| 경로 | 내용 |
|---|---|
| `wireguard-proxy/` | Go로 만든 WireGuard 엔진 + 로컬 HTTP 프록시 (JNI 공유 라이브러리) |
| `overlay/` | Morphe 패치(Kotlin)와 확장(Java) 소스 |
| `scripts/apply_overlay.py` | 원본 Morphe 패치에 설정 항목과 문자열을 추가 |
| `.github/workflows/build.yml` | 엔진 빌드 → 패치 적용 → `.mpp` 빌드 → 릴리스 |

라이선스: Morphe patches와 같은 GPLv3 (Section 7 추가 조건 포함). wireguard-go는 MIT.
