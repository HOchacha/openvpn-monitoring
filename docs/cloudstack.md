# CloudStack 연동

VPN 사용자와 목적지를 CloudStack이 아는 이름으로 바꿔 보여줍니다. 이 문서는
**인증서 이름이 어떤 CloudStack 계정으로 매핑되는지**와, 그 매핑이 애매할 때 어떻게
되는지를 설명합니다.

설정 키는 README의 「설정」을, 캐시 상태는 `GET /api/enrichment`를 보세요.

## 무엇이 붙는가

| 대상 | 붙는 정보 |
|---|---|
| 사용자 (CN) | 계정, 도메인 경로, 표시 이름, 이메일, 상태, 보유 VM 수, Isolated 네트워크 |
| 목적지 (IP) | VM 이름, 소유 계정, 소속 네트워크, 존, 전원 상태 |

목적지 해석은 VM의 **모든** NIC 주소를 대상으로 합니다 — 기본 IP, IPv6, `ipaddresses`,
보조 IP까지. 보조 IP로 가는 트래픽도 그 VM의 트래픽입니다.

## 이름 매핑 규칙

CloudStack 사용자명은 **도메인 안에서만** 유일합니다. `ROOT/eng`와 `ROOT/ops`에 각각
`admin`이 있을 수 있고, 이름만으로는 누구인지 정해지지 않습니다.

그래서 각 사용자를 여러 **별칭**으로 등록하고, 인증서 CN을 그 별칭들과 대조합니다.

`ROOT/eng` 도메인의 `admin` 사용자(계정 `engineering`)라면:

```
admin                    ← 사용자명
engineering              ← 계정명 (사용자명과 다를 때만)
ROOT/eng/admin           ← 전체 도메인 경로로 한정
eng/admin                ← 리프 도메인으로 한정
eng.admin   eng_admin    ← 인증서에 실제로 넣을 수 있는 구분자
ROOT/eng/engineering  eng/engineering  eng.engineering  eng_engineering
```

`/`는 ovpnmon이 발급하는 인증서 CN에 쓸 수 없습니다(경로 조작 위험). 그래서 `.`과 `_`로
이은 형태도 함께 등록합니다 — 도메인을 한정한 CN을 실제로 만들 수 있어야 하기 때문입니다.

계정명은 사용자명과 다를 때만 별칭이 됩니다. 인증서가 사람 이름을 따랐는지 계정 이름을
따랐는지는 여기서 알 수 없어서 둘 다 받습니다.

## 이름이 겹칠 때

**두 사용자가 같은 별칭을 주장하면, 그 별칭은 둘 중 누구도 가리키지 않습니다.**

하나를 고르면 어떤 사람의 트래픽이 **다른 테넌트의 것으로 기록되고**, 화면에는 그런
일이 일어났다는 표시가 전혀 남지 않습니다. 조용히 틀리는 것보다 모른다고 말하는 쪽이
낫습니다.

겹친 이름은 조회 시 "애매함"으로 답하며, 후보를 함께 돌려줍니다:

```json
{
  "source": "cloudstack",
  "ambiguous": true,
  "candidates": ["ROOT/eng/admin", "ROOT/ops/admin"]
}
```

대시보드는 이 사용자를 빈칸이 아니라 경고로 표시합니다. "여러 도메인에 존재한다"와
"CloudStack이 모르는 이름이다"는 취해야 할 조치가 다릅니다.

갱신할 때마다 로그에도 남습니다:

```
level=WARN msg="common name matches more than one CloudStack user; it will not resolve"
  name=admin candidates="ROOT/eng/admin, ROOT/ops/admin"
```

헤더의 상태 표시줄에도 `N ambiguous`로 나옵니다.

**해결 방법**은 인증서를 한정된 이름으로 발급하는 것입니다 — `admin` 대신 `eng.admin`.
겹치지 않는 이름은 영향받지 않습니다.

## 캐시

조회는 전부 메모리에서 이뤄집니다. 대시보드를 한 번 그릴 때 화면의 모든 목적지에 대해
조회가 일어나므로, 주소마다 관리 서버를 왕복하면 페이지가 못 쓰게 되고 분 단위로 바뀌는
데이터를 위해 CloudStack을 두들기게 됩니다.

`cloudstack-refresh`(기본 1분)마다 `listUsers` · `listVirtualMachines` ·
`listNetworks` · `listDomains`를 호출해 **전체 뷰를 새로 만들고 통째로 교체**합니다.
부분 갱신이면 어떤 사용자의 레코드가 바뀌는 그 순간만 "모르는 사용자"로 보입니다.

**갱신이 실패하면 이전 뷰를 그대로 둡니다.** 비우면 CloudStack이 잠깐 멈출 때마다 모든
사용자와 목적지의 라벨이 사라집니다. 같은 이유로 `/api/enrichment`는 `/healthz`와
분리돼 있습니다 — 오래된 뷰는 라벨링이 나빠지는 것이지 모니터링이 죽은 게 아니므로,
로드 밸런서에 unhealthy로 보이면 안 됩니다.

CloudStack이 응답하지 않아도 VPN 모니터링 자체는 영향받지 않습니다.

## 페이지네이션

CloudStack은 페이지 지정이 없으면 `default.page.size`(기본 500)에서 응답을 자르고,
진짜 총계는 `count`로만 알려줍니다. 그래서 `count`를 기준으로 페이지를 끝까지 돕니다.
이게 없으면 VM이 500대를 넘는 순간부터 **일부만 조용히 보입니다**.

응답이 자기 `count`와 어긋나도 무한 루프에 빠지지 않도록, 아무것도 늘지 않는 페이지에서
멈춥니다.

## 권한

읽기 전용 호출만 합니다 — `listUsers`, `listVirtualMachines`, `listNetworks`,
`listDomains`, 그리고 시작 시 `listCapabilities` 한 번. CloudStack의 무엇도 바꾸지
않으므로 **읽기 전용 계정으로 키를 발급하는 것을 권합니다.**

키는 CloudStack UI의 Accounts → 사용자 → Generate Keys에서 만듭니다.

## 상태 확인

```bash
curl -s -b cookie http://127.0.0.1:9095/api/enrichment
```

```json
{"enabled":true,"source":"cloudstack","healthy":true,
 "last_refresh":"...","users":3,"addresses":0,"networks":0}
```

`addresses`가 0이면 **자격증명 문제가 아니라 CloudStack에 VM이 없는 것**입니다. 이
구분이 안 되면 목적지 이름이 안 뜰 때 원인을 찾을 수 없어서, 헤더에도 같은 수치를
띄웁니다.

실제 관리 서버를 대상으로 확인하려면:

```bash
CS_URL=http://cloudstack:8080/client/api CS_KEY=... CS_SECRET=... \
  go test ./internal/cloudstack -run Live -v
```

`-run LiveDump`는 그 자격증명으로 무엇이 보이는지(계정·도메인·존·VM·네트워크·호스트)를
찍어 줍니다. 자격증명이 없으면 두 테스트 모두 skip됩니다.

## 한계

- **목적지 해석은 실데이터로 미검증입니다.** 이 배포의 CloudStack에 존·호스트·VM이
  없어서, 주소→VM 경로는 목 서버로만 확인했습니다.
- **CN 매핑은 이름 기반입니다.** 인증서와 CloudStack 계정을 잇는 것은 문자열 일치뿐이고,
  둘 사이에 강제되는 관계는 없습니다.
- **도메인 이동을 감지하지 않습니다.** 사용자가 다른 도메인으로 옮겨가면 다음 갱신에
  새 도메인으로 바뀔 뿐, 그런 일이 있었다는 기록은 남지 않습니다.
