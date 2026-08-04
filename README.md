# ovpnmon

OpenVPN 서버에 **누가 접속해 있는지**, 그리고 그 사용자가 **VPN을 통해 어디로 접속하는지**를
실시간으로 추적합니다.

<img width="1086" height="546" alt="image" src="https://github.com/user-attachments/assets/07629af2-1eac-438f-ad66-674483cc5196" />


## 요구 사항

먼저 확인해보십시오 — 아무것도 설치하지 않고 현재 상태만 보고합니다:

```bash
make deps-check
```

```
==> Kernel
  ok      kernel 6.8.0           TCX attachment needs >= 6.6
  ok      BTF                    /sys/kernel/btf/vmlinux present
==> Build toolchain
  ok      go 1.26.5              go.mod needs 1.26.5
  ...
```

부족한 것이 있으면:

```bash
make deps            # 빌드 툴체인 (필요하면 Go도 공식 tarball로 설치)
make deps-dev        # 테스트·벤치마크 도구 (bpftrace, iperf3, jq …)
make deps-all        # 위 둘 다
```

`make deps`는 필요한 Go 버전을 **`go.mod`에서 읽어** 판단합니다. 배포판이 제공하는
Go가 낮으면(예: Ubuntu 24.04는 1.22) 공식 tarball을 받아 sha256을 검증한 뒤
`/usr/local/go`에 설치합니다. 이미 충분하면 아무것도 하지 않습니다.
apt·dnf·yum·pacman을 인식하며, 그 외 배포판에서는 필요한 패키지 목록을 알려줍니다.

정리하면 요구 사항은 이렇습니다:

- Linux 커널 **6.6 이상** (TCX 훅). BTF(`/sys/kernel/btf/vmlinux`) 필요
- OpenVPN 2.4 이상, management 인터페이스 활성화
- 빌드: Go (버전은 `go.mod` 기준)
- **eBPF 재컴파일 시에만**: clang 15+, `libbpf-dev`. 컴파일된 오브젝트가 저장소에
  포함되어 있으므로 `bpf/ovpnmon.bpf.c`를 고치지 않는 한 필요 없습니다
- 실행: root, 또는 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`

> **OpenVPN 2.6의 DCO 주의.** Data Channel Offload가 켜지면 데이터 경로가 `ovpn-dco`
> 커널 모듈로 옮겨가 tun 디바이스를 지나지 않습니다. 서버 설정에 `disable-dco`가
> 필요하며, `make preflight`가 이를 검사합니다.

> **management 인터페이스는 동시 접속을 하나만 받습니다.** ovpnmon이 붙어 있는 동안
> `telnet 127.0.0.1 7505`로 직접 접속하면 연결은 되지만 응답이 오지 않고 대기합니다.
> 수동으로 진단할 일이 있으면 `systemctl stop ovpnmon` 후에 붙거나, 같은 데이터를
> `/api/snapshot`에서 읽으십시오. 같은 이유로 ovpnmon과 다른 OpenVPN 모니터링 도구를
> 같은 포트에 동시에 붙일 수 없습니다.

## 빠른 시작

**OpenVPN 서버 구축은 이 저장소의 범위가 아닙니다.** 이미 쓰고 계신 방법을 그대로
쓰십시오 — 없다면 [Nyr/openvpn-install](https://github.com/Nyr/openvpn-install)이
좋은 기본값입니다. NAT·IP 포워딩·영속 방화벽 규칙까지 처리해 줍니다.

VPN이 이미 돌고 있다는 전제에서:

```bash
git clone https://github.com/HOchacha/openvpn-monitoring
cd openvpn-monitoring

make preflight       # OpenVPN 쪽에 무엇이 필요한지, 재시작이 필요한지
make install         # 빌드 + /opt/ovpnmon 에 설치
sudo systemctl enable --now ovpnmon
```

`make preflight`가 알려주는 대로 OpenVPN 설정에 **두 줄**을 추가해야 할 수 있습니다.
그게 전부입니다:

```
management 127.0.0.1 7505     # 필수 — 없으면 "누가"를 알 수 없습니다
disable-dco                   # OpenVPN 2.6+ 에서만
```

> Nyr 설치 스크립트가 만드는 `server.conf`에는 둘 다 없으므로 추가가 필요합니다.
> 추가 후 OpenVPN을 한 번 재시작해야 하고, **그때 접속자가 끊깁니다.** ovpnmon
> 자체를 설치·시작·중지하는 것은 기존 연결에 아무 영향이 없습니다.

## 배포 상세

### 1. 점검 — 아무것도 바꾸지 않습니다

```bash
make deps-check   # 커널·BTF·툴체인
make preflight    # OpenVPN 쪽에 필요한 변경과 중단 여부
```

`make preflight`는 상태만 읽습니다. 알려주는 것 중 가장 중요한 건 **OpenVPN 재시작이
필요한지**입니다 — 재시작은 모든 클라이언트를 끊습니다.

```
Kernel
  ok       kernel 6.8.0             TCX attachment requires >= 6.6
  ok       BTF                      present
OpenVPN
  ok       openvpn 2.6.19           pid 439876
  ok       config                   /etc/openvpn/server/server.conf
  ok       management               127.0.0.1:7505
  ok       DCO                      already disabled in config
Tunnel
  ok       tun0                     10.8.0.1/24
           suggested ovpnmon settings:  iface = tun0   subnet = 10.8.0.0/24

Verdict
  Ready. OpenVPN needs no changes, so nothing disconnects.
```

### OpenVPN 쪽에 필요한 수정

**두 줄이 전부입니다.** 그마저 이미 있으면 아무것도 바꿀 필요가 없습니다.

```
management 127.0.0.1 7505     # 필수 — 없으면 "누가"를 알 수 없습니다
disable-dco                   # OpenVPN 2.6+ 에서 필요
```

`disable-dco`가 필요한 이유는 Data Channel Offload가 켜지면 데이터 경로가 커널 모듈로
옮겨가 **tun 디바이스를 지나지 않기** 때문입니다. 프로브는 정상적으로 붙지만 아무것도
세지 못합니다.

management에 비밀번호를 걸어둔 서버(`management <host> <port> <pwfile>`)라면 같은
파일을 ovpnmon에도 알려주십시오:

```ini
mgmt-password-file = /etc/openvpn/mgmt-password
```

**그 외에는 아무것도 바꾸지 않습니다:**

- `status`/`status-version` 설정 불필요 — management로 `status 3`을 직접 요청합니다
- PKI·인증서·인증 흐름에 관여하지 않습니다
- 라우팅·방화벽·NAT를 건드리지 않습니다 (운영 서버엔 이미 있습니다)
- 클라이언트를 끊거나 차단할 수 없습니다 — 보내는 명령은 `status 3`과 `exit` 뿐입니다

> management 인터페이스는 **동시 접속을 하나만** 받습니다. 이미 다른 도구(openvpn-monitor,
> 자체 스크립트 등)가 붙어 있다면 공존할 수 없으니 그쪽을 정리해야 합니다.
> 그리고 이 인터페이스는 세션을 kill할 수 있으므로 반드시 루프백으로 제한하십시오.

### 중단이 필요한 경우와 아닌 경우

| 작업 | 영향 |
|---|---|
| ovpnmon 설치·시작·중지 | **무중단.** eBPF 프로브를 붙이는 것은 기존 연결을 건드리지 않습니다 |
| OpenVPN에 `management` 추가 | **전 클라이언트 접속 끊김** (OpenVPN 재시작 필요) |
| OpenVPN에 `disable-dco` 추가 | **전 클라이언트 접속 끊김** (동일) |

preflight가 `Ready`라고 하면 OpenVPN을 건드릴 필요가 없으므로 아무도 끊기지 않습니다.
변경이 필요하다고 나오면 점검 창을 잡으십시오. **OpenVPN 변경을 먼저 하고, ovpnmon
설치는 나중에 아무 때나** 하면 중단을 한 번으로 줄일 수 있습니다.

### 2. 설치 — 무중단입니다

```bash
make deps                    # Go 등 빌드 도구 (없을 때만)
make install                 # 빌드 후 /opt/ovpnmon 에 설치
```

설정을 맞추고 기동합니다. `preflight.sh`가 이 호스트에 맞는 `iface`와 `subnet`을
이미 알려줬을 것입니다:

```bash
sudo vi /opt/ovpnmon/etc/ovpnmon.conf
sudo systemctl enable --now ovpnmon
```

확인:

```bash
curl -s localhost:9095/healthz
curl -s localhost:9095/api/snapshot | jq '.sessions[].common_name'
```

### 3. 선택 — Prometheus / Grafana

```bash
make observability
```

### 업그레이드

```bash
git pull
make install
sudo systemctl restart ovpnmon
```

`make install`은 **기존 설정을 덮어쓰지 않습니다** — 새 기본값은
`ovpnmon.conf.default`로 옆에 떨어뜨리므로 diff해서 확인할 수 있습니다. 이력 DB도
그대로입니다. 재시작 중에는 플로우 집계가 잠시 멈추지만(커널 맵이 비워집니다) 이미
기록된 이력은 남습니다.

**OpenVPN은 재시작하지 마십시오** — 필요 없고, 그것만이 사용자를 끊습니다.

> 빌드 도구를 운영 서버에 두고 싶지 않다면, 빌드 머신에서 `make build`로 만든
> `ovpnmon` 바이너리 하나만 복사해도 됩니다. eBPF 오브젝트가 안에 임베드되어 있어서
> 대상 서버에는 Go도 clang도 커널 헤더도 필요 없습니다. 나머지 파일(설정 샘플,
> systemd 유닛)은 저장소에서 가져오면 됩니다.

### 테스트 클라이언트

서버 설정은 `redirect-gateway`를 push하므로, **같은 호스트에서 그냥 클라이언트를 띄우면
호스트의 기본 경로가 터널로 넘어가 SSH 세션이 끊깁니다.** `dev/test-client.sh`는
클라이언트를 network namespace에 격리해 이 위험을 없앱니다.

```bash
sudo ./dev/test-client.sh up alice
sudo ./dev/test-client.sh exec alice -- curl -s https://example.com -o /dev/null
sudo ./dev/test-client.sh down alice
```

## 인터페이스

| 경로 | 내용 |
|---|---|
| `/` | 실시간 웹 대시보드 (Live / History 탭) |
| `/api/snapshot` | 세션·목적지·프로브 통계 전체 |
| `/api/sessions` | 세션 목록 (`?common_name=alice`로 필터) |
| `/api/events` | 최근 라이브 이벤트 (메모리) |
| `/api/users` | **전체 사용자** — PKI 발급자 + 접속 이력 + 현재 접속 여부 |
| `PUT /api/users/{cn}/note` | 사용자 메모 저장 (빈 값이면 삭제) |
| `POST /api/login` · `/api/logout` | 대시보드 로그인 |
| `/api/stream` | WebSocket 실시간 스트림 |
| `/api/history/hosts` | **누가 어디로** — 목적지별 집계 |
| `/api/history/sessions` | 접속 이력 |
| `/api/history/destinations` | 세션별 목적지 상세 |
| `/api/history/events` | 저장된 DNS/TLS/HTTP 관측 기록 |
| `/api/history/stats` | 저장 현황과 쓰기 상태 |
| `/metrics` | Prometheus 메트릭 |
| `/healthz` | management 연결 상태 |

`/api/history/*`는 `-store`가 설정된 경우에만 존재합니다.

주요 메트릭:

```
openvpn_sessions                                            현재 접속자 수
openvpn_session_info{common_name,virtual_ip,real_address}   접속자 신원
openvpn_client_bytes{common_name,direction}                 터널 내부 평문 바이트
openvpn_tunnel_bytes{common_name,direction}                 OpenVPN이 센 암호화 바이트
openvpn_destination_bytes{common_name,hostname,port,...}    목적지별 바이트
openvpn_probe_events_lost                                   링버퍼 유실 (0이어야 정상)
```

`openvpn_destination_bytes`는 카디널리티가 폭증할 수 있어 클라이언트당 상위 N개만
노출하고 나머지는 `hostname="other"`로 합산합니다 (`-top-destinations`, 기본 20,
`0`이면 비활성화).

## 설치되는 것

### 데몬

| 유닛 | 실행 | 역할 |
|---|---|---|
| `ovpnmon` | root | eBPF 프로브 + 대시보드/API/메트릭 |

OpenVPN 서버 자체와 그 방화벽 규칙은 OpenVPN 설치 스크립트가 관리합니다.

### 파일

ovpnmon이 소유하는 것은 **전부 `/opt/ovpnmon` 아래 한 곳에** 있습니다.
시스템 디렉토리에 흩어놓지 않습니다.

```
/opt/ovpnmon/
├── bin/ovpnmon                 바이너리 (eBPF 오브젝트 임베드, ~25MB)
├── etc/ovpnmon.conf            ★ 설정 (0640) — 여기만 고치면 됩니다
├── etc/firewall.conf           서브넷·인터페이스
├── data/history.db{,-wal,-shm} ★ 접속 이력 (0600, 디렉토리 0700)
└── README.md
```

OS 규약상 다른 곳에 있어야 하는 것은 systemd 유닛 하나뿐입니다:

```
/etc/systemd/system/ovpnmon.service
```

유닛은 `-config` 하나만 넘기고 나머지 설정은 전부 `etc/ovpnmon.conf`에 있으므로,
**설정을 바꾸려고 유닛 파일을 편집할 일이 없습니다.**

제거는 흔적을 남기지 않습니다:

```bash
make uninstall   # 바이너리·설정·유닛 제거, data/ 이력은 보존
make purge       # /opt/ovpnmon 통째로 삭제
```

> 아래는 OpenVPN 설치 스크립트가 만드는 파일입니다. ovpnmon과는 무관하며 여기서 관리하지 않습니다.
>
> ```
> /etc/openvpn/server/{server.conf,ca.crt,server.crt}
> /etc/openvpn/server/server.key            ★ 서버 개인키
> /etc/openvpn/server/tls-crypt.key         ★ 제어 채널 사전 공유키
> /etc/openvpn/easy-rsa/pki/                ★★ CA 개인키를 포함한 PKI 전체
> /etc/openvpn/client-profiles/*.ovpn       ★★ 클라이언트 개인키 포함
> /var/log/openvpn/{server,status}.log, ipp.txt
> /etc/sysctl.d/99-openvpn-forward.conf     net.ipv4.ip_forward = 1
> /etc/logrotate.d/openvpn                  주간 로테이션, 8주 보관
> ```
>
> ★★ 중 `easy-rsa/pki/private/ca.key`가 유출되면 누구나 유효한 클라이언트 인증서를
> 발급할 수 있어 인증 체계 전체가 무너집니다. 운영 환경에서는 CA를 오프라인 장비에
> 두는 것이 정석입니다.

### 커널에만 존재하는 상태 (파일 아님)

```
tun0                       VPN 인터페이스
eBPF 프로그램 2개           tun0의 TCX ingress/egress
BPF 맵 5개                  flows, sessions, events, probe_stats, scratch
```

재부팅하면 사라지고, `ovpnmon` 서비스가 기동하면서 다시 붙입니다. VPN의 NAT·포워딩
규칙은 OpenVPN 설치 스크립트가 관리합니다.

### 빌드에만 필요한 것

`/usr/local/go`와 `clang`·`libbpf-dev` 패키지는 빌드 전용입니다. eBPF 오브젝트가
바이너리에 임베드되므로 **배포 대상 서버에는 필요 없습니다.**

### 디스크 사용량

이력 DB가 유일하게 계속 자라는 부분입니다. 대략적으로 사용자당 하루 수백 KB
수준이며, `-retention`(기본 30일)이 상한을 정합니다. 대부분은 `events` 테이블이
차지하므로, 용량이 문제라면 보관 기간을 줄이는 것이 가장 효과적입니다.

## Prometheus / Grafana

`/metrics`를 직접 긁어도 되지만, 대시보드와 알림까지 한 번에 구성하려면:

```bash
make observability      # Prometheus + Grafana 설치, 프로비저닝까지
```

| | 주소 | 비고 |
|---|---|---|
| ovpnmon | `127.0.0.1:9095` | Prometheus에 9090을 내주고 이동 |
| Prometheus | `127.0.0.1:9090` | |
| Grafana | `127.0.0.1:3000` | 최초 로그인 `admin` / `admin` |

기본은 루프백입니다. 접속은 SSH 터널로:

```bash
ssh -N -L 3000:127.0.0.1:3000 -L 9090:127.0.0.1:9090 ubuntu@<host>
```

### 외부에 노출하려면

`deploy/observability/observability.conf`를 고치고 다시 적용합니다:

```ini
bind_addr       = 0.0.0.0
prometheus_port = 9091      # 9090 이 이미 쓰이고 있다면
```

```bash
make observability-config
```

**노출 전에 반드시:**

1. **Grafana 비밀번호를 바꾸십시오.** 기본값 `admin/admin`으로 열면 곧바로 위험합니다.
   ```bash
   sudo grafana-cli admin reset-admin-password '<새 비밀번호>'
   ```
2. **ovpnmon과 Prometheus에는 인증이 전혀 없습니다.** 방화벽으로 접근 주소를
   제한하거나 리버스 프록시를 앞에 두십시오. 두 엔드포인트 모두 사용자별 접속
   호스트명 목록을 그대로 내어줍니다.
   ```bash
   sudo iptables -A INPUT -p tcp --dport 9095 -s <관리자대역> -j ACCEPT
   sudo iptables -A INPUT -p tcp --dport 9095 -j DROP
   ```

### 설정은 저장소가 원본입니다

클릭으로 만든 대시보드는 Grafana DB와 함께 사라집니다. 여기서는 전부 파일입니다:

```
deploy/observability/
├── install.sh
├── prometheus/
│   ├── ovpnmon-scrape.yml      스크레이프 설정
│   └── ovpnmon.rules.yml       알림 + recording 규칙
└── grafana/
    ├── datasource.yml
    ├── dashboard-provider.yml
    └── dashboards/ovpnmon.json
```

대시보드는 `allowUiUpdates: false`로 프로비저닝됩니다 — UI에서 고쳐도 30초 뒤
파일 내용으로 되돌아갑니다. **JSON을 고치고 `make observability-config`를 돌리십시오.**
그래야 호스트를 다시 만들어도 같은 대시보드가 나옵니다.

Prometheus 쪽도 `prometheus.yml`을 직접 편집하지 않고 `scrape_config_files`와
`rule_files`로 드롭인을 참조하게 합니다. 패키지 업그레이드나 다른 잡에 영향을 주지
않습니다.

### 대시보드

`VPN / OpenVPN — sessions and destinations`. 서버·사용자 변수로 필터할 수 있습니다.

- **Health** — 접속자 수, management 연결 상태, 업/다운로드 **속도와 누적**, 추적 플로우, 유실 이벤트
- **Who** — 사용자별 처리량(다운로드는 음수로 그려 방향 분리), 접속자 테이블
  (인증서 CN·VPN IP·접속 출발지·암호화 방식·접속 시간)
- **Where** — 목적지 Top 20 테이블, 목적지별 트래픽 추이, 사용자별 신규 연결 수
- **Probe and history** — 검사 패킷 수, 이름 해석 현황, 이력 쓰기 상태

### 알림

모니터 자신이 신뢰할 수 있는지를 봅니다. **조용히 눈이 먼 모니터는 없는 것보다 나쁩니다** —
대시보드는 멀쩡해 보이기 때문입니다.

| 알림 | 의미 |
|---|---|
| `OvpnmonDown` | 수집 전면 중단 (프로세스가 죽으면 eBPF도 떨어짐) |
| `OvpnmonManagementUnreachable` | 트래픽은 세지만 사용자에 귀속되지 않음 |
| `OvpnmonRingBufferOverflow` | DNS/TLS 관측 유실 → 목적지가 IP로만 남음 |
| `OvpnmonProbeSeeingNoTraffic` | 접속자는 있는데 패킷이 안 보임 (인터페이스 오지정 또는 DCO) |
| `OvpnmonHistoryWritesFailing` | 감사 로그에 구멍 |
| `OvpnmonHistoryEventsDropped` | 부하로 이력 유실 (쓰기는 논블로킹이 의도) |

Alertmanager는 별도 구성입니다. `prometheus-alertmanager` 패키지를 설치하고
`/etc/prometheus/prometheus.yml`의 `alerting.alertmanagers`를 확인하십시오.

## 이력 (감사 로그)

커널 플로우 맵은 **현재 상태**만 담습니다. 조용해진 대화는 `-flow-idle` 후 사라지고,
재시작하면 전부 없어집니다. `-store`를 켜면 그 내용이 데이터베이스에 남아
"지난주에 누가 어디에 접속했나"를 물어볼 수 있습니다.

```bash
# SQLite (기본 권장 — 파일 하나, 외부 의존성 없음)
ovpnmon -store sqlite:/var/lib/ovpnmon/history.db -retention 720h

# 기존 MySQL 사용
ovpnmon -store 'mysql://ovpnmon:secret@tcp(127.0.0.1:3306)/ovpnmon?parseTime=true'
```

세 개의 테이블이 각각 다른 질문에 답합니다:

| 테이블 | 내용 |
|---|---|
| `sessions` | 누가 언제부터 언제까지, 어느 IP에서 접속했나 |
| `destinations` | 세션별로 어느 목적지에 얼마나 트래픽이 오갔나 |
| `events` | DNS 조회·TLS 접속·HTTP 요청 개별 기록 |

조회 예시:

```bash
# 지난 7일간 alice가 접속한 목적지
curl -s 'localhost:9090/api/history/hosts?common_name=alice&since=7d' | jq

# 특정 도메인에 접속한 사람 전부 (하위 도메인 포함)
curl -s 'localhost:9090/api/history/hosts?hostname=example.com&since=30d' | jq

# 특정 기간의 원본 관측 기록
curl -s 'localhost:9090/api/history/events?from=2026-08-01&to=2026-08-02' | jq
```

`since`는 `30m` `24h` `7d` `2w`를, `from`/`to`는 RFC3339·`YYYY-MM-DD`·unix time·`-7d`
형식을 받습니다. 대시보드의 **History** 탭에서 같은 질의를 폼으로 할 수도 있습니다.

설계상 알아두실 점:

- **쓰기는 비동기입니다.** 모니터링이 감시 대상을 멈춰 세우면 안 되므로, 큐가 가득 차면
  기록을 버리고 카운터를 올립니다. `openvpn_history_events_dropped`가 0이 아니면
  감사 로그에 구멍이 생긴 것이니 경보를 걸어두십시오.
- **바이트는 증분으로 누적됩니다.** 커널 플로우가 만료됐다 되살아나면 카운터가 0부터
  다시 시작하므로, 최대값이 아니라 증가분을 더합니다.
- **ovpnmon을 재시작해도 세션이 쪼개지지 않습니다.** OpenVPN이 알려주는 실제 연결
  시각을 키로 삼아 기존 기록을 이어받습니다. 반대로 프로세스가 비정상 종료되어 열린 채
  남은 세션은 다음 기동 때 마지막 활동 시각으로 닫힙니다.
- `-retention`(기본 30일)이 지난 기록은 하루 한 번 삭제됩니다. `0`이면 영구 보관입니다.
- SQLite 파일은 `0600`으로 생성됩니다.

## 설정

설정은 `/opt/ovpnmon/etc/ovpnmon.conf`에 모여 있습니다. 키 이름은 플래그 이름과
같아서 `ovpnmon -help`에 나오는 것은 무엇이든 파일에도 쓸 수 있습니다.

```ini
iface  = tun0
subnet = 10.8.0.0/24
mgmt   = 127.0.0.1:7505
listen = 127.0.0.1:9090

store     = sqlite:/opt/ovpnmon/data/history.db
retention = 720h

top-destinations = 20
flow-idle        = 5m
name-ttl         = 30m
log-level        = info
```

우선순위는 **커맨드라인 > 설정 파일 > 기본값**입니다. 임시로 하나만 바꿔 실행하려면
플래그를 주면 되고, 파일을 고칠 필요가 없습니다.

**오타는 조용히 무시되지 않고 기동 실패입니다.** 설정 파일의 오타는 그러지 않으면
"왜 이 설정이 안 먹지"를 한참 뒤에 발견하게 됩니다.

```
$ ovpnmon -config /opt/ovpnmon/etc/ovpnmon.conf
ovpnmon: reading config: /opt/ovpnmon/etc/ovpnmon.conf:24: unknown setting "retenshun"
```

전체 옵션은 `ovpnmon -help`에 있습니다.

`listen`의 기본값은 루프백입니다. 외부에 노출한다면 앞단에 인증을 두십시오 —
이 엔드포인트는 사용자들의 접속 내역 전체를 담고 있습니다.

## 한계

- **IPv4만 추적합니다.** IPv6 플로우는 집계되지 않습니다 (DNS AAAA 응답은 캐시에 기록됨).
- **QUIC / HTTP3** (UDP 443)의 ClientHello는 암호화되어 있어 SNI를 볼 수 없습니다.
  이 트래픽은 DNS 응답으로만 이름이 붙습니다.
- **Encrypted Client Hello(ECH)** 를 쓰는 연결은 SNI가 보이지 않습니다.
- **DoH/DoT**를 쓰는 클라이언트는 DNS 신호도 남기지 않습니다. 목적지는 IP로만 남습니다.
- 페이로드 스냅샷은 **512바이트**이며, 그보다 뒤에 있는 SNI 확장은 잘립니다
  (`probe.truncated` 카운터로 관측 가능). ClientHello가 여러 세그먼트로 쪼개진 경우도
  첫 세그먼트만 봅니다.
- 플로우 맵은 65536개 엔트리의 LRU입니다. 초과분은 커널이 오래된 것부터 밀어냅니다.

## 프라이버시

이 도구는 VPN 사용자가 방문하는 호스트명 단위의 접속 기록을 만듭니다.
운영 주체에게 그 권한이 있는지, 사용자에게 고지가 되었는지, 보관 기간이 적절한지는
배포 전에 확인해야 할 사항입니다. 페이로드 본문은 저장하지 않습니다.

`-store` 없이 쓰면 모든 것이 메모리에만 있고 재시작과 함께 사라집니다. `-store`를 켜는
순간부터는 되돌릴 수 없는 기록이 남으므로, **켜기 전에 보관 기간을 정하십시오**
(`-retention`, 기본 30일). 여기에는 사용자의 실제 접속 IP도 포함되며, 이는 목적지보다
민감한 정보입니다 — 소재지와 ISP가 드러납니다.

## 구조

```
bpf/ovpnmon.bpf.c        eBPF 데이터플레인 (플로우 집계 + 페이로드 샘플링)
internal/ebpfx/          프로그램 로드·TCX 부착·맵 접근
internal/mgmt/           OpenVPN management 프로토콜 클라이언트
internal/resolver/       DNS/SNI/HTTP 파서와 이름 캐시
internal/collector/      세 소스를 합쳐 스냅샷 생성
internal/api/            HTTP·WebSocket·대시보드
internal/metrics/        Prometheus exporter
deploy/                  서버 구축 스크립트, systemd 유닛, 테스트 클라이언트
```

`bpf/ovpnmon.bpf.c`를 수정한 뒤에는 `make generate`로 재컴파일해야 합니다.
컴파일된 오브젝트는 바이너리에 임베드되므로, 배포 대상에는 clang이나 커널 헤더가 필요 없습니다.

## 개발

```bash
make generate     # eBPF 재컴파일 + Go 바인딩 생성
make vet          # go vet + gofmt 확인
make test-root    # 커널 verifier 테스트 포함 전체 테스트
```

## 로그인

기본값은 **인증 없음**입니다. 대시보드를 루프백 밖으로 노출한다면 반드시 켜십시오 —
이 화면은 모든 사용자의 접속 내역을 담고 있습니다.

```bash
ovpnmon -hash-password '<password>'      # 해시 출력
```

출력된 값을 `/opt/ovpnmon/etc/ovpnmon.conf`에 넣고 재시작합니다:

```ini
auth-user          = admin
auth-password-hash = $2a$10$...
metrics-token      = <긴 무작위 문자열>
```

- 세션은 **메모리에만** 있습니다. ovpnmon을 재시작하면 전원 로그아웃되고, 훔친 쿠키도
  같이 무효가 됩니다
- 쿠키는 `HttpOnly` + `SameSite=Strict`입니다. 다른 사이트가 운영자 쿠키로 메모를
  수정하는 것을 막습니다
- `/healthz`만 공개입니다 (로드밸런서 헬스체크). 나머지 `/api/*`와 `/metrics`는 세션이
  필요합니다
- **Prometheus는 브라우저 세션이 없으므로** `metrics-token`을 씁니다.
  `make observability-config`가 이 값을 스크레이프 설정으로 복사합니다. 토큰 없이 인증만
  켜면 Prometheus가 401을 받아 대시보드가 빈 채로 남습니다

TLS는 아직 없습니다. 비밀번호가 평문으로 오가므로, 신뢰할 수 없는 망에 노출한다면 앞단에
리버스 프록시로 HTTPS를 두십시오.

## Users 탭

사용자 목록은 easy-rsa `index.txt`(발급된 전체 사용자와 인증서 상태), 이력 DB(접속 횟수와
누적 트래픽), management(현재 접속)를 합쳐 만듭니다. **접속이 끊겨도 목록에서 사라지지
않습니다.**

PKI 경로는 관용적 위치에서 자동 탐지하며, 다른 곳에 있으면 지정합니다:

```ini
pki-index = /path/to/pki/index.txt
server-cn = server              # 서버 인증서는 사용자 목록에서 제외
```

PKI를 읽지 못해도 동작합니다 — 목록이 "접속한 적 있는 사용자"로 좁아집니다.

사용자를 펼치면 **메모**를 남길 수 있습니다 (이력 DB에 저장, 2000자). 이것이 유일한 쓰기
엔드포인트입니다 — 앞단에 인증이 없다면 네트워크에서 닿는 누구나 수정할 수 있으니, 대시보드를
외부에 노출한다면 감안하십시오. 메모로 할 수 있는 일은 텍스트 저장뿐이고, 접속을 끊거나
설정을 바꾸지는 못합니다.

트래픽은 **현재 속도**(큰 숫자)와 **세션 시작 이후 누적**(작은 숫자)을 함께 보여줍니다.
`tunnel_bytes_*`는 OpenVPN이 세는 암호화된 바이트, `flow_*`는 프로브가 터널 내부에서 본
평문 바이트로, 후자가 목적지별로 귀속됩니다.
