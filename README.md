# openstack-doctor

OpenStack 위에서 **kubespray (Ansible)** 로 쿠버네티스 클러스터를 만들다가
중간에 멈추는 상황을 진단하는 도구입니다.

OpenStack 인증 정보만 주면

- **Keystone / Nova / Neutron / Cinder / Glance / Octavia / Heat / Quota
  / Flavors / SecurityGroups** 를 훑어서 어디가 막혔는지 찾아내고,
- **클러스터 시나리오 룰**(인스턴스 미생성, IP 미할당, API LB 누락 등) 을 적용하고,
- **(선택)** SSH 정보가 있을 때만 컨트롤러/컴퓨트/k8s 노드에 접속해
  systemd 상태·journal·NTP·MTU·conntrack 까지 모아 줍니다.

## 운영 안전 보장 (가장 중요)

이 도구는 **운영 OpenStack 에 변경도, 부하도 가하지 않도록** 다층으로 막혀 있습니다.

| 보호 계층 | 무엇을 막는가 | 어디서 |
|---|---|---|
| HTTP 메서드 화이트리스트 | `GET/HEAD/OPTIONS` 외 모든 호출. 토큰 갱신용 `POST /auth/tokens` 만 예외 | `safety.install_readonly_guard` |
| 레이트 리밋 (`--rps`, 기본 2) | 초당 요청 수 폭주 | `safety.RateLimiter` |
| 호출당 타임아웃 (`--api-timeout`, 기본 30s) | 한 요청이 무한정 매달리는 것 | `Session.timeout` |
| 글로벌 요청 예산 (`--max-requests`, 기본 2000) | 실행 전체에서 일정 횟수 이상 호출 | `safety.Budget` |
| 글로벌 시간 예산 (`--total-timeout`, 기본 600s) | 실행 전체 wall-clock 초과 | `safety.Budget` |
| 회로 차단기 (`--consec-failure-limit`, 기본 5) | 연속 실패 시 즉시 모든 호출 중단 | `safety.Budget` |
| SDK 자동 재시도 비활성화 | 5xx/타임아웃에 대한 폭주성 재시도 증폭 | `auth.connect` 의 retries=0 |
| 페이지네이션 상한 (`--max-items`, 기본 500) | 단일 list 호출이 수만 개를 가져오는 것 | `safety.bounded_list` |
| 절대 상한 (`ABSOLUTE_MAX_ITEMS=5000`) | `--max-items 0` (무제한) 옵션이 와도 더 못 가져오게 | `safety.bounded_list` |
| 사전 latency 측정 + 경고 | 클라우드가 이미 느릴 때 사용자가 보수 모드로 갈 수 있게 | `auth.connect` 의 preflight |
| `--polite` 프리셋 | 위 모든 값을 한 번에 가장 보수적으로 | `cli.diagnose` |
| `--dry-run` | 인증/카탈로그 점검 외 *진짜 호출은 한 건도* 안 보냄 | `safety.install_dry_run` |
| `all_projects=True` 절대 미사용 | 의도치 않게 다른 테넌트 자원 스캔 | grep 으로 검증됨 |

리포트 `context.safety` 섹션에 `allowed_requests` / `blocked_writes` /
`budget_used` / `circuit_tripped` / `preflight_latency_ms` 등이 같이 출력됩니다.
이 중 `blocked_writes` 가 0이 아니면 *코드 버그* 신호이므로 이슈로 보고해 주세요.

> 참고: wrapper 설치 순서는
> `readonly_guard -> budget -> rate_limiter -> [dry_run] -> transport`
> 입니다. dry-run 모드에서도 readonly_guard / budget / rate_limiter 는 그대로
> 동작하므로 (1) `blocked_writes` 카운터가 dry-run 에서도 의미 있고,
> (2) 만약 코드가 실수로 쓰기를 시도하면 dry-run 으로 조용히 넘어가지 않고
> `WriteAttemptBlocked` 로 즉시 잡힙니다.

### 처음 운영에 붙일 때 권장 순서

```bash
# 1) 진짜 아무것도 안 건드리는지 확인 (인증만 함)
openstack-doctor diagnose --cloud my-openstack --dry-run

# 2) 보수 모드로 일부만
openstack-doctor diagnose --cloud my-openstack --polite \
    --only keystone,nova,neutron --skip-readiness

# 3) 정상 확인 후 전체
openstack-doctor diagnose --cloud my-openstack --markdown report.md
```

## 부재 / 누락에 대한 자세

- **일부 OpenStack 서비스가 미설치**여도 (예: Octavia 없음, Heat 없음)
  카탈로그에서 자동 감지하여 해당 체크는 `INFO` 로 “미설치, skip” 처리됩니다.
- **SSH 정보가 없어도** OpenStack API 만으로 진단합니다.
  `nodes:` 섹션이 비어 있으면 노드 수집은 깔끔히 건너뜁니다.
- **kubespray 자체는 K8s Job 안에서 돌아 외부에서 보이지 않습니다.**
  그래서 “kubespray 내부”를 들여다보는 점검은 빼고,
  대신 *OpenStack 쪽에서 보이는 클러스터 상태*(인스턴스/포트/LB/SG/이미지/flavor)를
  교차검증하는 `cluster_readiness` 모듈로 대체했습니다.
  이 시나리오 전체를 끄고 싶으면 `--skip-readiness` 를 주세요.

## 설치

```bash
cd openstack-doctor
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## 가장 빠른 사용법

`clouds.yaml` 만 있는 경우

```bash
openstack-doctor diagnose \
  --cloud my-openstack \
  --name-prefix my-k8s- \
  --image-name ubuntu-22.04 \
  --expected-nodes 6 \
  --expected-flavors k8s.master,k8s.worker \
  --markdown report.md --json report.json
```

`OS_*` 환경변수만 있는 경우

```bash
source openrc.sh
openstack-doctor diagnose --name-prefix my-k8s-
```

YAML 한 파일로 인증 + (선택) SSH 정보 한꺼번에

```bash
openstack-doctor diagnose --config ./my-cluster.yaml --markdown report.md
```

## 단일 노드만 진단 (인증정보 없이도 가능)

```bash
openstack-doctor collect-node \
  --host 10.0.0.21 --user ubuntu --key ~/.ssh/id_rsa \
  --role compute
```

## 어떤 패턴을 잡아내나

- **Nova**
  - `ERROR` / `BUILD` 고착 인스턴스 + 해당 인스턴스의 `server actions` 마지막 실패 메시지까지 함께 출력 (가장 결정적인 단서)
  - `nova-compute` 다운, 하이퍼바이저 down/disabled
- **Neutron**
  - 인스턴스 포트 `DOWN`, agent dead, 라우터 비정상, FIP 비정상
- **Cinder**
  - 볼륨 `error*` / `attaching` 고착, cinder 서비스 down
- **Glance**
  - 필요한 이미지 부재/비활성, private 이미지 가시성, 비표준 disk_format, SCSI 디스크 버스 등 cloud-init 호환성
- **Octavia** *(미설치면 자동 skip)*
  - LB `PENDING_*` 고착, `ERROR`, 멤버 헬스체크 실패, 풀/리스너 누락
- **Heat** *(미설치면 자동 skip)*
  - 스택 `*_FAILED` / `*_IN_PROGRESS` 고착
- **Quota**
  - cores / RAM / instances / ports / floatingips / SG 룰 임계 초과
- **Flavors**
  - 기대 flavor 부재, 기존 인스턴스가 참조하는 flavor 가 카탈로그에 없는 경우
- **SecurityGroups**
  - 22 / 6443 / 2379-2380 / 10250 / 10257 / 10259 / 179 / 4789 / 8472 / 51820 누락 audit (`--skip-sg-audit` 로 끄기 가능)
- **cluster_readiness**
  - 기대 노드 수 미달, 인스턴스에 IP 없음, k8s API LB 리스너 누락, 클러스터 SG 부재
- **노드 SSH (선택)**
  - controller: nova-* / neutron-server / octavia-* / rabbitmq / mariadb / haproxy
  - compute: nova-compute / neutron-*-agent / openvswitch / libvirtd
  - k8s: kubelet / containerd / docker
  - 디스크 사용률 90/95% 경고
  - **NTP 시계 동기화** 점검 (etcd lease, 토큰 만료 원인)
  - **MTU 일관성** (오버레이 네트워크 MTU mismatch 추적)
  - **conntrack 사용률** (포화시 신규 연결 drop)
  - **호스트키는 기본적으로 strict**: `~/.ssh/known_hosts` 에 등록되지 않은 호스트는
    접속 거부됩니다. MITM 위험을 감수하고 자동 신뢰가 필요하면
    `--insecure-ssh` 또는 yaml `ssh.insecure_host_key: true` 로 명시적 opt-in.
  - **유닛 이름 화이트리스트**: yaml/CLI 로 들어오는 systemd 유닛 이름은
    `[A-Za-z0-9_.@:+-]+` 만 허용 (셸 메타문자가 들어 있으면 거부 + WARN 으로 표시).
  - 한 노드에 대한 모든 명령은 **단일 SSH 세션** 으로 실행되고 bastion 도 함께
    정리됩니다 (이전 버전 대비 명령당 SSH 핸드셰이크/bastion leak 없음).

## 결과 포맷

- 콘솔: 색상 요약 표 + 항목별 상세 (Rich)
- `--json <path>`: 머신 파싱용
- `--markdown <path>`: PR/이슈에 그대로 붙이기 좋은 리포트
- `--snapshot <dir>`: 원본 응답을 폴더에 저장 → 오프라인 분석/재현
- `--redact`: 리포트에서 IP/토큰/비밀값 마스킹
- 종료 코드: `--fail-on warn|error|critical` 로 CI 게이팅 가능 (기본 `error`, 임계 이상이면 `2`)

## 설계 메모

- 모든 OpenStack 호출은 `openstacksdk` 한 가지로 통일.
- 체크 모듈은 `openstack_doctor/checks/<service>.py` 한 파일 = 한 서비스.
  새 서비스 진단을 추가하려면 같은 시그니처 `run(handle, ctx) -> CheckResult` 만 만들고
  `checks/__init__.py` 의 `REGISTRY` 에 등록하면 됩니다.
- 시나리오 룰(여러 서비스 데이터를 조인)은 `cluster_readiness.py` 에 따로 모았습니다.
- SSH 모듈은 `paramiko` 만 사용하고, 실행 명령은 read-only 화이트리스트
  (`systemctl is-active`, `journalctl -n N`, `df`, `chronyc tracking`, `ip -o link` 등) 입니다.

## 개발 / 테스트

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

ruff check .         # 린트
mypy                 # 타입 체크 (openstack_doctor 패키지)
pytest -ra           # 회귀 테스트 (tests/)
```

`tests/` 는 OpenStack 클라우드 없이 실행됩니다. 가장 안전 민감한 부분
(드라이런/리드온리 가드 래퍼 체인, SSH 토큰 화이트리스트, CLI 컨텍스트
우선순위, 마크다운 코드펜스 이스케이프, 인벤토리 캐시) 을 회귀로 고정해
둡니다. GitHub Actions(`.github/workflows/ci.yml`) 에서 위 세 단계를
`python 3.10/3.11/3.12` 매트릭스로 게이팅합니다.

## 더 붙이기 좋은 다음 기능

- RabbitMQ 큐 깊이 점검 (controller SSH 후 `rabbitmqctl list_queues`)
- placement / cells_v2 mapping 일관성 점검
- 두 시점 리포트 `diff` (“언제부터 망가졌나”)
- Slack / GitLab MR 자동 코멘트 (CI 의 `--fail-on` 와 결합)
- amphora 인스턴스 자동 추적 (Octavia → Nova 교차)
