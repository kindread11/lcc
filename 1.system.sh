#!/usr/bin/env bash
# 파일: /opt/localchat/docker-bootstrap.sh
# 목적: LocalChat 완전 자동 설치(이미지 pull, Compose, 방화벽, AWS S3 백업/복구, systemd)
set -euo pipefail

### ====== 로깅/유틸 ======
_log(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
_warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
_err(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }
_is_cmd(){ command -v "$1" >/dev/null 2>&1; }

require_root(){ [ "$(id -u)" -eq 0 ] || { _err "root 권한 필요 (예: sudo bash $0)"; exit 1; }; }
gen_secret(){ openssl rand -hex 16; }

# 안전한 비밀번호 입력
get_password_input(){
  local prompt="$1" var="$2" p="" pc=""
  while :; do
    echo -n "$prompt (빈 값 입력 시 기본값 Passw0rd! 사용): "
    read -rs p; echo
    if [ -z "$p" ]; then
      eval "$var='Passw0rd!'"
      _log "비밀번호가 입력되지 않아 기본값 Passw0rd! 로 설정되었습니다."
      break
    fi
    echo -n "비밀번호 확인: "
    read -rs pc; echo
    if [ "$p" = "$pc" ]; then
      if [ ${#p} -ge 8 ]; then
        eval "$var=\$p"
        _log "비밀번호 설정 완료"
        break
      else
        _warn "비밀번호는 최소 8자 이상이어야 합니다."
      fi
    else
      _warn "비밀번호가 일치하지 않습니다. 다시 입력하세요."
    fi
  done
}

detect_pkg_mgr(){
  if _is_cmd dnf; then echo dnf
  elif _is_cmd yum; then echo yum
  elif _is_cmd apt-get; then echo apt
  else _err "패키지 관리자(dnf/yum/apt) 미탐지"; exit 1
  fi
}

install_prereqs(){
  local pm="$1"
  _log "필수 패키지 설치 (python3, openssl, curl, awscli, jq)"
  case "$pm" in
    apt)
      apt -y update
      apt -y install python3 python3-pip python3-venv openssl curl gnupg lsb-release awscli jq
      ;;
    dnf|yum)
      $pm -y install python3 python3-pip openssl curl awscli jq || true
      if ! command -v aws >/dev/null 2>&1; then
        _warn "awscli 패키지 미발견 → pip로 설치 시도(awscli v1)"
        python3 -m pip install --upgrade awscli || { _err "awscli 설치 실패"; exit 1; }
      fi
      ;;
  esac
}

### ====== 설정 (필요시 변경) ======
APP_DIR="/opt/localchat"
APP_PORT="8000"

# Docker Hub 이미지 (주문 사양)
APP_IMAGE="kindread11/localchat-app:1.0"
DB_IMAGE="kindread11/localchat-db11.4:1.0"

# DB 컨테이너 사용
USE_LOCAL_DB_CONTAINER="yes"
DB_NAME="localchat"
DB_USER="DBADMIN"
DB_PASS=""           # 실행 중 입력
DB_PORT="3306"       # 컨테이너 내부 포트
DB_ROOT_PASS=""      # 실행 중 입력

# 프록시 옵션
TRUST_PROXY="0"
NUM_PROXIES="1"

### ====== 런타임(Docker/Podman) 설치/선택 ======
# 전역 변수: RUNTIME=("docker"|"podman"), DOCKER_BIN, COMPOSE_BIN, UNIT_WANTS, UNIT_REQUIRES
RUNTIME=""
DOCKER_BIN=""
COMPOSE_BIN=""
UNIT_WANTS=""
UNIT_REQUIRES=""

install_container_runtimes(){
  local pm="$1"

  # 충돌 방지: podman-docker가 docker 래퍼를 덮어쓰는 경우 제거
  if rpm -q podman-docker >/dev/null 2>&1; then
    _log "podman-docker 제거(충돌 방지)"
    (dnf -y remove podman-docker docker || yum -y remove podman-docker docker || true)
  fi

  # 우선 Docker 설치 시도
  if ! _is_cmd docker; then
    _log "Docker 설치 시도"
    case "$pm" in
      apt)
        apt -y update
        apt -y install docker.io docker-compose-plugin || _warn "docker.io 설치 실패(무시 가능)"
        ;;
      dnf|yum)
        if ! $pm repolist 2>/dev/null | grep -qi docker-ce; then
          _log "Docker CE repo 추가"
          if _is_cmd dnf; then
            dnf -y install dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
          else
            yum -y install yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
          fi
        fi
        if ! $pm -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
          _warn "docker-ce 설치 실패 → moby-engine 시도"
          $pm -y install moby-engine moby-cli docker-compose-plugin || _warn "moby-engine 설치 실패(무시 가능)"
        fi
        ;;
    esac
  fi

  # Podman도 함께 설치(양립 지원)
  if ! _is_cmd podman; then
    _log "Podman 설치 시도"
    case "$pm" in
      apt) apt -y install podman ;;     # 필요 시 podman-plugins 포함
      dnf|yum) $pm -y install podman podman-plugins ;;
    esac
  fi
}

select_runtime_and_enable(){
  # 1순위: docker.service
  if systemctl list-unit-files | grep -q '^docker\.service'; then
    _log "Docker 서비스 발견 → 활성화"
    systemctl enable --now docker
    RUNTIME="docker"
    DOCKER_BIN="/usr/bin/docker"
    COMPOSE_BIN="/usr/bin/docker compose"
    UNIT_WANTS="network-online.target"
    UNIT_REQUIRES="docker.service"
    return
  fi

  # 2순위: podman.socket
  if systemctl list-unit-files | grep -q '^podman\.socket'; then
    _log "Podman 소켓 발견 → 활성화"
    systemctl enable --now podman.socket
    RUNTIME="podman"
    DOCKER_BIN="/usr/bin/podman"
    # podman compose 지원(plugins 필요). 없으면 안내 후 종료.
    if $DOCKER_BIN help 2>/dev/null | grep -q "compose"; then
      COMPOSE_BIN="/usr/bin/podman compose"
    elif _is_cmd podman-compose; then
      COMPOSE_BIN="/usr/bin/podman-compose"
    else
      _err "podman compose(또는 podman-compose)가 설치되어 있지 않습니다. 'dnf -y install podman-plugins' 또는 'pip install podman-compose' 후 재실행하세요."
    fi
    UNIT_WANTS="network-online.target"
    UNIT_REQUIRES="podman.socket"
    return
  fi

  # 3순위: docker가 있으나 서비스 파일이 없는 경우(수동 유닛 작성)
  if _is_cmd docker; then
    _warn "docker 바이너리만 존재, service 유닛 없음 → 유닛 생성"
    cat > /etc/systemd/system/docker.service <<'UNIT'
[Unit]
Description=Docker Application Container Engine
Documentation=https://docs.docker.com
After=network-online.target firewalld.service
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
ExecReload=/bin/kill -s HUP $MAINPID
LimitNOFILE=infinity
LimitNPROC=infinity
LimitCORE=infinity
Delegate=yes
KillMode=process
Restart=on-failure
StartLimitBurst=3
StartLimitIntervalSec=60

[Install]
WantedBy=multi-user.target
UNIT
    systemctl daemon-reload
    systemctl enable --now docker
    RUNTIME="docker"
    DOCKER_BIN="/usr/bin/docker"
    COMPOSE_BIN="/usr/bin/docker compose"
    UNIT_WANTS="network-online.target"
    UNIT_REQUIRES="docker.service"
    return
  fi

  _err "사용 가능한 컨테이너 런타임을 찾지 못했거나 활성화 실패"
}

docker_login_if_needed(){
  if [ "$RUNTIME" = "docker" ]; then
    if ! $DOCKER_BIN system info 2>/dev/null | grep -q "Username:"; then
      _log "Docker Hub 로그인 필요 → 프롬프트 표시"
      $DOCKER_BIN login
    else
      _log "Docker Hub 이미 로그인 상태"
    fi
  else
    _log "Podman 사용 중 → Docker Hub 로그인 단계 건너뜀(필요 시 수동 로그인 가능: podman login)"
  fi
}

ensure_dirs(){
  _log "디렉터리 생성: ${APP_DIR}"
  install -d "${APP_DIR}/bin"
}

write_compose(){
  _log "docker-compose.yml 생성"
  if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
    get_password_input "DB 사용자(${DB_USER}) 비밀번호" "DB_PASS"
    get_password_input "DB root 비밀번호" "DB_ROOT_PASS"
  fi

  cat > "${APP_DIR}/docker-compose.yml" <<COMPOSE
services:
  db:
    image: ${DB_IMAGE}
    container_name: localchat-db
    restart: unless-stopped
    environment:
      MARIADB_DATABASE: ${DB_NAME}
      MARIADB_USER: ${DB_USER}
      MARIADB_PASSWORD: ${DB_PASS}
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASS}
    volumes:
      - localchat_dbdata:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mysqladmin ping -h 127.0.0.1 -uroot -p${DB_ROOT_PASS} --silent || exit 1"]
      interval: 60s
      timeout: 30s
      retries: 5
      start_period: 180s

  app:
    image: ${APP_IMAGE}
    container_name: localchat-app
    restart: unless-stopped
    environment:
      DATABASE_URL: "mysql+pymysql://${DB_USER}:${DB_PASS}@db:${DB_PORT}/${DB_NAME}"
      LOCALCHAT_SECRET: "$(gen_secret)"
      APP_HOST: "0.0.0.0"
      APP_PORT: "${APP_PORT}"
      TRUST_PROXY: "${TRUST_PROXY}"
      NUM_PROXIES: "${NUM_PROXIES}"
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "${APP_PORT}:8000"
    pull_policy: always

volumes:
  localchat_dbdata:
COMPOSE

  chmod 600 "${APP_DIR}/docker-compose.yml"
}

open_firewall(){
  _log "방화벽 포트 ${APP_PORT}/tcp 개방"
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=${APP_PORT}/tcp --permanent || true
    firewall-cmd --reload || true
    _log "firewalld: ${APP_PORT}/tcp 허용"
  elif _is_cmd ufw && ufw status | grep -q "Status: active"; then
    ufw allow ${APP_PORT}/tcp || true
    _log "ufw: ${APP_PORT}/tcp 허용"
  else
    _warn "firewalld/ufw 비활성 → 수동 확인 요망"
  fi
}

selinux_hint(){
  if _is_cmd getenforce && [ "$(getenforce)" = "Enforcing" ]; then
    _log "SELinux Enforcing: Docker/Podman 포트 매핑은 일반적으로 추가 설정 불필요"
  fi
}

compose_pull_up(){
  _log "이미지 Pull: ${DB_IMAGE}, ${APP_IMAGE}"
  $DOCKER_BIN pull "${DB_IMAGE}" || true
  $DOCKER_BIN pull "${APP_IMAGE}" || true

  _log "Compose up -d"
  (cd "${APP_DIR}" && eval "${COMPOSE_BIN} up -d")
}

### ====== AWS & S3 백업/복구 ======
aws_login_env(){
  echo
  _log "=== AWS 자격 증명 입력 (화면에 출력하지 않음) ==="
  read -rp "AWS Access Key ID: " AWS_AK
  read -rsp "AWS Secret Access Key: " AWS_SK; echo
  read -rp "AWS Region [ap-northeast-2]: " IN_RG
  AWS_RG="${IN_RG:-ap-northeast-2}"
  export AWS_ACCESS_KEY_ID="$AWS_AK"
  export AWS_SECRET_ACCESS_KEY="$AWS_SK"
  export AWS_DEFAULT_REGION="$AWS_RG"
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    _err "AWS 인증 실패(키/리전 확인 필요)"; exit 1
  fi
  _log "AWS 인증 성공 (리전=${AWS_RG})"

  # 버킷 입력/정규화
  while :; do
    read -rp "S3 버킷 이름 또는 경로(s3://bucket-name) 입력: " S3_IN
    S3_IN="${S3_IN:-}"
    [ -n "$S3_IN" ] || { _warn "빈 값입니다. 다시 입력하세요."; continue; }
    case "$S3_IN" in
      s3://*) S3_BUCKET="$S3_IN" ;;
      *) S3_BUCKET="s3://${S3_IN}" ;;
    esac
    if aws s3 ls "$S3_BUCKET" >/dev/null 2>&1; then
      _log "버킷 접근 확인: $S3_BUCKET"
      break
    else
      _warn "버킷 접근 실패 또는 없음: $S3_BUCKET (권한/리전/이름 확인)"
    fi
  done
  export S3_BUCKET
}

write_backup_restore_scripts(){
  _log "백업/복구 스크립트 생성"
  cat > "${APP_DIR}/bin/backup-s3.sh" <<'BKP'
#!/usr/bin/env bash
set -euo pipefail
# 필요 env: DB_USER, DB_PASS, DB_NAME, S3_BUCKET
TS=$(date +%Y%m%d-%H%M%S)
DUMP="/tmp/db-${TS}.sql.gz"
podman ps >/dev/null 2>&1 && CTR="podman" || CTR="docker"
$CTR exec localchat-db sh -c "mysqldump -u${DB_USER} -p${DB_PASS} ${DB_NAME}" | gzip > "${DUMP}"
aws s3 cp "${DUMP}" "${S3_BUCKET}/db-${TS}.sql.gz"
aws s3 cp "${DUMP}" "${S3_BUCKET}/db-latest.sql.gz"
rm -f "${DUMP}"
BKP
  chmod +x "${APP_DIR}/bin/backup-s3.sh"

  cat > "${APP_DIR}/bin/restore-s3.sh" <<'RST'
#!/usr/bin/env bash
set -euo pipefail
# 필요 env: DB_USER, DB_PASS, DB_NAME, S3_BUCKET
TMP="/tmp/db-restore.sql.gz"
podman ps >/dev/null 2>&1 && CTR="podman" || CTR="docker"
aws s3 cp "${S3_BUCKET}/db-latest.sql.gz" "${TMP}"
gunzip -c "${TMP}" | $CTR exec -i localchat-db sh -c "mysql -u${DB_USER} -p${DB_PASS} ${DB_NAME}"
rm -f "${TMP}"
RST
  chmod +x "${APP_DIR}/bin/restore-s3.sh"
}

write_backup_timer(){
  _log "systemd 타이머(30분) 생성"
  cat > /etc/systemd/system/localchat-backup.service <<UNIT
[Unit]
Description=LocalChat DB S3 백업 실행
After=network.target ${UNIT_REQUIRES}
Requires=${UNIT_REQUIRES}

[Service]
Type=oneshot
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/bin
Environment=DB_USER=${DB_USER}
Environment=DB_PASS=${DB_PASS}
Environment=DB_NAME=${DB_NAME}
Environment=S3_BUCKET=${S3_BUCKET}
ExecStart=${APP_DIR}/bin/backup-s3.sh
UNIT

  cat > /etc/systemd/system/localchat-backup.timer <<'UNIT'
[Unit]
Description=LocalChat DB S3 백업 (30분마다)

[Timer]
OnCalendar=*:0/30
Persistent=true

[Install]
WantedBy=timers.target
UNIT

  systemctl daemon-reload
  systemctl enable --now localchat-backup.timer
}

wait_db_ready(){
  _log "DB health 대기 (최대 10분)"
  local deadline=$((SECONDS+600))
  while :; do
    if ! $DOCKER_BIN ps --format '{{.Names}}' | grep -q '^localchat-db$'; then
      sleep 2; continue
    fi
    local st
    st="$($DOCKER_BIN inspect -f '{{.State.Health.Status}}' localchat-db 2>/dev/null || true)"
    if [ "$st" = "healthy" ]; then
      _log "DB 컨테이너 healthy"
      break
    fi
    if (( SECONDS > deadline )); then
      _err "DB 헬스체크 타임아웃"; exit 1
    fi
    sleep 3
  done
}

initial_restore_if_exists(){
  _log "S3에 최초 복구용 덤프 존재 여부 확인"
  if aws s3 ls "${S3_BUCKET}/db-latest.sql.gz" >/dev/null 2>&1; then
    _log "덤프 발견 → 복구 실행"
    DB_USER="${DB_USER}" DB_PASS="${DB_PASS}" DB_NAME="${DB_NAME}" S3_BUCKET="${S3_BUCKET}" \
      "${APP_DIR}/bin/restore-s3.sh"
    _log "복구 완료"
  else
    _log "S3에 덤프 없음 → 앱이 초기 테이블 생성"
  fi
}

write_compose_service(){
  _log "systemd 유닛(부팅 자동 기동) 생성"
  # ExecStart/Stop에서 bash -lc 로 처리해 compose 명령어와 경로를 안전하게 실행
  cat > /etc/systemd/system/localchat-compose.service <<UNIT
[Unit]
Description=LocalChat via ${RUNTIME^} Compose
After=network-online.target ${UNIT_REQUIRES}
Wants=${UNIT_WANTS}
Requires=${UNIT_REQUIRES}

[Service]
Type=oneshot
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/env bash -lc 'cd "${APP_DIR}" && ${COMPOSE_BIN} up -d'
ExecStop=/usr/bin/env bash -lc 'cd "${APP_DIR}" && ${COMPOSE_BIN} down'
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now localchat-compose.service
  systemctl status --no-pager localchat-compose.service || true
}

### ====== 메인 ======
require_root
PM=$(detect_pkg_mgr); _log "패키지 관리자: ${PM}"

install_prereqs "${PM}"

_log "디렉터리/런타임 준비"
ensure_dirs
install_container_runtimes "${PM}"
select_runtime_and_enable
docker_login_if_needed

write_compose
open_firewall
selinux_hint
compose_pull_up

# AWS 로그인 & S3 연결 (항상; 백업/복구 위해)
aws_login_env
write_backup_restore_scripts
wait_db_ready
initial_restore_if_exists
write_backup_timer
write_compose_service

_log "설치 완료! 브라우저에서 http://<서버IP>:${APP_PORT} 접속 → /setup에서 최초 관리자 계정 생성"
_log "수동 백업: systemctl start localchat-backup.service"
_log "수동 복구: DB_USER/DB_PASS/DB_NAME/S3_BUCKET 환경 설정 후 ${APP_DIR}/bin/restore-s3.sh 실행"
if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
  _log "DB 접속 정보: user=${DB_USER} db=${DB_NAME} (비밀번호는 compose에 설정됨)"
fi