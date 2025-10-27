#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/localchat"
APP_PORT="8000"

USE_LOCAL_DB_CONTAINER="yes"
DB_NAME="localchat"
DB_USER="DBADMIN"
DB_PASS=""
DB_PORT="3306"
DB_ROOT_PASS=""

TRUST_PROXY="0"
NUM_PROXIES="1"

S3_BUCKET=""
S3_REGION="ap-northeast-2"
S3_AUTO_CREATE="no"
S3_ENABLE_VERSIONING="no"
S3_ENABLE_SSE="no"
S3_LIFECYCLE_DAYS=""

_is_cmd(){ command -v "$1" >/dev/null 2>&1; }
_log(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
_warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
_err(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }

require_root(){ [ "$(id -u)" -eq 0 ] || { _err "root로 실행하세요"; exit 1; }; }
gen_secret(){ openssl rand -hex 16; }

get_password_input(){
  local prompt="$1" var_name="$2" password="" password_confirm=""
  while true; do
    echo -n "$prompt (엔터=Passw0rd!): "
    read -s password; echo
    if [ -z "$password" ]; then
      eval "$var_name='Passw0rd!'"
      _log "비밀번호 기본값 Passw0rd! 적용"
      break
    fi
    echo -n "비밀번호 확인: "
    read -s password_confirm; echo
    if [ "$password" = "$password_confirm" ]; then
      if [ ${#password} -ge 8 ]; then
        eval "$var_name='$password'"
        _log "비밀번호 설정 완료"
        break
      else
        _warn "8자 이상 필요"
      fi
    else
      _warn "불일치"
    fi
  done
}

detect_pkg_mgr(){
  if _is_cmd dnf; then echo dnf
  elif _is_cmd yum; then echo yum
  elif _is_cmd apt; then echo apt
  else _err "패키지 관리자 없음"; exit 1
  fi
}

install_prereqs(){
  local pm="$1"
  _log "필수 패키지 설치"
  case "$pm" in
    apt)
      apt -y update
      apt -y install python3 python3-pip python3-venv openssl curl gnupg lsb-release awscli jq mariadb-client
      ;;
    dnf|yum)
      $pm -y install python3 python3-pip openssl curl awscli jq mariadb || true
      if ! command -v aws >/dev/null 2>&1; then
        python3 -m pip install --upgrade awscli || { _err "awscli 설치 실패"; exit 1; }
      fi
      ;;
  esac
}

install_docker(){
  local pm="$1"
  if _is_cmd docker && docker --version >/dev/null 2>&1; then
    _log "Docker 존재"
  else
    case "$pm" in
      apt)
        apt -y update
        apt -y install docker.io docker-compose-plugin
        ;;
      dnf|yum)
        if ! $pm repolist 2>/dev/null | grep -qi docker-ce; then
          if _is_cmd dnf; then
            dnf -y install dnf-plugins-core
            dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
          else
            yum -y install yum-utils
            yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
          fi
        fi
        $pm -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        ;;
    esac
  fi
  systemctl enable --now docker
}

ensure_dirs(){ mkdir -p "${APP_DIR}/bin"; }

write_app_py(){
  cat > "${APP_DIR}/app.py" <<'PY'
# ... (Flask app 전체 코드 – 기존 버전 그대로 유지) ...
PY
}

write_requirements(){
  cat > "${APP_DIR}/requirements.txt" <<'REQ'
flask
flask-socketio
eventlet
flask-login
werkzeug
sqlalchemy
pymysql
REQ
}

write_dockerfile(){
  cat > "${APP_DIR}/Dockerfile" <<'DOCKER'
FROM python:3.12-slim
WORKDIR /opt/localchat
RUN apt-get update && apt-get install -y --no-install-recommends build-essential default-libmysqlclient-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt
COPY app.py ./app.py
ENV APP_HOST=0.0.0.0 APP_PORT=8000
EXPOSE 8000
CMD ["python","app.py"]
DOCKER
}

write_compose(){
  if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
    get_password_input "DB 사용자(${DB_USER}) 비밀번호" "DB_PASS"
    get_password_input "DB root 비밀번호" "DB_ROOT_PASS"
    cat > "${APP_DIR}/docker-compose.yml" <<COMPOSE
services:
  db:
    image: mariadb:11.4
    container_name: localchat-db
    restart: unless-stopped
    environment:
      MARIADB_DATABASE: ${DB_NAME}
      MARIADB_USER: ${DB_USER}
      MARIADB_PASSWORD: ${DB_PASS}
      MARIADB_ROOT_PASSWORD: ${DB_ROOT_PASS}
    ports:
      - "3306:3306"
    volumes:
      - localchat_db:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mariadb -h 127.0.0.1 -u root -p${DB_ROOT_PASS} -e 'SELECT 1' || exit 1"]
      interval: 10s
      timeout: 5s
      retries: 20
      start_period: 60s
  app:
    build: .
    container_name: localchat-app
    restart: unless-stopped
    environment:
      DATABASE_URL: "mysql+pymysql://${DB_USER}:${DB_PASS}@db:${DB_PORT}/${DB_NAME}"
      LOCALCHAT_SECRET: "$(gen_secret)"
      APP_HOST: "0.0.0.0"
      APP_PORT: "${APP_PORT}"
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "${APP_PORT}:8000"
volumes:
  localchat_db:
COMPOSE
  fi
}

open_firewall(){
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=${APP_PORT}/tcp --permanent || true
    firewall-cmd --reload || true
  fi
}

compose_up(){ (cd "${APP_DIR}" && docker compose up -d --build); }

aws_login_env(){
  if [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then
    read -rp "AWS Access Key ID: " AWS_AK
    read -rsp "AWS Secret Access Key: " AWS_SK; echo
    export AWS_ACCESS_KEY_ID="$AWS_AK"
    export AWS_SECRET_ACCESS_KEY="$AWS_SK"
  fi
  export AWS_DEFAULT_REGION="${S3_REGION}"
  if [ -z "${S3_BUCKET}" ]; then
    read -rp "S3 버킷 이름: " S3_BUCKET
  fi
  export S3_BUCKET="s3://${S3_BUCKET#s3://}"
}

write_backup_restore_scripts(){
  cat > "${APP_DIR}/bin/backup-s3.sh" <<'BKP'
#!/usr/bin/env bash
set -euo pipefail
TS=$(date +%Y%m%d-%H%M%S)
DUMP="/tmp/db-${TS}.sql.gz"

# DB 컨테이너 내부에서 mysqldump 실행
docker exec localchat-db mysqldump \
  -u${DB_USER} -p${DB_PASS} ${DB_NAME} \
  | gzip > "${DUMP}"

aws s3 cp "${DUMP}" "${S3_BUCKET}/db-${TS}.sql.gz"
aws s3 cp "${DUMP}" "${S3_BUCKET}/db-latest.sql.gz"
rm -f "${DUMP}"
BKP
  chmod +x "${APP_DIR}/bin/backup-s3.sh"

  cat > "${APP_DIR}/bin/restore-s3.sh" <<'RST'
#!/usr/bin/env bash
set -euo pipefail
TMP="/tmp/db-restore.sql.gz"

aws s3 cp "${S3_BUCKET}/db-latest.sql.gz" "${TMP}"
# 컨테이너 내부에서 mysql 실행
gunzip -c "${TMP}" \
  | docker exec -i localchat-db \
      mysql -u${DB_USER} -p${DB_PASS} ${DB_NAME}
rm -f "${TMP}"
RST
  chmod +x "${APP_DIR}/bin/restore-s3.sh"
}

wait_db_ready(){
  local deadline=$((SECONDS+600))
  while :; do
    st="$(docker inspect -f '{{.State.Health.Status}}' localchat-db 2>/dev/null || true)"
    [ "$st" = "healthy" ] && break
    [ $SECONDS -gt $deadline ] && { _err "DB 준비 타임아웃"; exit 1; }
    sleep 3
  done
}

initial_restore_if_exists(){
  if aws s3 ls "${S3_BUCKET}/db-latest.sql.gz" >/dev/null 2>&1; then
    DB_USER="${DB_USER}" DB_PASS="${DB_PASS}" DB_NAME="${DB_NAME}" DB_PORT="${DB_PORT}" \
      "${APP_DIR}/bin/restore-s3.sh"
  fi
}

write_backup_timer(){
  cat > /etc/systemd/system/localchat-backup.service <<UNIT
[Unit]
Description=LocalChat DB S3 백업
After=network.target docker.service
Requires=docker.service
[Service]
Type=oneshot
Environment=DB_USER=${DB_USER}
Environment=DB_PASS=${DB_PASS}
Environment=DB_NAME=${DB_NAME}
Environment=DB_PORT=${DB_PORT}
Environment=S3_BUCKET=${S3_BUCKET}
ExecStart=${APP_DIR}/bin/backup-s3.sh
UNIT
  cat > /etc/systemd/system/localchat-backup.timer <<'UNIT'
[Unit]
Description=LocalChat DB S3 백업 타이머
[Timer]
OnCalendar=*:0/30
Persistent=true
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now localchat-backup.timer
}

write_compose_service(){
  cat > /etc/systemd/system/localchat-compose.service <<UNIT
[Unit]
Description=LocalChat via Docker Compose
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service
[Service]
Type=oneshot
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/docker compose -f ${APP_DIR}/docker-compose.yml up -d
ExecStop=/usr/bin/docker compose -f ${APP_DIR}/docker-compose.yml down
RemainAfterExit=yes
TimeoutStartSec=0
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
  systemctl enable --now localchat-compose.service
}

require_root
PM=$(detect_pkg_mgr)
install_prereqs "${PM}"
ensure_dirs
write_app_py
write_requirements
write_dockerfile
install_docker "${PM}"
write_compose
open_firewall
compose_up
aws_login_env
write_backup_restore_scripts
wait_db_ready
initial_restore_if_exists
write_backup_timer
write_compose_service

_log "설치 완료: http://<서버IP>:${APP_PORT} 접속 후 /setup 에서 최초 관리자 계정 생성"