#!/usr/bin/env bash
# /opt/localchat/install.sh
# 목적: LocalChat 서버를 리눅스에 자동 설치 (Python venv + MariaDB + 방화벽 + SELinux + systemd)
set -euo pipefail

### ---- 설정 값(필요시 수정) ----
APP_DIR="/opt/localchat"
SERVICE_NAME="localchat.service"
APP_PORT="8000"
CREATE_LOCAL_DB="yes"        # 로컬 MariaDB 설치/설정 수행: yes|no
DB_NAME="localchat"
DB_USER="lc_user"
DB_PASS=""                   # 비워두면 랜덤 생성
DB_HOST="127.0.0.1"
DB_PORT="3306"

### ---- 내부 헬퍼 ----
_is_cmd() { command -v "$1" >/dev/null 2>&1; }
_log() { echo -e "\033[1;32m[INFO]\033[0m $*"; }
_warn() { echo -e "\033[1;33m[WARN]\033[0m $*"; }
_err() { echo -e "\033[1;31m[ERROR]\033[0m $*"; }

require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    _err "root로 실행하세요: sudo $0"
    exit 1
  fi
}

gen_secret() { python3 -c 'import secrets; print(secrets.token_hex(16))'; }
gen_password() { tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16; echo; }

detect_pkg_mgr() {
  if _is_cmd dnf; then echo dnf; return
  elif _is_cmd apt; then echo apt; return
  elif _is_cmd yum; then echo yum; return
  else _err "지원 패키지 관리자 미탐지(dnf/apt/yum)."; exit 1
  fi
}

ensure_python_stack() {
  local pmgr="$1"
  _log "Python/컴파일 의존 패키지 설치"
  case "$pmgr" in
    dnf|yum)
      $pmgr -y install python3 python3-venv python3-devel gcc \
        mariadb-connector-c-devel policycoreutils-python-utils || true
      ;;
    apt)
      apt -y update
      apt -y install python3 python3-venv python3-dev build-essential \
        default-libmysqlclient-dev policycoreutils-python-utils || true
      ;;
  esac
}

ensure_app_dir() {
  _log "앱 디렉터리 준비: $APP_DIR"
  mkdir -p "$APP_DIR"
  cd "$APP_DIR"
  if [ ! -f "$APP_DIR/app.py" ]; then
    _err "$APP_DIR/app.py 가 없습니다. 먼저 app.py를 배치하세요."
    exit 1
  fi
}

create_venv_and_deps() {
  _log "Python 가상환경 구성 및 의존 모듈 설치"
  python3 -m venv .venv
  "$APP_DIR/.venv/bin/pip" install --upgrade pip
  "$APP_DIR/.venv/bin/pip" install flask flask-socketio eventlet flask-login werkzeug sqlalchemy pymysql
}

install_mariadb_local() {
  local pmgr="$1"
  _log "MariaDB(로컬) 설치 및 기동"
  case "$pmgr" in
    dnf|yum)
      $pmgr -y install mariadb-server
      systemctl enable --now mariadb || systemctl enable --now mariadb.service
      ;;
    apt)
      apt -y install mariadb-server
      systemctl enable --now mariadb
      ;;
  esac
}

prepare_database() {
  _log "DB 접속 정보 준비 및 DB/계정 생성"
  if [ -z "$DB_PASS" ]; then
    DB_PASS="$(gen_password)"
    _log "DB 비밀번호 자동 생성: $DB_PASS"
  fi
  # MariaDB root는 기본 socket 인증이므로 비밀번호 없이 실행 가능(초기 상태 가정)
  mysql -u root <<SQL
CREATE DATABASE IF NOT EXISTS \`$DB_NAME\` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER IF NOT EXISTS '$DB_USER'@'%' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON \`$DB_NAME\`.* TO '$DB_USER'@'%';
FLUSH PRIVILEGES;
SQL
}

write_env_file() {
  _log ".env 작성"
  local secret
  secret="$(gen_secret)"
  cat > "$APP_DIR/.env" <<EOF
DATABASE_URL=mysql+pymysql://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$DB_NAME
LOCALCHAT_SECRET=$secret
APP_HOST=0.0.0.0
APP_PORT=$APP_PORT
# 프록시 뒤에서 실제 클라이언트 IP 인식 필요 시 활성화
# TRUST_PROXY=1
# NUM_PROXIES=1
EOF
  chmod 600 "$APP_DIR/.env"
  _log "DATABASE_URL=$(grep '^DATABASE_URL' "$APP_DIR/.env" | sed 's/DATABASE_URL=//')"
}

open_firewall() {
  _log "방화벽 규칙 추가 (가능한 경우에만)"
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=${APP_PORT}/tcp --permanent || true
    firewall-cmd --reload || true
    _log "firewalld에 ${APP_PORT}/tcp 허용 등록"
  else
    _warn "firewalld 비활성. ufw 확인 시도."
    if _is_cmd ufw && ufw status | grep -q "Status: active"; then
      ufw allow ${APP_PORT}/tcp || true
      _log "ufw에 ${APP_PORT}/tcp 허용 등록"
    else
      _warn "firewalld/ufw 모두 비활성. 수동으로 포트를 개방하세요."
    fi
  fi
}

selinux_adjust() {
  if _is_cmd getenforce && [ "$(getenforce)" = "Enforcing" ]; then
    _log "SELinux Enforcing: 포트 라벨링(http_port_t)에 ${APP_PORT}/tcp 추가 시도"
    # httpd_t로 바인딩할 게 아니라면 보통 필요 없지만, 추후 프록시/이관 대비 포트 허용
    if ! _is_cmd semanage; then
      _warn "semanage 명령이 없어 설치를 시도합니다."
      local pmgr; pmgr=$(detect_pkg_mgr)
      case "$pmgr" in
        dnf|yum) $pmgr -y install policycoreutils-python-utils || true ;;
        apt)     apt -y install policycoreutils-python-utils || true ;;
      esac
    fi
    if _is_cmd semanage; then
      semanage port -a -t http_port_t -p tcp ${APP_PORT} 2>/dev/null || \
      semanage port -m -t http_port_t -p tcp ${APP_PORT} || true
      _log "SELinux 포트 컨텍스트 적용 완료(또는 이미 존재)"
    else
      _warn "semanage 사용 불가. SELinux 포트 라벨링 건너뜁니다."
    fi
  else
    _log "SELinux Permissive/Disabled 상태로 판단. 별도 조정 불필요."
  fi
}

write_systemd_unit() {
  _log "systemd 서비스 생성: /etc/systemd/system/${SERVICE_NAME}"
  cat > "/etc/systemd/system/${SERVICE_NAME}" <<UNIT
[Unit]
Description=LocalChat (Flask-SocketIO, MariaDB)
After=network.target

[Service]
User=root
WorkingDirectory=${APP_DIR}
EnvironmentFile=${APP_DIR}/.env
ExecStart=${APP_DIR}/.venv/bin/python ${APP_DIR}/app.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

  systemctl daemon-reload
  systemctl enable --now "${SERVICE_NAME}"
  systemctl status --no-pager "${SERVICE_NAME}" || true
}

### ---- 메인 로직 ----
require_root
pmgr=$(detect_pkg_mgr)
_log "패키지 관리자: $pmgr"

ensure_python_stack "$pmgr"
ensure_app_dir
create_venv_and_deps

if [ "$CREATE_LOCAL_DB" = "yes" ]; then
  install_mariadb_local "$pmgr"
  prepare_database
else
  _log "로컬 DB 설치/설정 생략 (CREATE_LOCAL_DB=no). .env는 수동으로 DATABASE_URL을 넣어주세요."
fi

write_env_file
open_firewall
selinux_adjust
write_systemd_unit

_log "설치 완료: http://<서버IP>:${APP_PORT} 접속 → /setup에서 최초 관리자 계정 생성"
