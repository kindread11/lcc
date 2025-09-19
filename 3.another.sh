#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/localchat"
APP_PORT="8000"
USE_LOCAL_DB_CONTAINER="yes"
DB_NAME="localchat"
DB_USER="DBADMIN"
DB_PASS=""        # 입력받음
DB_PORT="3306"
DB_ROOT_PASS=""   # 입력받음

# 이미지 태그 (미리 빌드/푸시해둔 레지스트리 경로 사용)
APP_IMAGE="myrepo/localchat-app:latest"
DB_IMAGE="mariadb:11.4"

_log(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
_warn(){ echo -e "\033[1;33m[WARN]\033[0m $*"; }
_err(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }

require_root(){ [ "$(id -u)" -eq 0 ] || { _err "root로 실행하세요"; exit 1; }; }

detect_pkg_mgr(){
  if command -v dnf >/dev/null; then echo dnf
  elif command -v yum >/dev/null; then echo yum
  elif command -v apt >/dev/null; then echo apt
  else _err "지원되지 않는 배포판"; exit 1
  fi
}

install_prereqs(){
  local pm="$1"
  _log "필수 패키지 설치"
  case "$pm" in
    apt) apt -y update; apt -y install curl jq ;;
    dnf|yum) $pm -y install curl jq ;;
  esac
}

install_docker(){
  local pm="$1"
  if command -v docker >/dev/null; then
    _log "Docker 이미 설치됨"
    return
  fi
  _log "Docker 설치"
  case "$pm" in
    apt)
      apt -y install docker.io docker-compose-plugin
      ;;
    dnf|yum)
      $pm -y install dnf-plugins-core || true
      $pm config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo || true
      $pm -y install docker-ce docker-ce-cli containerd.io docker-compose-plugin || true
      ;;
  esac
  systemctl enable --now docker
}

get_password_input(){
  local prompt="$1"
  local var_name="$2"
  local pw1 pw2
  while :; do
    read -rsp "$prompt: " pw1; echo
    read -rsp "확인: " pw2; echo
    [ "$pw1" = "$pw2" ] || { echo "불일치"; continue; }
    eval "$var_name='$pw1'"
    break
  done
}

write_compose(){
  mkdir -p "$APP_DIR"
  if [ "$USE_LOCAL_DB_CONTAINER" = "yes" ]; then
    get_password_input "DB 사용자(${DB_USER}) 비밀번호" DB_PASS
    get_password_input "DB root 비밀번호" DB_ROOT_PASS
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
      test: ["CMD-SHELL", "mariadb -h 127.0.0.1 -u root -p${DB_ROOT_PASS} -e 'SELECT 1' || exit 1"]
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
      APP_HOST: "0.0.0.0"
      APP_PORT: "${APP_PORT}"
    depends_on:
      db:
        condition: service_healthy
    ports:
      - "${APP_PORT}:8000"

volumes:
  localchat_dbdata:
COMPOSE
  else
cat > "${APP_DIR}/docker-compose.yml" <<COMPOSE
services:
  app:
    image: ${APP_IMAGE}
    container_name: localchat-app
    restart: unless-stopped
    environment:
      DATABASE_URL: "mysql+pymysql://USER:PASS@DBHOST:3306/localchat"
      APP_HOST: "0.0.0.0"
      APP_PORT: "8000"
    ports:
      - "8000:8000"
COMPOSE
  fi
}

compose_up(){
  cd "$APP_DIR"
  _log "이미지 pull"
  docker pull "$APP_IMAGE"
  [ "$USE_LOCAL_DB_CONTAINER" = "yes" ] && docker pull "$DB_IMAGE" || true
  _log "컨테이너 기동"
  docker compose up -d
}

### 메인
require_root
PM=$(detect_pkg_mgr)
install_prereqs "$PM"
install_docker "$PM"
write_compose
compose_up

_log "배포 완료! 브라우저: http://<서버IP>:${APP_PORT}/setup 접속"