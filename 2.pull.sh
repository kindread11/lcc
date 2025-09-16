#!/usr/bin/env bash
# 파일: /opt/localchat/host-prepare.sh
# 목적: 운영 호스트 준비 (Docker/Compose 설치, systemd 유닛, 방화벽)
set -euo pipefail

APP_DIR="/opt/localchat"
APP_PORT="8000"

_is_cmd(){ command -v "$1" >/dev/null 2>&1; }
_log(){ echo -e "\033[1;32m[INFO]\033[0m $*"; }
_err(){ echo -e "\033[1;31m[ERROR]\033[0m $*"; }
require_root(){ [ "$(id -u)" -eq 0 ] || { _err "root로 실행하세요: sudo bash $0"; exit 1; }; }

detect_pkg_mgr(){
  if _is_cmd dnf; then echo dnf
  elif _is_cmd yum; then echo yum
  elif _is_cmd apt; then echo apt
  else _err "패키지 관리자(dnf/yum/apt) 미탐지"; exit 1
  fi
}

install_docker(){
  local pm="$1"
  case "$pm" in
    apt)
      apt -y update
      apt -y install docker.io docker-compose-plugin curl
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
      $pm -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin \
      || $pm -y install moby-engine moby-cli docker-compose-plugin
      ;;
  esac
  systemctl enable --now docker
}

write_unit(){
  install -d "${APP_DIR}"
  cat > /etc/systemd/system/localchat-compose.service <<'UNIT'
[Unit]
Description=LocalChat via Docker Compose
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=/opt/localchat
ExecStartPre=/usr/bin/docker compose pull
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
RemainAfterExit=yes
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

open_firewall(){
  # 8000/tcp 오픈 (firewalld/ufw 모두 시도)
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=${APP_PORT}/tcp --permanent || true
    firewall-cmd --reload || true
    _log "firewalld: ${APP_PORT}/tcp 허용"
  elif _is_cmd ufw && ufw status | grep -q "Status: active"; then
    ufw allow ${APP_PORT}/tcp || true
    _log "ufw: ${APP_PORT}/tcp 허용"
  else
    _log "별도 방화벽(8000/tcp) 설정은 필요 시 수동 적용 바랍니다."
  fi
}

main(){
  require_root
  PM=$(detect_pkg_mgr)
  _log "패키지 관리자: ${PM}"
  install_docker "${PM}"
  write_unit
  open_firewall
  _log "호스트 준비 완료."
}
main "$@"