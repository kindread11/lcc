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

require_root(){ [ "$(id -u)" -eq 0 ] || { _err "root로 실행"; exit 1; }; }
gen_secret(){ openssl rand -hex 16; }
gen_password(){ tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16; echo; }

get_password_input(){
  local prompt="$1"
  local var_name="$2"
  local password=""
  local password_confirm=""
  while true; do
    echo -n "$prompt (빈 값 입력 시 기본값 Passw0rd! 사용): "
    read -s password; echo
    if [ -z "$password" ]; then
      eval "$var_name='Passw0rd!'"
      _log "비밀번호가 입력되지 않아 기본값 Passw0rd! 로 설정"
      break
    fi
    echo -n "비밀번호 확인: "
    read -s password_confirm; echo
    if [ "$password" = "$password_confirm" ]; then
      if [ ${#password} -ge 8 ]; then
        eval "$var_name='$password'"
        _log "비밀번호가 설정됨"
        break
      else
        _warn "비밀번호는 최소 8자 이상"
      fi
    else
      _warn "비밀번호 불일치. 재입력"
    fi
  done
}

detect_pkg_mgr(){
  if _is_cmd dnf; then echo dnf
  elif _is_cmd yum; then echo yum
  elif _is_cmd apt; then echo apt
  else _err "패키지 관리자 미탐지"; exit 1
  fi
}

install_prereqs(){
  local pm="$1"
  _log "필수 패키지 설치"
  case "$pm" in
    apt)
      apt -y update
      apt -y install python3 python3-pip python3-venv openssl curl gnupg lsb-release awscli jq
      ;;
    dnf|yum)
      $pm -y install python3 python3-pip openssl curl awscli jq || true
      if ! command -v aws >/dev/null 2>&1; then
        _warn "awscli 없음 → pip 설치"
        python3 -m pip install --upgrade awscli || { _err "awscli 설치 실패"; exit 1; }
      fi
      ;;
  esac
}

install_docker(){
  local pm="$1"
  if rpm -q podman-docker >/dev/null 2>&1; then
    _log "podman-docker 제거"
    sudo dnf -y remove podman-docker docker || sudo yum -y remove podman-docker docker || true
  fi
  if _is_cmd docker && docker --version >/dev/null 2>&1; then
    _log "Docker 이미 설치됨"
  else
    _log "Docker 설치 시도"
    case "$pm" in
      apt)
        sudo apt -y update
        sudo apt -y install docker.io docker-compose-plugin || { _warn "docker.io 설치 실패"; }
        ;;
      dnf|yum)
        if ! $pm repolist 2>/dev/null | grep -qi docker-ce; then
          _log "Docker CE 리포 추가"
          if _is_cmd dnf; then
            sudo dnf -y install dnf-plugins-core
            sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
          else
            sudo yum -y install yum-utils
            sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
          fi
        fi
        if ! sudo $pm -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
          _warn "docker-ce 설치 실패"
        fi
        ;;
    esac
  fi
  if systemctl list-unit-files | grep -q '^docker\.service'; then
    _log "docker.service 활성화"
    sudo systemctl enable --now docker
  elif docker --version 2>&1 | grep -qi 'podman'; then
    if systemctl list-unit-files | grep -q '^podman\.socket'; then
      _warn "docker가 Podman 래퍼 → podman.socket 활성화"
      sudo systemctl enable --now podman.socket
    else
      _err "podman.socket 없음"
      exit 1
    fi
  else
    _warn "docker.service 없음"
    if command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
      pm_local="$(command -v dnf >/dev/null 2>&1 && echo dnf || echo yum)"
      if ! $pm_local repolist 2>/dev/null | grep -qi docker-ce; then
        _log "Docker CE 리포 추가"
        if [ "$pm_local" = "dnf" ]; then
          sudo dnf -y install dnf-plugins-core
          sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        else
          sudo yum -y install yum-utils
          sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
        fi
      fi
      if sudo $pm_local -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin; then
        sudo systemctl enable --now docker
      else
        _warn "docker-ce 실패 → moby-engine 시도"
        if sudo $pm_local -y install moby-engine moby-cli docker-compose-plugin; then
          sudo systemctl enable --now docker
        else
          _err "docker-ce / moby-engine 설치 실패"
          exit 1
        fi
      fi
    else
      _err "dnf/yum 없음"
      exit 1
    fi
  fi
}

ensure_dirs(){
  _log "디렉터리 생성: ${APP_DIR}"
  mkdir -p "${APP_DIR}"
}

write_app_py(){
  _log "app.py 생성/갱신"
  cat > "${APP_DIR}/app.py" <<'PYCODE'
#!/usr/bin/env python3
import os, secrets, re, ipaddress
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template_string, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from jinja2 import DictLoader

SECRET_KEY   = os.environ.get("LOCALCHAT_SECRET", secrets.token_hex(16))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
APP_HOST     = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT     = int(os.environ.get("APP_PORT", "8000"))
TRUST_PROXY  = os.environ.get("TRUST_PROXY", "0") == "1"
NUM_PROXIES  = int(os.environ.get("NUM_PROXIES", "1"))

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL env 필요. 예) mysql+pymysql://user:pw@db:3306/localchat")

app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

if TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=NUM_PROXIES, x_proto=NUM_PROXIES, x_host=NUM_PROXIES, x_port=NUM_PROXIES)

socketio = SocketIO(app, async_mode="eventlet")
login_manager = LoginManager(app); login_manager.login_view = "login"
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

def init_db():
    with engine.begin() as conn:
        conn.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS users (
          username VARCHAR(190) PRIMARY KEY,
          pw_hash  VARCHAR(255) NOT NULL,
          display_name VARCHAR(190),
          is_admin TINYINT(1) NOT NULL DEFAULT 0,
          is_active TINYINT(1) NOT NULL DEFAULT 1,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""")
        conn.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS rooms (
          id INT AUTO_INCREMENT PRIMARY KEY,
          room_key  VARCHAR(64) NOT NULL UNIQUE,
          room_name VARCHAR(190) NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""")
        conn.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS messages (
          id BIGINT AUTO_INCREMENT PRIMARY KEY,
          room_key  VARCHAR(64) NOT NULL,
          username  VARCHAR(190) NOT NULL,
          body      TEXT NOT NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          INDEX idx_room_created (room_key, created_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""")
        conn.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS allowed_ips (
          id INT AUTO_INCREMENT PRIMARY KEY,
          pattern VARCHAR(64) NOT NULL,
          note VARCHAR(190) NULL,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;""")
        if conn.execute(text("SELECT COUNT(*) FROM rooms")).scalar() == 0:
            conn.execute(text(
              "INSERT INTO rooms(room_key, room_name) VALUES "
              "('general','일반'),('devops','DevOps'),('random','잡담')"))
}
}

def users_count():
    with engine.begin() as conn:
        return conn.execute(text("SELECT COUNT(*) FROM users")).scalar()

def get_user(username):
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT username, pw_hash, is_admin, is_active FROM users WHERE username=:u"), {"u": username}
        ).fetchone()
        if row:
            return {
                "username": row[0],
                "pw_hash": row[1],
                "is_admin": bool(row[2]),
                "is_active": bool(row[3])
            }
        return None

def create_user(username, password, is_admin=False):
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO users(username, pw_hash, is_admin) VALUES(:u,:p,:a)"),
            {"u": username, "p": generate_password_hash(password), "a": 1 if is_admin else 0}
        )

def get_allowed_patterns():
    with engine.begin() as conn:
        return [row.pattern for row in conn.execute(text("SELECT pattern FROM allowed_ips ORDER BY id")).all()]

def add_allowed_pattern(pattern, note=None):
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO allowed_ips(pattern, note) VALUES(:p,:n)"), {"p": pattern, "n": note})

def delete_allowed_pattern(id_):
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM allowed_ips WHERE id=:i"), {"i": id_})

class User(UserMixin):
    def __init__(self, username, is_admin=False):
        self.id = username
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    u = get_user(user_id)
    return User(u["username"], u["is_admin"]) if u else None

def client_ip():
    if TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def ip_allowed(ip: str) -> bool:
    patterns = get_allowed_patterns()
    if not patterns: return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for pat in patterns:
        try:
          if "/" in pat:
            if addr in ipaddress.ip_network(pat, strict=False): return True
          else:
            if addr == ipaddress.ip_address(pat): return True
        except ValueError:
          continue
    return False

@app.before_request
def enforce_ip_allowlist():
    if users_count() == 0 and request.endpoint in ("setup", "static"):
        return
    if not ip_allowed(client_ip()):
        abort(403)

def admin_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not current_user.is_authenticated: return login_manager.unauthorized()
        if not getattr(current_user, "is_admin", False): abort(403)
        return f(*a, **kw)
    return wrapper

TPL_LAYOUT = """<!doctype html><html lang="ko"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ title or 'LocalChat' }}</title>
<style>
body{font-family:sans-serif;margin:20px}.container{max-width:900px;margin:0 auto}
.card{border:1px solid #ddd;padding:16px;border-radius:8px}.flash{background:#ffeecc;padding:8px;margin-bottom:10px;border-radius:4px}
input[type=text],input[type=password]{width:100%;padding:10px;margin:8px 0}button{padding:10px 16px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f7f7f7}
.msg{margin:6px 0}.you{font-weight:bold}.nav a{margin-right:10px}
</style>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
</head><body><div class="container">
<div class="nav" style="margin-bottom:12px">
{% if current_user.is_authenticated %}
  {{ current_user.username }}님 |
  <a href="{{ url_for('rooms') }}">채팅방</a>
  {% if current_user.is_admin %} | <a href="{{ url_for('admin_ip_allowlist') }}">관리자: IP 허용</a> | <a href="{{ url_for('admin_users') }}">관리자: 사용자</a>{% endif %}
  | <a href="{{ url_for('logout') }}">로그아웃</a>
{% else %}
  <a href="{{ url_for('login') }}">로그인</a> | <a href="{{ url_for('register') }}">회원가입</a>
{% endif %}
</div>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<div class="card">{% block content %}{% endblock %}</div>
</div></body></html>"""

TPL_LOGIN = """{% extends "layout.html" %}{% block content %}
<h2>로그인</h2>
{% if first_run %}<div class="flash">초기 설정이 필요합니다. <a href="{{ url_for('setup') }}">여기</a>에서 최초 계정을 만드세요.</div>{% endif %}
<form method="post">
  <label>아이디</label><input type="text" name="username" required>
  <label>비밀번호</label><input type="password" name="password" required>
  <button type="submit">로그인</button>
</form>
{% endblock %}"""

TPL_SETUP = """{% extends "layout.html" %}{% block content %}
<h2>최초 계정 생성</h2>
<form method="post" autocomplete="off">
  <label>아이디(영문/숫자/._- 3~32자)</label><input type="text" name="username" required>
  <label>비밀번호(최소 8자)</label><input type="password" name="password" required>
  <label>비밀번호 확인</label><input type="password" name="password2" required>
  <button type="submit">계정 만들기</button>
</form>
<p style="color:#666">※ 최초 1회만 생성 가능하며, 이후에는 로그인 화면만 노출됩니다.</p>
{% endblock %}"""

TPL_ROOMS = """{% extends "layout.html" %}{% block content %}
<h2>채팅방</h2>

<h3>새 채팅방 만들기</h3>
<form method="post" action="{{ url_for('create_room') }}" autocomplete="off" style="margin-bottom:12px">
  <label>방 키(영문/숫자/._- 3~32자)</label>
  <input type="text" name="room_key" required>
  <label>방 이름(표시명)</label>
  <input type="text" name="room_name" required>
  <button type="submit">생성</button>
  <p style="color:#666;margin:6px 0 0">키는 URL에 사용됩니다. 예: general, devops, random</p>
</form>

<h3>채팅방 리스트</h3>
<ul>
{% for r in rooms %}
  <li>
    <a href="{{ url_for('chat_room', room_key=r.room_key) }}"># {{ r.room_name }} ({{ r.room_key }})</a>
    {% if current_user.is_admin %}
      <form method="post" action="{{ url_for('admin_room_delete', room_key=r.room_key) }}" style="display:inline" onsubmit="return confirm('삭제하시겠습니까?');">
        <button type="submit">삭제</button>
      </form>
    {% endif %}
  </li>
{% endfor %}
</ul>
{% endblock %}"""

TPL_CHAT = """{% extends "layout.html" %}{% block content %}
<h2># {{ room.room_name }} ({{ room.room_key }})</h2>
<div id="chat" style="border:1px solid #ccc;height:320px;overflow:auto;padding:8px;margin:8px 0">
  {% for m in msgs %}
    <div class="msg"><b>[{{ m.username }}]</b> {{ m.body }}
      <span style="color:#888;font-size:0.85em"> ({{ m.created_at }})</span>
    </div>
  {% endfor %}
</div>
<form id="sendForm"><input type="text" id="msg" placeholder="메시지 입력..." autocomplete="off"><button type="submit">전송</button></form>
<script>
const socket = io();
const username = "{{ current_user.username }}";
const room     = "{{ room.room_key }}";
const chat = document.getElementById('chat');
const form = document.getElementById('sendForm');
const msg  = document.getElementById('msg');
function addLine(text, cls){const d=document.createElement('div');d.className='msg '+(cls||'');d.textContent=text;chat.appendChild(d);chat.scrollTop=chat.scrollHeight;}
socket.on('connect', ()=>{ socket.emit('join', {room}); });
socket.on('sys',  d=> addLine(d.text));
socket.on('chat', d=> addLine((d.user===username?'나':'['+d.user+']')+': '+d.text, d.user===username?'you':'')); 
form.addEventListener('submit', e=>{
  e.preventDefault();
  const text=msg.value.trim(); if(!text) return;
  socket.emit('chat', {room, text}); msg.value='';
});
</script>
{% endblock %}"""

TPL_ADMIN_IP = """{% extends "layout.html" %}{% block content %}
<h2>관리자: 허용 IP 목록</h2>
<p>목록이 비어있으면 모든 IP 접근을 허용합니다. 하나 이상 등록하면 해당 IP/대역만 접근 가능해집니다.</p>
<form method="post" style="margin:12px 0">
  <label>패턴(단일 IP 또는 CIDR)</label>
  <input type="text" name="pattern" placeholder="예: 192.168.1.10 또는 10.0.0.0/24" required>
  <label>설명(선택)</label>
  <input type="text" name="note" placeholder="내부망, 본사 등">
  <button type="submit">추가</button>
</form>
<table>
  <thead><tr><th>ID</th><th>패턴</th><th>설명</th><th>생성시각</th><th>삭제</th></tr></thead>
  <tbody>
  {% for row in rows %}
    <tr>
      <td>{{ row.id }}</td>
      <td>{{ row.pattern }}</td>
      <td>{{ row.note or '' }}</td>
      <td>{{ row.created_at }}</td>
      <td>
        <form method="post" action="{{ url_for('admin_ip_delete', id=row.id) }}" onsubmit="return confirm('삭제하시겠습니까?')">
          <button type="submit">삭제</button>
        </form>
      </td>
    </tr>
  {% endfor %}
  </tbody>
</table>
{% endblock %}"""

app.jinja_loader = DictLoader({"layout.html": TPL_LAYOUT})

@app.context_processor
def inject_layout(): return {"layout": TPL_LAYOUT}

@app.route("/")
def index():
    if users_count() == 0: return redirect(url_for("setup"))
    return redirect(url_for("rooms") if current_user.is_authenticated else url_for("login"))

@app.route("/setup", methods=["GET","POST"])
def setup():
    if users_count() > 0:
        flash("이미 초기 설정이 완료되었습니다."); return redirect(url_for("login"))
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "")
        p2= (request.form.get("password2") or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", u):
            flash("아이디 형식이 올바르지 않습니다."); return render_template_string(TPL_SETUP)
        if len(p) < 8:
            flash("비밀번호는 8자 이상이어야 합니다."); return render_template_string(TPL_SETUP)
        if p != p2:
            flash("비밀번호 확인이 일치하지 않습니다."); return render_template_string(TPL_SETUP)
        try:
            create_user(u, p, is_admin=True)
            flash("최초(관리자) 계정이 생성되었습니다. 로그인하세요.")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"계정 생성 실패: {e}")
    return render_template_string(TPL_SETUP, title="최초 계정 생성")

@app.route("/register", methods=["GET","POST"])
def register():
    if users_count() == 0:
        return redirect(url_for("setup"))

    TPL_REGISTER = """{% extends "layout.html" %}{% block content %}
    <h2>회원가입 (관리자 승인 필요)</h2>
    <form method="post" autocomplete="off">
      <label>아이디(영문/숫자/._- 3~32자)</label><input type="text" name="username" required>
      <label>비밀번호(최소 8자)</label><input type="password" name="password" required>
      <label>비밀번호 확인</label><input type="password" name="password2" required>
      <button type="submit">가입 신청</button>
    </form>
    <p style="color:#666">승인되면 로그인하실 수 있습니다.</p>
    {% endblock %}"""

    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "")
        p2= (request.form.get("password2") or "")
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", u):
            flash("아이디 형식이 올바르지 않습니다."); return render_template_string(TPL_REGISTER)
        if len(p) < 8:
            flash("비밀번호는 8자 이상이어야 합니다."); return render_template_string(TPL_REGISTER)
        if p != p2:
            flash("비밀번호 확인이 일치하지 않습니다."); return render_template_string(TPL_REGISTER)
        if get_user(u):
            flash("이미 존재하는 아이디입니다."); return render_template_string(TPL_REGISTER)
        with engine.begin() as conn:
            conn.execute(text(
                "INSERT INTO users(username, pw_hash, is_admin, is_active) VALUES(:u,:p,0,0)"
            ), {"u": u, "p": generate_password_hash(p)})
        flash("가입 신청이 접수되었습니다. 관리자 승인 후 로그인할 수 있습니다.")
        return redirect(url_for("login"))

    return render_template_string(TPL_REGISTER, title="회원가입")

@app.route("/admin/users")
@login_required
@admin_required
def admin_users():
    with engine.begin() as conn:
        pending = conn.execute(text("""
            SELECT username, created_at FROM users
            WHERE is_active=0
            ORDER BY created_at ASC
        """)).all()
        actives = conn.execute(text("""
            SELECT username, created_at, is_admin FROM users
            WHERE is_active=1
            ORDER BY created_at DESC
        """)).all()
    TPL_ADMIN_USERS = """{% extends "layout.html" %}{% block content %}
    <h2>관리자: 사용자 관리</h2>
    <h3>승인 대기</h3>
    <table><thead><tr><th>아이디</th><th>신청시각</th><th>승인</th><th>삭제</th></tr></thead><tbody>
    {% for u in pending %}
      <tr>
        <td>{{ u.username }}</td><td>{{ u.created_at }}</td>
        <td><form method="post" action="{{ url_for('admin_user_approve', username=u.username) }}"><button type="submit">승인</button></form></td>
        <td><form method="post" action="{{ url_for('admin_user_delete', username=u.username) }}" onsubmit="return confirm('삭제하시겠습니까?')"><button type="submit">삭제</button></form></td>
      </tr>
    {% endfor %}
    </tbody></table>

    <h3>활성 사용자</h3>
    <table><thead><tr><th>아이디</th><th>생성시각</th><th>권한</th><th>비활성화</th></tr></thead><tbody>
    {% for u in actives %}
      <tr>
        <td>{{ u.username }}</td><td>{{ u.created_at }}</td><td>{{ '관리자' if u.is_admin else '일반' }}</td>
        <td><form method="post" action="{{ url_for('admin_user_deactivate', username=u.username) }}" onsubmit="return confirm('비활성화하시겠습니까?')"><button type="submit">비활성화</button></form></td>
      </tr>
    {% endfor %}
    </tbody></table>
    {% endblock %}"""
    return render_template_string(TPL_ADMIN_USERS, title="관리자: 사용자 관리", pending=pending, actives=actives, current_user=current_user)

@app.route("/admin/users/approve/<username>", methods=["POST"])
@login_required
@admin_required
def admin_user_approve(username):
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET is_active=1 WHERE username=:u"), {"u": username})
    flash("승인되었습니다.")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/deactivate/<username>", methods=["POST"])
@login_required
@admin_required
def admin_user_deactivate(username):
    if current_user.username == username:
        flash("자기 자신은 비활성화할 수 없습니다."); return redirect(url_for("admin_users"))
    with engine.begin() as conn:
        conn.execute(text("UPDATE users SET is_active=0 WHERE username=:u"), {"u": username})
    flash("비활성화되었습니다.")
    return redirect(url_for("admin_users"))

@app.route("/admin/users/delete/<username>", methods=["POST"])
@login_required
@admin_required
def admin_user_delete(username):
    if current_user.username == username:
        flash("자기 자신은 삭제할 수 없습니다."); return redirect(url_for("admin_users"))
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM users WHERE username=:u"), {"u": username})
    flash("삭제되었습니다.")
    return redirect(url_for("admin_users"))

@app.route("/login", methods=["GET","POST"])
def login():
    first_run = (users_count() == 0)
    if first_run: return redirect(url_for("setup"))
    if request.method=="POST":
        u = (request.form.get("username") or "").strip()
        p = (request.form.get("password") or "")
        row = get_user(u)
        if row and check_password_hash(row["pw_hash"], p):
            if not row.get("is_active", True):
                flash("관리자 승인 대기 중입니다. 승인 후 로그인 가능합니다.")
                return render_template_string(TPL_LOGIN, title="로그인", current_user=current_user, first_run=first_run)
            login_user(User(u, row["is_admin"]));
            return redirect(url_for("rooms"))
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template_string(TPL_LOGIN, title="로그인", current_user=current_user, first_run=first_run)

@app.route("/logout")
@login_required
def logout():
    from flask_login import logout_user as _logout
    _logout(); flash("로그아웃 되었습니다."); return redirect(url_for("login"))

@app.route("/rooms")
@login_required
def rooms():
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT room_key, room_name FROM rooms ORDER BY id")).all()
    return render_template_string(TPL_ROOMS, title="채팅방", rooms=rows, current_user=current_user)

@app.post("/rooms/create")
@login_required
def create_room():
    rk = (request.form.get("room_key") or "").strip()
    rn = (request.form.get("room_name") or "").strip()
    if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", rk):
        flash("방 키 형식이 올바르지 않습니다.(영문/숫자/._- 3~32자)"); return redirect(url_for("rooms"))
    if not rn:
        flash("방 이름을 입력하세요."); return redirect(url_for("rooms"))
    try:
        with engine.begin() as conn:
            exists = conn.execute(text("SELECT 1 FROM rooms WHERE room_key=:k"), {"k": rk}).scalar()
            if exists:
                flash("이미 존재하는 방 키입니다."); return redirect(url_for("rooms"))
            conn.execute(text("INSERT INTO rooms(room_key, room_name) VALUES(:k,:n)"), {"k": rk, "n": rn})
        flash("채팅방이 생성되었습니다.")
    except Exception as e:
        flash(f"생성 실패: {e}")
    return redirect(url_for("rooms"))

@app.post("/admin/rooms/delete/<room_key>")
@login_required
@admin_required
def admin_room_delete(room_key):
    try:
        with engine.begin() as conn:
            conn.execute(text("DELETE FROM messages WHERE room_key=:k"), {"k": room_key})
            conn.execute(text("DELETE FROM rooms WHERE room_key=:k"), {"k": room_key})
        flash("삭제되었습니다.")
    except Exception as e:
        flash(f"삭제 실패: {e}")
    return redirect(url_for("rooms"))

@app.route("/chat/<room_key>")
@login_required
def chat_room(room_key):
    with engine.begin() as conn:
        room = conn.execute(text("SELECT room_key, room_name FROM rooms WHERE room_key=:k"), {"k": room_key}).fetchone()
        if not room:
            flash("존재하지 않는 채팅방입니다."); return redirect(url_for("rooms"))
        msgs = conn.execute(text("""
            SELECT username, body, created_at
            FROM messages
            WHERE room_key=:k
            ORDER BY created_at DESC
            LIMIT 50
        """), {"k": room_key}).all()
    msgs = list(reversed([dict(m._mapping) for m in msgs]))
    return render_template_string(TPL_CHAT, title=f"채팅 - {room.room_name}", room=room, current_user=current_user, msgs=msgs)

@app.route("/admin/ip-allowlist", methods=["GET","POST"])
@login_required
@admin_required
def admin_ip_allowlist():
    if request.method == "POST":
        pattern = (request.form.get("pattern") or "").strip()
        note    = (request.form.get("note") or "").strip() or None
        ok = False
        try:
            if "/" in pattern: ipaddress.ip_network(pattern, strict=False); ok = True
            else: ipaddress.ip_address(pattern); ok = True
        except ValueError: ok = False
        if not ok: 
            flash("패턴 형식이 올바르지 않습니다. 단일 IP 또는 CIDR(예: 10.0.0.0/24)로 입력하세요.")
        else: 
            add_allowed_pattern(pattern, note); flash("추가되었습니다.")
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT id, pattern, note, created_at FROM allowed_ips ORDER BY id")).all()
    return render_template_string(TPL_ADMIN_IP, title="관리자: 허용 IP", rows=rows, current_user=current_user)

@app.route("/admin/ip-allowlist/delete/<int:id>", methods=["POST"])
@login_required
@admin_required
def admin_ip_delete(id):
    delete_allowed_pattern(id); flash("삭제되었습니다."); return redirect(url_for("admin_ip_allowlist"))

@socketio.on("join")
def on_join(data):
    if not current_user.is_authenticated:
        return
    if not ip_allowed(client_ip()): return
    room = data.get("room"); join_room(room)
    emit("sys", {"text": f"[시스템] {current_user.username}님 입장"}, to=room)

@socketio.on("chat")
def on_chat(data):
    if not current_user.is_authenticated:
        return
    if not ip_allowed(client_ip()): return
    room = data.get("room"); msg_text = (data.get("text") or "").strip()
    if not room or not msg_text: return
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO messages(room_key, username, body) VALUES(:r,:u,:b)"),
                     {"r": room, "u": current_user.username, "b": msg_text})
    emit("chat", {"user": current_user.username, "text": msg_text}, to=room)

if __name__ == "__main__":
    try:
        init_db()
    except OperationalError as e:
        raise SystemExit(f"[DB 연결 실패] {e}")
    except Exception as e:
        print(f"[오류] {e}")
        raise SystemExit(f"[초기화 실패] {e}")
    socketio.run(app, host=APP_HOST, port=APP_PORT, debug=False)
PYCODE
}

write_requirements(){
  _log "requirements.txt 생성"
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
  _log "Dockerfile 생성"
  cat > "${APP_DIR}/Dockerfile" <<'DOCKER'
FROM python:3.12-slim
WORKDIR /opt/localchat
RUN apt-get update && apt-get install -y --no-install-recommends build-essential default-libmysqlclient-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt
COPY app.py ./app.py
ENV APP_HOST=0.0.0.0 APP_PORT=8000
EXPOSE 8000
CMD ["python", "app.py"]
DOCKER
}

open_firewall(){
  _log "방화벽 포트 개방 시도"
  if systemctl is-active --quiet firewalld; then
    firewall-cmd --add-port=${APP_PORT}/tcp --permanent || true
    firewall-cmd --reload || true
    _log "firewalld: ${APP_PORT}/tcp 허용"
  elif _is_cmd ufw && ufw status | grep -q "Status: active"; then
    ufw allow ${APP_PORT}/tcp || true
    _log "ufw: ${APP_PORT}/tcp 허용"
  else
    _warn "firewalld/ufw 비활성. 필요 시 수동 개방"
  fi
}

write_compose(){
  _log "docker-compose.yml 생성"
  if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
    echo
    _log "=== 데이터베이스 비밀번호 설정 ==="
    echo "MariaDB 컨테이너의 비밀번호를 설정합니다."
    echo
    get_password_input "DB 사용자(${DB_USER}) 비밀번호" "DB_PASS"
    get_password_input "DB root 비밀번호" "DB_ROOT_PASS"
    echo
    _log "비밀번호 설정 완료!"
    echo "  - DB 사용자 비밀번호: ${DB_PASS}"
    echo "  - DB root 비밀번호: ${DB_ROOT_PASS}"
    echo
  fi

  if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
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
    volumes:
      - localchat_dbdata:/var/lib/mysql
    healthcheck:
      test: ["CMD-SHELL", "mariadb -h 127.0.0.1 -u root -p${DB_ROOT_PASS} -e 'SELECT 1' || exit 1"]
      interval: 60s
      timeout: 30s
      retries: 5
      start_period: 180s

  app:
    build:
      context: .
      dockerfile: Dockerfile
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

volumes:
  localchat_dbdata:
COMPOSE
  else
cat > "${APP_DIR}/docker-compose.yml" <<COMPOSE
services:
  app:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: localchat-app
    restart: unless-stopped
    environment:
      DATABASE_URL: "mysql+pymysql://USER:PASS@DBHOST:3306/localchat"
      LOCALCHAT_SECRET: "change-me"
      APP_HOST: "0.0.0.0"
      APP_PORT: "8000"
      TRUST_PROXY: "0"
      NUM_PROXIES: "1"
    ports:
      - "8000:8000"
COMPOSE
  fi
}

selinux_hint(){
  if _is_cmd getenforce && [ "$(getenforce)" = "Enforcing" ]; then
    _log "SELinux Enforcing 감지. Docker 포트 매핑은 일반적으로 추가 설정 불필요."
    _log "만약 Nginx 등 다른 서비스가 ${APP_PORT}/tcp를 직접 바인딩한다면 semanage로 http_port_t 추가를 고려하세요."
  fi
}

compose_up(){
  _log "Docker Compose 빌드/기동"
  cd "${APP_DIR}"
  docker compose up -d --build
}

write_chat_client(){
  _log "Python 채팅 클라이언트 생성"
  cat > "${APP_DIR}/chat_client.py" <<'PYCLIENT'
#!/usr/bin/env python3
"""
LocalChat 텍스트 클라이언트
사용법: python3 chat_client.py
"""
import requests, getpass, sys, re
class LocalChatClient:
    def __init__(self, base_url="http://127.0.0.1:8000"):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent':'LocalChat-Python-Client/1.0'})
        self.current_room=None; self.username=None
    def login(self):
        print("=== LocalChat 로그인 ===")
        username = input("사용자명: ").strip()
        if not username: print("사용자명을 입력하세요."); return False
        password = getpass.getpass("비밀번호: ")
        if not password: print("비밀번호를 입력하세요."); return False
        try:
            r=self.session.post(f"{self.base_url}/login", data={"username":username,"password":password}, allow_redirects=False)
            if r.status_code==302: self.username=username; print(f"로그인 성공: {username}"); return True
            print("로그인 실패: 아이디 또는 비밀번호가 올바르지 않습니다."); return False
        except requests.exceptions.RequestException as e:
            print(f"연결 오류: {e}"); return False
    def get_rooms(self):
        try:
            r=self.session.get(f"{self.base_url}/rooms")
            if r.status_code==200:
                rooms=re.findall(r'href="/chat/([^"]+)"[^>]*># ([^<]+)', r.text)
                return [(k,n) for k,n in rooms]
            print(f"채팅방 목록 조회 실패: {r.status_code}"); return []
        except requests.exceptions.RequestException as e:
            print(f"연결 오류: {e}"); return []
    def show_rooms(self):
        rooms=self.get_rooms()
        if not rooms: print("채팅방이 없습니다."); return
        print("\n=== 채팅방 목록 ===")
        for i,(k,n) in enumerate(rooms,1): print(f"{i}. {n} ({k})")
        print("0. 새 채팅방 만들기\nq. 종료")
    def create_room(self):
        print("\n=== 새 채팅방 만들기 ===")
        rk=input("방 키 (영문/숫자/._- 3~32자): ").strip()
        rn=input("방 이름: ").strip()
        if not rk or not rn: print("방 키와 방 이름을 모두 입력하세요."); return None
        if not re.match(r'^[A-Za-z0-9._-]{3,32}$', rk): print("방 키 형식이 올바르지 않습니다."); return None
        try:
            r=self.session.post(f"{self.base_url}/rooms/create", data={"room_key":rk,"room_name":rn}, allow_redirects=False)
            if r.status_code==302: print(f"채팅방 '{rn}' ({rk})이 생성되었습니다."); return rk
            print("채팅방 생성 실패."); return None
        except requests.exceptions.RequestException as e:
            print(f"연결 오류: {e}"); return None
    def get_messages(self, rk):
        try:
            r=self.session.get(f"{self.base_url}/chat/{rk}")
            if r.status_code==200:
                msgs=re.findall(r'<b>\[([^\]]+)\]</b> ([^<]+)<span[^>]*> \(([^)]+)\)</span>', r.text)
                return msgs
            print(f"메시지 조회 실패: {r.status_code}"); return []
        except requests.exceptions.RequestException as e:
            print(f"연결 오류: {e}"); return []
    def show_messages(self, rk, rn):
        msgs=self.get_messages(rk)
        if not msgs: print("메시지가 없습니다."); return
        print(f"\n=== #{rn} ({rk}) ===")
        for u,b,t in msgs:
            marker="나" if u==self.username else f"[{u}]"
            print(f"{marker}: {b} ({t})")
    def send_message(self, rk, m):
        try:
            r=self.session.post(f"{self.base_url}/chat/{rk}", data={"message":m}, allow_redirects=False)
            return r.status_code==302
        except requests.exceptions.RequestException as e:
            print(f"연결 오류: {e}"); return False
    def chat_room(self, rk, rn):
        self.current_room=rk
        print(f"\n=== #{rn} ({rk}) 채팅방 ===")
        print("명령어: /exit, /refresh, /rooms")
        while True:
            self.show_messages(rk, rn)
            m=input(f"\n[{self.username}] ").strip()
            if not m: continue
            if m=="/exit": break
            if m=="/refresh": continue
            if m=="/rooms": self.show_rooms(); continue
            print("전송됨" if self.send_message(rk,m) else "전송 실패")
    def run(self):
        print("LocalChat Python 클라이언트"); print("="*40)
        if not self.login(): return
        while True:
            self.show_rooms()
            c=input("\n선택: ").strip().lower()
            if c=='q': print("종료합니다."); break
            if c=='0':
                rk=self.create_room()
                if rk:
                    rooms=self.get_rooms(); rn=next((n for k,n in rooms if k==rk), rk)
                    self.chat_room(rk,rn)
            else:
                try:
                    idx=int(c)-1; rooms=self.get_rooms()
                    if 0<=idx<len(rooms):
                        rk,rn=rooms[idx]; self.chat_room(rk,rn)
                    else: print("잘못된 선택입니다.")
                except ValueError:
                    print("숫자를 입력하세요.")
if __name__=="__main__":
    try:
        LocalChatClient().run()
    except KeyboardInterrupt:
        print("\n\n프로그램을 종료합니다.")
    except Exception as e:
        print(f"오류 발생: {e}"); sys.exit(1)
PYCLIENT
  chmod +x "${APP_DIR}/chat_client.py"
}

install_mysqldump_in_db(){
  if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
    _log "DB 컨테이너에 mysqldump 설치 확인"
    if ! docker exec localchat-db which mysqldump >/dev/null 2>&1; then
      _log "mysqldump 미발견 → mariadb-client 설치"
      docker exec localchat-db bash -c "apt-get update && apt-get install -y mariadb-client" || {
        _err "DB 컨테이너 내부 mariadb-client 설치 실패"
        exit 1
      }
    else
      _log "mysqldump 이미 설치됨"
    fi
  fi
}

### ====== AWS & S3 백업/복구 ======
aws_login_env(){
  echo
  _log "=== AWS 자격 증명 입력 (파일에 저장하지 않음) ==="
  if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
    read -rp "AWS Access Key ID: " AWS_AK
    read -rsp "AWS Secret Access Key: " AWS_SK; echo
    export AWS_ACCESS_KEY_ID="$AWS_AK"
    export AWS_SECRET_ACCESS_KEY="$AWS_SK"
  else
    _log "환경변수 AWS 자격 증명 사용"
  fi
  read -rp "AWS Region [${S3_REGION}]: " IN_RG
  AWS_RG="${IN_RG:-${S3_REGION}}"
  export AWS_DEFAULT_REGION="$AWS_RG"
  if ! aws sts get-caller-identity >/dev/null 2>&1; then
    _err "AWS 인증 실패(키/리전 확인 필요)"
    unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION
    exit 1
  fi
  _log "AWS 인증 성공"
  local B_IN B_NAME
  if [ -n "${S3_BUCKET}" ]; then
    B_IN="${S3_BUCKET}"
    case "$B_IN" in
      s3://*) B_NAME="${B_IN#s3://}" ;;
      *) B_NAME="${B_IN}" ;;
    esac
    _log "S3 버킷 지정: ${B_NAME}"
  else
    while :; do
      read -rp "S3 버킷 이름 또는 경로(s3://bucket-name) 입력: " B_IN
      B_IN="${B_IN:-}"
      [ -n "$B_IN" ] || { _warn "빈 값입니다. 다시 입력하세요."; continue; }
      case "$B_IN" in
        s3://*) B_NAME="${B_IN#s3://}" ;;
        *) B_NAME="${B_IN}" ;;
      esac
      break
    done
  fi
  if aws s3api head-bucket --bucket "$B_NAME" >/dev/null 2>&1; then
    _log "버킷 접근 확인: s3://${B_NAME}"
  else
    if [ "${S3_AUTO_CREATE}" = "yes" ]; then
      _log "버킷 없음 → 자동 생성 실행: ${B_NAME} (${AWS_RG})"
      if [ "${AWS_RG}" = "us-east-1" ]; then
        aws s3api create-bucket --bucket "$B_NAME"
      else
        aws s3api create-bucket --bucket "$B_NAME" --create-bucket-configuration LocationConstraint="${AWS_RG}"
      fi
      if [ "${S3_ENABLE_SSE}" = "yes" ]; then
        aws s3api put-bucket-encryption --bucket "$B_NAME" --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
      fi
      if [ "${S3_ENABLE_VERSIONING}" = "yes" ]; then
        aws s3api put-bucket-versioning --bucket "$B_NAME" --versioning-configuration Status=Enabled
      fi
      if [ -n "${S3_LIFECYCLE_DAYS}" ]; then
        aws s3api put-bucket-lifecycle-configuration --bucket "$B_NAME" --lifecycle-configuration "{\"Rules\":[{\"ID\":\"localchat-backup-expire\",\"Status\":\"Enabled\",\"Filter\":{},\"Expiration\":{\"Days\":${S3_LIFECYCLE_DAYS}}}]}"
      fi
      aws s3api head-bucket --bucket "$B_NAME" >/dev/null 2>&1 || { _err "버킷 생성 확인 실패"; exit 1; }
      _log "버킷 생성 완료: s3://${B_NAME}"
    else
      _warn "버킷 접근 실패 또는 없음: s3://${B_NAME} (권한/리전/이름 확인). 자동 생성 비활성화 상태"
      exit 1
    fi
  fi
  export S3_BUCKET="s3://${B_NAME}"
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
gunzip -c "${TMP}" \
  | docker exec -i localchat-db \
      mysql -u${DB_USER} -p${DB_PASS} ${DB_NAME}
rm -f "${TMP}"
RST
  chmod +x "${APP_DIR}/bin/restore-s3.sh"
}

wait_db_ready(){
  _log "DB health 대기 (최대 10분)"
  local deadline=$((SECONDS+600))
  while :; do
    if ! docker ps --format '{{.Names}}' | grep -q '^localchat-db$'; then
      sleep 2; continue
    fi
    local st
    st="$(docker inspect -f '{{.State.Health.Status}}' localchat-db 2>/dev/null || true)"
    if [ "$st" = "healthy" ]; then
      _log "DB 컨테이너 healthy"; break
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

write_backup_timer(){
  _log "systemd 타이머(30분) 생성"
  cat > /etc/systemd/system/localchat-backup.service <<UNIT
[Unit]
Description=LocalChat DB S3 백업 실행
After=network.target docker.service
Requires=docker.service

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

write_compose_service(){
  _log "systemd 유닛(부팅 자동 기동) 생성"
  cat > /etc/systemd/system/localchat-compose.service <<UNIT
[Unit]
Description=LocalChat via Docker Compose
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
WorkingDirectory=${APP_DIR}
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
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
PM=$(detect_pkg_mgr)
_log "패키지 관리자: ${PM}"

install_prereqs "${PM}"
ensure_dirs
write_app_py
write_requirements
write_dockerfile
write_chat_client
install_docker "${PM}"
open_firewall
write_compose
selinux_hint
compose_up
install_mysqldump_in_db

# === S3 백업/복구 ===
aws_login_env
write_backup_restore_scripts
wait_db_ready
initial_restore_if_exists
write_backup_timer
write_compose_service

_log "설치 완료! 브라우저에서 http://<서버IP>:${APP_PORT} 접속 → /setup에서 최초 관리자 계정 생성"
_log "Python 채팅 클라이언트: cd ${APP_DIR} && python3 chat_client.py"
if [ "${USE_LOCAL_DB_CONTAINER}" = "yes" ]; then
  _log "DB 접속 정보: user=${DB_USER} pass=${DB_PASS} db=${DB_NAME} (컨테이너 'db')"
fi