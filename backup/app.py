#!/usr/bin/env python3
# /opt/localchat/app.py
import os, secrets, re, ipaddress
from functools import wraps
from flask import Flask, request, redirect, url_for, render_template_string, flash, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, join_room, emit
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

# ===== 환경설정 =====
SECRET_KEY   = os.environ.get("LOCALCHAT_SECRET", secrets.token_hex(16))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()  # 예) mysql+pymysql://user:pw@host:3306/db
APP_HOST     = os.environ.get("APP_HOST", "0.0.0.0")
APP_PORT     = int(os.environ.get("APP_PORT", "8000"))
TRUST_PROXY  = os.environ.get("TRUST_PROXY", "0") == "1"   # 리버스프록시 뒤일 때 X-Forwarded-For 사용
NUM_PROXIES  = int(os.environ.get("NUM_PROXIES", "1"))     # 신뢰할 프록시 홉 수

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL 환경변수가 필요합니다. 예) mysql+pymysql://user:pw@host:3306/db")

# ===== 앱/세션/소켓 =====
app = Flask(__name__)
app.config["SECRET_KEY"] = SECRET_KEY

# 신뢰 프록시 설정(선택)
if TRUST_PROXY:
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=NUM_PROXIES, x_proto=NUM_PROXIES, x_host=NUM_PROXIES, x_port=NUM_PROXIES)

socketio = SocketIO(app, async_mode="eventlet")
login_manager = LoginManager(app); login_manager.login_view = "login"
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)

# ===== DB 초기화/도우미 =====
def init_db():
    with engine.begin() as conn:
        conn.exec_driver_sql("""
        CREATE TABLE IF NOT EXISTS users (
          username VARCHAR(190) PRIMARY KEY,
          pw_hash  VARCHAR(255) NOT NULL,
          display_name VARCHAR(190),
          is_admin TINYINT(1) NOT NULL DEFAULT 0,
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
        # 기본 채팅방
        if conn.execute(text("SELECT COUNT(*) FROM rooms")).scalar() == 0:
            conn.execute(text(
              "INSERT INTO rooms(room_key, room_name) VALUES "
              "('general','일반'),('devops','DevOps'),('random','잡담')"))

def users_count():
    with engine.begin() as conn:
        return conn.execute(text("SELECT COUNT(*) FROM users")).scalar()

def get_user(username):
    with engine.begin() as conn:
        row = conn.execute(text(
            "SELECT username, pw_hash, is_admin FROM users WHERE username=:u"), {"u": username}
        ).fetchone()
        return dict(row) if row else None

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

# ===== 로그인 객체 =====
class User(UserMixin):
    def __init__(self, username, is_admin=False):
        self.id = username
        self.username = username
        self.is_admin = is_admin

@login_manager.user_loader
def load_user(user_id):
    u = get_user(user_id)
    return User(u["username"], bool(u["is_admin"])) if u else None

# ===== IP 허용 로직 =====
def client_ip():
    """
    신뢰 프록시 사용 시 X-Forwarded-For의 첫 IP, 아니면 remote_addr 반환
    """
    if TRUST_PROXY:
        xff = request.headers.get("X-Forwarded-For", "")
        if xff:
            # 가장 왼쪽 클라이언트 주소 사용
            return xff.split(",")[0].strip()
    return request.remote_addr or "0.0.0.0"

def ip_allowed(ip: str) -> bool:
    patterns = get_allowed_patterns()
    if not patterns:  # 목록이 비어있으면 모두 허용
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for pat in patterns:
        try:
            if "/" in pat:
                # CIDR
                net = ipaddress.ip_network(pat, strict=False)
                if addr in net:
                    return True
            else:
                # 단일 IP
                if addr == ipaddress.ip_address(pat):
                    return True
        except ValueError:
            # 잘못된 패턴은 무시
            continue
    return False

# 전역 필터: 로그인/세션 이전 단계에서 IP 차단
@app.before_request
def enforce_ip_allowlist():
    # setup: 최초 사용자 0명일 때는 누구나 접근해야 하므로 예외
    if users_count() == 0 and request.endpoint in ("setup", "static"):
        return
    # 정적/헬스체크 등 필요한 예외가 있으면 여기에 추가
    allowed = ip_allowed(client_ip())
    # 허용되지 않은 경우: 로그인/설정 포함 전부 차단(403)
    if not allowed:
        abort(403)

# ===== 관리자 권한 데코레이터 =====
def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not getattr(current_user, "is_admin", False):
            abort(403)
        return f(*args, **kwargs)
    return wrapper

# ===== 템플릿 =====
TPL_LAYOUT = """<!doctype html><html lang="ko"><head>
<meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>{{ title or 'LocalChat' }}</title>
<style>
body{font-family:sans-serif;margin:20px}.container{max-width:900px;margin:0 auto}
.card{border:1px solid #ddd;padding:16px;border-radius:8px}.flash{background:#ffeecc;padding:8px;margin-bottom:10px;border-radius:4px}
input[type=text],input[type=password]{width:100%;padding:10px;margin:8px 0}button{padding:10px 16px}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:8px}th{background:#f7f7f7}
.msg{margin:6px 0}.you{font-weight:bold}
.nav a{margin-right:10px}
</style>
<script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
</head><body><div class="container">
<div class="nav" style="margin-bottom:12px">
{% if current_user.is_authenticated %}
  {{ current_user.username }}님 |
  <a href="{{ url_for('rooms') }}">채팅방</a>
  {% if current_user.is_admin %}| <a href="{{ url_for('admin_ip_allowlist') }}">관리자: IP 허용</a>{% endif %}
  | <a href="{{ url_for('logout') }}">로그아웃</a>
{% endif %}
</div>
{% with messages = get_flashed_messages() %}{% if messages %}{% for m in messages %}<div class="flash">{{ m }}</div>{% endfor %}{% endif %}{% endwith %}
<div class="card">{% block content %}{% endblock %}</div>
</div></body></html>"""

TPL_LOGIN = """{% extends "layout" %}{% block content %}
<h2>로그인</h2>
{% if first_run %}<div class="flash">초기 설정이 필요합니다. <a href="{{ url_for('setup') }}">여기</a>에서 최초 계정을 만드세요.</div>{% endif %}
<form method="post">
  <label>아이디</label><input type="text" name="username" required>
  <label>비밀번호</label><input type="password" name="password" required>
  <button type="submit">로그인</button>
</form>
{% endblock %}"""

TPL_SETUP = """{% extends "layout" %}{% block content %}
<h2>최초 계정 생성</h2>
<form method="post" autocomplete="off">
  <label>아이디(영문/숫자/._- 3~32자)</label><input type="text" name="username" required>
  <label>비밀번호(최소 8자)</label><input type="password" name="password" required>
  <label>비밀번호 확인</label><input type="password" name="password2" required>
  <button type="submit">계정 만들기</button>
</form>
<p style="color:#666">※ 최초 1회만 생성 가능하며, 이후에는 로그인 화면만 노출됩니다.</p>
{% endblock %}"""

TPL_ROOMS = """{% extends "layout" %}{% block content %}
<h2>채팅방 리스트</h2>
<ul>
{% for r in rooms %}
<li><a href="{{ url_for('chat_room', room_key=r.room_key) }}"># {{ r.room_name }} ({{ r.room_key }})</a></li>
{% endfor %}
</ul>
{% endblock %}"""

TPL_CHAT = """{% extends "layout" %}{% block content %}
<h2># {{ room.room_name }} ({{ room.room_key }})</h2>

<div id="chat" style="border:1px solid #ccc;height:320px;overflow:auto;padding:8px;margin:8px 0">
  {# 초기 로드: 최근 50개 메시지(시간순) #}
  {% for m in msgs %}
    <div class="msg">
      <b>[{{ m.username }}]</b> {{ m.body }}
      <span style="color:#888;font-size:0.85em"> ({{ m.created_at }})</span>
    </div>
  {% endfor %}
</div>

<form id="sendForm">
  <input type="text" id="msg" placeholder="메시지 입력..." autocomplete="off">
  <button type="submit">전송</button>
</form>

<script src="https://cdn.socket.io/4.7.2/socket.io.min.js" crossorigin="anonymous"></script>
<script>
const socket = io();
const username = "{{ current_user.username }}";
const room     = "{{ room.room_key }}";

const chat = document.getElementById('chat');
const form = document.getElementById('sendForm');
const msg  = document.getElementById('msg');

function addLine(text, cls){
  const d=document.createElement('div');
  d.className='msg '+(cls||'');
  d.textContent=text;
  chat.appendChild(d);
  chat.scrollTop = chat.scrollHeight;
}

// 연결되면 방 참가
socket.on('connect', ()=>{ socket.emit('join', {room}); });

// 시스템/채팅 수신
socket.on('sys',  d=> addLine(d.text));
socket.on('chat', d=> {
  addLine((d.user===username?'나':'['+d.user+']')+': '+d.text, d.user===username?'you':'');
});

// 전송
form.addEventListener('submit', e=>{
  e.preventDefault();
  const text=msg.value.trim(); if(!text) return;
  socket.emit('chat', {room, text});
  msg.value='';
});
</script>
{% endblock %}"""

TPL_ADMIN_IP = """{% extends "layout" %}{% block content %}
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

@app.context_processor
def inject_layout(): return {"layout": TPL_LAYOUT}

# ===== 라우트 =====
@app.route("/")
def index():
    if users_count() == 0:  # 최초 실행
        return redirect(url_for("setup"))
    return redirect(url_for("rooms") if current_user.is_authenticated else url_for("login"))

@app.route("/setup", methods=["GET","POST"])
def setup():
    if users_count() > 0:
        flash("이미 초기 설정이 완료되었습니다."); return redirect(url_for("login"))
    if request.method == "POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        p2= request.form.get("password2") or ""
        if not re.fullmatch(r"[A-Za-z0-9._-]{3,32}", u):
            flash("아이디 형식이 올바르지 않습니다."); return render_template_string(TPL_SETUP)
        if len(p) < 8:
            flash("비밀번호는 8자 이상이어야 합니다."); return render_template_string(TPL_SETUP)
        if p != p2:
            flash("비밀번호 확인이 일치하지 않습니다."); return render_template_string(TPL_SETUP)
        try:
            # 최초 계정은 관리자
            create_user(u, p, is_admin=True)
            flash("최초(관리자) 계정이 생성되었습니다. 로그인하세요.")
            return redirect(url_for("login"))
        except Exception as e:
            flash(f"계정 생성 실패: {e}")
    return render_template_string(TPL_SETUP, title="최초 계정 생성")

@app.route("/login", methods=["GET","POST"])
def login():
    first_run = (users_count() == 0)
    if first_run: return redirect(url_for("setup"))
    if request.method=="POST":
        u = (request.form.get("username") or "").strip()
        p = request.form.get("password") or ""
        row = get_user(u)
        if row and check_password_hash(row["pw_hash"], p):
            login_user(User(u, bool(row["is_admin"]))); return redirect(url_for("rooms"))
        flash("아이디 또는 비밀번호가 올바르지 않습니다.")
    return render_template_string(TPL_LOGIN, title="로그인", current_user=current_user, first_run=first_run), 200, {"Content-Type":"text/html; charset=utf-8"}

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

@app.route("/chat/<room_key>")
@login_required
def chat_room(room_key):
    with engine.begin() as conn:
        room = conn.execute(
            text("SELECT room_key, room_name FROM rooms WHERE room_key=:k"),
            {"k": room_key}
        ).fetchone()
        if not room:
            flash("존재하지 않는 채팅방입니다."); 
            return redirect(url_for("rooms"))

        # 최근 50개 메시지 (최신순으로 뽑은 뒤, 화면에선 시간순으로 보여주기 위해 역순 변환)
        msgs = conn.execute(text("""
            SELECT username, body, created_at
            FROM messages
            WHERE room_key=:k
            ORDER BY created_at DESC
            LIMIT 50
        """), {"k": room_key}).all()

    # 화면에선 오래된 → 최신 순서로 보이도록 역순
    msgs = list(reversed([dict(m) for m in msgs]))

    return render_template_string(
        TPL_CHAT, 
        title=f"채팅 - {room.room_name}", 
        room=room, 
        current_user=current_user,
        msgs=msgs,                # ← 템플릿에 전달
    )

# ===== 관리자: IP 허용 목록 =====
@app.route("/admin/ip-allowlist", methods=["GET","POST"])
@login_required
@admin_required
def admin_ip_allowlist():
    # 추가
    if request.method == "POST":
        pattern = (request.form.get("pattern") or "").strip()
        note    = (request.form.get("note") or "").strip() or None
        # 간단 형식 검증
        ok = False
        try:
            if "/" in pattern:
                ipaddress.ip_network(pattern, strict=False)
                ok = True
            else:
                ipaddress.ip_address(pattern)
                ok = True
        except ValueError:
            ok = False
        if not ok:
            flash("패턴 형식이 올바르지 않습니다. 단일 IP 또는 CIDR(예: 10.0.0.0/24)로 입력하세요.")
        else:
            add_allowed_pattern(pattern, note)
            flash("추가되었습니다.")
    # 목록 조회
    with engine.begin() as conn:
        rows = conn.execute(text("SELECT id, pattern, note, created_at FROM allowed_ips ORDER BY id")).all()
    return render_template_string(TPL_ADMIN_IP, title="관리자: 허용 IP", rows=rows, current_user=current_user)

@app.route("/admin/ip-allowlist/delete/<int:id>", methods=["POST"])
@login_required
@admin_required
def admin_ip_delete(id):
    delete_allowed_pattern(id)
    flash("삭제되었습니다.")
    return redirect(url_for("admin_ip_allowlist"))

# ===== 소켓 =====
@socketio.on("join")
def on_join(data):
    # 소켓 핸드셋에서도 IP 차단(웹소켓 업그레이드 요청은 before_request를 타지만 안전상 재검사)
    if not ip_allowed(client_ip()):
        return  # 무응답
    room = data.get("room"); join_room(room)
    emit("sys", {"text": f"[시스템] {current_user.username}님 입장"}, to=room)

@socketio.on("chat")
def on_chat(data):
    if not ip_allowed(client_ip()):
        return
    room = data.get("room"); text = (data.get("text") or "").strip()
    if not room or not text: return
    with engine.begin() as conn:
        conn.execute(text(
            "INSERT INTO messages(room_key, username, body) VALUES(:r,:u,:b)"),
            {"r": room, "u": current_user.username, "b": text}
        )
    emit("chat", {"user": current_user.username, "text": text}, to=room)

# ===== 시작 =====
if __name__ == "__main__":
    try:
        init_db()
    except OperationalError as e:
        raise SystemExit(f"[DB 연결 실패] {e}\nDATABASE_URL을 확인하세요.")
    socketio.run(app, host=APP_HOST, port=APP_PORT)