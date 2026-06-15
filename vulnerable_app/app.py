from __future__ import annotations

import hashlib
import sqlite3
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, jsonify, redirect, request, session, url_for


app = Flask(__name__)

# Intentionally vulnerable demo settings for the course scanner.
SECRET_KEY = "dev-vulnerable-secret-key"
API_KEY = "sk-demo-vulnerable-key-123456"
DB_PASSWORD = "plain-demo-db-password"
LAB_BACKDOOR_TOKEN = "lab-backdoor-token"
app.secret_key = SECRET_KEY

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "vulnerable.db"
FILES_DIR = BASE_DIR / "files"

DEMO_USERS = [
    (1, "admin", "admin123", "admin", "admin@example.local", "System administrator"),
    (2, "user1", "123456", "user", "user1@example.local", "Normal test user"),
    (3, "user2", "123456", "user", "user2@example.local", "Second normal user"),
]

DEFAULT_COMMENTS = [
    "欢迎来到课程靶场评论区。",
    "这里会故意原样渲染评论内容，便于扫描器识别 XSS。",
]


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def weak_md5(password: str) -> str:
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def init_db(seed: bool = False) -> None:
    if seed and DATABASE.exists():
        DATABASE.unlink()

    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                plain_password TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT NOT NULL,
                note TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                content TEXT NOT NULL,
                author TEXT NOT NULL DEFAULT 'guest'
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event TEXT NOT NULL,
                detail TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS balances (
                user_id INTEGER PRIMARY KEY,
                amount INTEGER NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_user TEXT NOT NULL,
                to_user TEXT NOT NULL,
                amount INTEGER NOT NULL,
                note TEXT NOT NULL
            )
            """
        )

        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if seed or user_count == 0:
            connection.execute("DELETE FROM users")
            connection.execute("DELETE FROM comments")
            connection.execute("DELETE FROM audit_logs")
            connection.execute("DELETE FROM balances")
            connection.execute("DELETE FROM transfers")
            # Weak password storage is deliberate: passwords are MD5 hashes and plaintext.
            connection.executemany(
                """
                INSERT INTO users
                    (id, username, password_hash, plain_password, role, email, note)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (user_id, username, weak_md5(password), password, role, email, note)
                    for user_id, username, password, role, email, note in DEMO_USERS
                ],
            )
            connection.executemany(
                "INSERT INTO comments (content, author) VALUES (?, ?)",
                [(comment, "system") for comment in DEFAULT_COMMENTS],
            )
            connection.execute(
                "INSERT INTO audit_logs (event, detail) VALUES (?, ?)",
                ("seed", "Demo database reset with weak credentials"),
            )
            connection.executemany(
                "INSERT INTO balances (user_id, amount) VALUES (?, ?)",
                [(1, 9000), (2, 1200), (3, 800)],
            )
        connection.commit()


@app.before_request
def ensure_database() -> None:
    init_db(seed=False)


def current_user_label() -> str:
    username = session.get("username")
    role = session.get("role")
    if username:
        return f"{username} ({role})"
    return "guest"


def page(title: str, body: str, active: str = "") -> str:
    username = session.get("username")
    auth_link = (
        f'<span class="user">Logged in as {username}</span><a href="/logout">Logout</a>'
        if username
        else '<a href="/login">Login</a>'
    )
    nav_items = [
        ("/", "Home", "home"),
        ("/login", "Login", "login"),
        ("/comments", "Comments", "comments"),
        ("/admin", "Admin", "admin"),
        ("/profile/2", "Profile #2", "profile"),
        ("/advanced", "Advanced", "advanced"),
        ("/lab", "Lab", "lab"),
    ]
    nav_html = "".join(
        f'<a class="{"active" if key == active else ""}" href="{href}">{label}</a>'
        for href, label, key in nav_items
    )
    return f"""
    <!doctype html>
    <html lang="zh-CN">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>{title}</title>
      <style>
        :root {{
          --ink: #172033;
          --muted: #5f6c80;
          --line: #d8dee8;
          --panel: #ffffff;
          --wash: #f5f7fb;
          --brand: #2563eb;
          --danger: #b42318;
          --warn-bg: #fff4d6;
          --ok-bg: #e8f7ef;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          font-family: Arial, "Microsoft YaHei", sans-serif;
          background: var(--wash);
          color: var(--ink);
          line-height: 1.55;
        }}
        header {{
          background: #172033;
          color: #fff;
          padding: 14px 24px;
          display: flex;
          justify-content: space-between;
          gap: 18px;
          align-items: center;
          flex-wrap: wrap;
        }}
        header strong {{ font-size: 18px; }}
        header a {{ color: #fff; text-decoration: none; margin-left: 14px; }}
        .shell {{ max-width: 1060px; margin: 0 auto; padding: 24px; }}
        .topnav {{
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          margin-bottom: 16px;
        }}
        .topnav a {{
          border: 1px solid var(--line);
          color: var(--ink);
          background: #fff;
          text-decoration: none;
          padding: 8px 12px;
          border-radius: 6px;
        }}
        .topnav a.active {{ border-color: var(--brand); color: var(--brand); }}
        main {{
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 8px;
          padding: 24px;
        }}
        h1 {{ margin-top: 0; font-size: 28px; }}
        h2 {{ margin-top: 28px; font-size: 20px; }}
        p {{ color: var(--muted); }}
        input, textarea, select {{
          width: 100%;
          padding: 10px;
          margin: 6px 0 14px;
          border: 1px solid #bcccdc;
          border-radius: 6px;
          font: inherit;
        }}
        button, .button {{
          display: inline-block;
          background: var(--brand);
          color: white;
          border: 0;
          border-radius: 6px;
          padding: 10px 16px;
          cursor: pointer;
          text-decoration: none;
          font: inherit;
        }}
        table {{
          width: 100%;
          border-collapse: collapse;
          margin: 14px 0;
        }}
        th, td {{
          text-align: left;
          border-bottom: 1px solid var(--line);
          padding: 10px;
          vertical-align: top;
        }}
        code {{
          background: #eef2f7;
          padding: 2px 5px;
          border-radius: 4px;
          color: #1f2937;
        }}
        .grid {{
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(230px, 1fr));
          gap: 14px;
        }}
        .card {{
          border: 1px solid var(--line);
          border-radius: 8px;
          padding: 14px;
          background: #fff;
        }}
        .notice {{
          background: var(--warn-bg);
          border: 1px solid #f7d476;
          color: #5c4300;
          padding: 12px;
          border-radius: 6px;
        }}
        .ok {{
          background: var(--ok-bg);
          border: 1px solid #b7dfc6;
          color: #174c2a;
          padding: 12px;
          border-radius: 6px;
        }}
        .danger {{ color: var(--danger); font-weight: 700; }}
        .comment {{
          border-bottom: 1px solid var(--line);
          padding: 12px 0;
        }}
        .meta {{ color: var(--muted); font-size: 13px; }}
        .split {{
          display: grid;
          grid-template-columns: minmax(0, 1fr) minmax(280px, 360px);
          gap: 18px;
        }}
        pre {{
          white-space: pre-wrap;
          overflow-wrap: anywhere;
          background: #0f172a;
          color: #e5e7eb;
          padding: 14px;
          border-radius: 8px;
          max-height: 360px;
          overflow: auto;
        }}
        @media (max-width: 780px) {{
          .split {{ grid-template-columns: 1fr; }}
        }}
      </style>
    </head>
    <body>
      <header>
        <strong>Vulnerable Test Site</strong>
        <nav>{auth_link}</nav>
      </header>
      <div class="shell">
        <nav class="topnav">{nav_html}</nav>
        <main>{body}</main>
      </div>
    </body>
    </html>
    """


@app.get("/")
def index() -> str:
    return page(
        "Vulnerable Test Site",
        """
        <h1>本地漏洞靶场</h1>
        <p class="notice">本网站只用于课程实验和本地授权扫描，包含故意设计的漏洞。</p>
        <div class="grid">
          <section class="card">
            <h2>DAST 目标</h2>
            <p><code>POST /login</code> SQL 注入登录绕过</p>
            <p><code>POST /comments</code> 和 <code>GET /comments</code> 存储型 XSS</p>
            <p><code>GET /admin</code> 和 <code>GET /profile/2</code> 越权访问</p>
          </section>
          <section class="card">
            <h2>SAST 目标</h2>
            <p>源码里保留演示用硬编码假密钥。</p>
            <p>用户密码同时保存为 MD5 和明文，便于弱密码存储规则命中。</p>
          </section>
          <section class="card">
            <h2>进阶漏洞区</h2>
            <p>包含 CSRF、路径穿越、SSRF、开放重定向、批量赋值、调试信息泄露。</p>
            <p><a class="button" href="/advanced">Open advanced labs</a></p>
          </section>
        </div>
        <h2>测试账号</h2>
        <table>
          <tr><th>Username</th><th>Password</th><th>Role</th></tr>
          <tr><td><code>admin</code></td><td><code>admin123</code></td><td>admin</td></tr>
          <tr><td><code>user1</code></td><td><code>123456</code></td><td>user</td></tr>
          <tr><td><code>user2</code></td><td><code>123456</code></td><td>user</td></tr>
          <tr><td><code>lab_backdoor</code></td><td><code>letmein-lab</code></td><td>admin</td></tr>
        </table>
        """,
        active="home",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page(
            "Login",
            """
            <h1>登录</h1>
            <p>扫描器会用错误密码和 SQL 注入 payload 对这个接口做对比。</p>
            <form method="post">
              <label>Username</label>
              <input name="username" autocomplete="username" value="user1">
              <label>Password</label>
              <input name="password" type="password" autocomplete="current-password" value="123456">
              <button type="submit">Login</button>
            </form>
            """,
            active="login",
        )

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    password_hash = weak_md5(password)

    # Lab backdoor for scanner iteration: intentionally grants admin in local demos.
    if username == "lab_backdoor" and password == "letmein-lab":
        session["user_id"] = 999
        session["username"] = "lab_backdoor"
        session["role"] = "admin"
        return page(
            "Dashboard",
            """
            <h1>Welcome, lab_backdoor</h1>
            <p class="ok">Login success. Role: <code>admin</code></p>
            <p class="notice">This is an intentional lab backdoor for local testing.</p>
            <p><a class="button" href="/admin">Open admin dashboard</a></p>
            """,
            active="login",
        )

    # Vulnerable by design: direct string interpolation enables SQL injection.
    sql = (
        "SELECT id, username, role FROM users "
        f"WHERE username = '{username}' AND password_hash = '{password_hash}'"
    )

    with get_connection() as connection:
        connection.execute(
            "INSERT INTO audit_logs (event, detail) VALUES (?, ?)",
            ("login_attempt", f"username={username}"),
        )
        user = connection.execute(sql).fetchone()
        connection.commit()

    if user:
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        session["role"] = user["role"]
        return page(
            "Dashboard",
            f"""
            <h1>Welcome, {user["username"]}</h1>
            <p class="ok">Login success. Role: <code>{user["role"]}</code></p>
            <p><a class="button" href="/admin">Open admin dashboard</a></p>
            """,
            active="login",
        )

    return (
        page(
            "Login failed",
            "<h1>Login failed</h1><p>Invalid username or password.</p>",
            active="login",
        ),
        401,
    )


@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/comments", methods=["GET", "POST"])
def comments() -> str:
    if request.method == "POST":
        content = (
            request.form.get("comment")
            or request.form.get("content")
            or request.form.get("message")
            or ""
        )
        author = session.get("username", "guest")
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO comments (content, author) VALUES (?, ?)",
                (content, author),
            )
            connection.commit()
        return redirect(url_for("comments"))

    with get_connection() as connection:
        rows = connection.execute(
            "SELECT content, author FROM comments ORDER BY id DESC"
        ).fetchall()

    rendered_comments = "\n".join(
        f'<div class="comment"><div>{row["content"]}</div>'
        f'<div class="meta">author: {row["author"]}</div></div>'
        for row in rows
    )
    return page(
        "Comments",
        f"""
        <h1>评论区</h1>
        <p>这里故意不做 HTML 转义，扫描器提交脚本标签后会在页面中原样看到 payload。</p>
        <form method="post">
          <label>Comment</label>
          <textarea name="comment" rows="4"></textarea>
          <button type="submit">Post</button>
        </form>
        <h2>All comments</h2>
        {rendered_comments or "<p>No comments yet.</p>"}
        """,
        active="comments",
    )


@app.get("/admin")
def admin() -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    with get_connection() as connection:
        users = connection.execute(
            "SELECT id, username, role, email, note FROM users ORDER BY id"
        ).fetchall()

    user_rows = "\n".join(
        f"<tr><td>{user['id']}</td><td>{user['username']}</td><td>{user['role']}</td>"
        f"<td>{user['email']}</td><td>{user['note']}</td></tr>"
        for user in users
    )

    # Vulnerable by design: login is checked, but admin role is not checked.
    return page(
        "Admin Dashboard",
        f"""
        <h1>Admin dashboard</h1>
        <p class="notice">当前用户：<code>{current_user_label()}</code>。此页故意没有校验管理员角色。</p>
        <table>
          <tr><th>ID</th><th>Username</th><th>Role</th><th>Email</th><th>Note</th></tr>
          {user_rows}
        </table>
        """,
        active="admin",
    )


@app.get("/profile/<int:user_id>")
def profile(user_id: int) -> str:
    if "user_id" not in session:
        return redirect(url_for("login"))

    # Vulnerable by design: any logged-in user can read any profile by ID.
    with get_connection() as connection:
        user = connection.execute(
            "SELECT id, username, role, email, note FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()

    if not user:
        return page("Not found", "<h1>Profile not found</h1>", active="profile"), 404

    return page(
        "Profile",
        f"""
        <h1>Profile: {user["username"]}</h1>
        <p class="notice">当前登录用户可以直接读取 URL 中指定 ID 的资料，没有校验资源归属。</p>
        <table>
          <tr><th>User ID</th><td><code>{user["id"]}</code></td></tr>
          <tr><th>Email</th><td><code>{user["email"]}</code></td></tr>
          <tr><th>Role</th><td><code>{user["role"]}</code></td></tr>
          <tr><th>Note</th><td>{user["note"]}</td></tr>
        </table>
        <p><a href="/profile/1">Profile #1</a> | <a href="/profile/2">Profile #2</a> | <a href="/profile/3">Profile #3</a></p>
        """,
        active="profile",
    )


@app.get("/advanced")
def advanced_home() -> str:
    return page(
        "Advanced Vulnerability Labs",
        """
        <h1>进阶漏洞实验区</h1>
        <p class="notice">这些模块用于让作业不止停留在基础漏洞。所有数据和凭据均为本地演示用途。</p>
        <div class="grid">
          <section class="card">
            <h2>CSRF 转账</h2>
            <p>转账接口没有 CSRF token，只依赖 cookie 会话。</p>
            <p><a class="button" href="/transfer">Open transfer</a></p>
          </section>
          <section class="card">
            <h2>路径穿越</h2>
            <p>文件下载接口没有规范化路径。</p>
            <p><a class="button" href="/download?file=public.txt">Open download</a></p>
          </section>
          <section class="card">
            <h2>SSRF</h2>
            <p>服务端会按用户输入抓取 URL。</p>
            <p><a class="button" href="/fetch?url=http://127.0.0.1:5001/health">Open fetch</a></p>
          </section>
          <section class="card">
            <h2>开放重定向</h2>
            <p>跳转接口直接信任 next 参数。</p>
            <p><a class="button" href="/redirect?next=/login">Open redirect</a></p>
          </section>
          <section class="card">
            <h2>批量赋值</h2>
            <p>资料更新接口允许普通用户提交 role 字段。</p>
            <p><a class="button" href="/settings">Open settings</a></p>
          </section>
          <section class="card">
            <h2>信息泄露</h2>
            <p>调试接口返回配置、用户和审计日志。</p>
            <p><a class="button" href="/debug/config">Open debug</a></p>
          </section>
        </div>
        """,
        active="advanced",
    )


@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    if "user_id" not in session:
        return redirect(url_for("login"))

    message = ""
    if request.method == "POST":
        to_user = request.form.get("to_user", "")
        amount = int(request.form.get("amount", "0") or 0)
        note = request.form.get("note", "")
        from_user = session.get("username", "unknown")
        with get_connection() as connection:
            connection.execute(
                "INSERT INTO transfers (from_user, to_user, amount, note) VALUES (?, ?, ?, ?)",
                (from_user, to_user, amount, note),
            )
            connection.execute(
                "UPDATE balances SET amount = amount - ? WHERE user_id = ?",
                (amount, session.get("user_id")),
            )
            connection.commit()
        message = f'<p class="ok">Transfer submitted: {amount} credits to {to_user}.</p>'

    with get_connection() as connection:
        balances = connection.execute(
            """
            SELECT users.username, balances.amount
            FROM balances JOIN users ON balances.user_id = users.id
            ORDER BY users.id
            """
        ).fetchall()
        transfers = connection.execute(
            "SELECT from_user, to_user, amount, note FROM transfers ORDER BY id DESC LIMIT 5"
        ).fetchall()

    balance_rows = "".join(
        f"<tr><td>{row['username']}</td><td>{row['amount']}</td></tr>" for row in balances
    )
    transfer_rows = "".join(
        f"<tr><td>{row['from_user']}</td><td>{row['to_user']}</td>"
        f"<td>{row['amount']}</td><td>{row['note']}</td></tr>"
        for row in transfers
    )
    return page(
        "CSRF Transfer",
        f"""
        <h1>CSRF 转账实验</h1>
        <p class="notice">此表单没有 CSRF token，也没有 SameSite/CSP 等保护，适合演示跨站请求伪造风险。</p>
        {message}
        <div class="split">
          <section>
            <form method="post">
              <label>To user</label>
              <input name="to_user" value="user2">
              <label>Amount</label>
              <input name="amount" type="number" value="100">
              <label>Note</label>
              <input name="note" value="course-demo">
              <button type="submit">Transfer</button>
            </form>
          </section>
          <section>
            <h2>Balances</h2>
            <table><tr><th>User</th><th>Amount</th></tr>{balance_rows}</table>
          </section>
        </div>
        <h2>Recent transfers</h2>
        <table><tr><th>From</th><th>To</th><th>Amount</th><th>Note</th></tr>{transfer_rows}</table>
        """,
        active="advanced",
    )


@app.get("/download")
def download_file():
    filename = request.args.get("file", "public.txt")
    target = FILES_DIR / filename
    try:
        content = target.read_text(encoding="utf-8", errors="ignore")
        status = 200
    except OSError as exc:
        content = f"Unable to read file: {exc}"
        status = 404

    return (
        page(
            "Path Traversal Download",
            f"""
            <h1>路径穿越下载</h1>
            <p class="notice">接口将用户输入直接拼到文件路径中，没有限制最终路径必须留在 files 目录。</p>
            <form method="get">
              <label>File</label>
              <input name="file" value="{filename}">
              <button type="submit">Read file</button>
            </form>
            <p>Resolved path: <code>{target}</code></p>
            <pre>{content}</pre>
            """,
            active="advanced",
        ),
        status,
    )


@app.get("/fetch")
def fetch_url():
    url = request.args.get("url", "http://127.0.0.1:5001/health")
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"}:
        result = "Only http and https URLs are supported in this lab."
    else:
        try:
            request_obj = urllib.request.Request(url, headers={"User-Agent": "vulnerable-lab-fetcher"})
            with urllib.request.urlopen(request_obj, timeout=3) as response:
                raw = response.read(2000)
            result = raw.decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            result = f"Fetch failed: {exc}"

    return page(
        "SSRF Fetcher",
        f"""
        <h1>SSRF URL 抓取</h1>
        <p class="notice">服务端会根据用户输入发起请求，没有做内网地址、元数据地址或协议目标限制。</p>
        <form method="get">
          <label>URL</label>
          <input name="url" value="{url}">
          <button type="submit">Fetch</button>
        </form>
        <pre>{result}</pre>
        """,
        active="advanced",
    )


@app.get("/redirect")
def open_redirect():
    next_url = request.args.get("next", "/")
    return redirect(next_url)


@app.route("/settings", methods=["GET", "POST"])
def settings():
    if "user_id" not in session:
        return redirect(url_for("login"))
    if session.get("user_id") == 999:
        return page(
            "Settings",
            "<h1>Settings</h1><p>Use user1 or user2 to demonstrate mass assignment.</p>",
            active="advanced",
        )

    message = ""
    allowed_columns = {"email", "note", "role", "plain_password"}
    if request.method == "POST":
        updates = {
            key: value
            for key, value in request.form.items()
            if key in allowed_columns
        }
        if updates:
            assignments = ", ".join(f"{key} = ?" for key in updates)
            values = list(updates.values()) + [session["user_id"]]
            with get_connection() as connection:
                connection.execute(
                    f"UPDATE users SET {assignments} WHERE id = ?",
                    values,
                )
                connection.commit()
            session["role"] = updates.get("role", session.get("role"))
            message = '<p class="ok">Settings updated.</p>'

    with get_connection() as connection:
        user = connection.execute(
            "SELECT username, email, role, note, plain_password FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    return page(
        "Mass Assignment Settings",
        f"""
        <h1>批量赋值资料更新</h1>
        <p class="notice">后端直接接收表单字段并更新数据库，普通用户可以提交 <code>role</code> 字段把自己改成 admin。</p>
        {message}
        <form method="post">
          <label>Username</label>
          <input value="{user['username']}" disabled>
          <label>Email</label>
          <input name="email" value="{user['email']}">
          <label>Note</label>
          <input name="note" value="{user['note']}">
          <label>Role</label>
          <select name="role">
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
          <label>Plain password recovery field</label>
          <input name="plain_password" value="{user['plain_password']}">
          <button type="submit">Save settings</button>
        </form>
        """,
        active="advanced",
    )


@app.get("/debug/config")
def debug_config():
    with get_connection() as connection:
        users = connection.execute(
            "SELECT id, username, role, email, plain_password FROM users ORDER BY id"
        ).fetchall()
        logs = connection.execute(
            "SELECT event, detail FROM audit_logs ORDER BY id DESC LIMIT 8"
        ).fetchall()

    payload = {
        "debug": True,
        "database": str(DATABASE),
        "secret_key": SECRET_KEY,
        "api_key": API_KEY,
        "db_password": DB_PASSWORD,
        "current_user": current_user_label(),
        "users": [dict(row) for row in users],
        "recent_audit_logs": [dict(row) for row in logs],
    }
    return jsonify(payload)


@app.get("/lab")
def lab_home() -> str:
    return page(
        "Lab Controls",
        """
        <h1>靶场控制台</h1>
        <p class="notice">这些入口只用于本地课程演示，方便扫描器前端和规则迭代时获得稳定状态。</p>
        <div class="grid">
          <section class="card">
            <h2>Health</h2>
            <p><code>GET /health</code></p>
            <p>返回 JSON，便于前端判断靶场是否启动。</p>
            <p><a class="button" href="/health">Open health</a></p>
          </section>
          <section class="card">
            <h2>Debug Session</h2>
            <p><code>/lab/debug/session?token=lab-backdoor-token</code></p>
            <p>仅本机可用，创建 admin 会话。</p>
            <p><a class="button" href="/lab/debug/session?token=lab-backdoor-token">Create session</a></p>
          </section>
          <section class="card">
            <h2>Reset Data</h2>
            <p><code>POST /lab/reset</code></p>
            <form method="post" action="/lab/reset">
              <input type="hidden" name="token" value="lab-backdoor-token">
              <button type="submit">Reset database</button>
            </form>
          </section>
        </div>
        """,
        active="lab",
    )


@app.get("/health")
def health():
    with get_connection() as connection:
        users = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        comments_count = connection.execute("SELECT COUNT(*) FROM comments").fetchone()[0]
    return jsonify(
        {
            "status": "ok",
            "service": "vulnerable-test-site",
            "users": users,
            "comments": comments_count,
        }
    )


@app.get("/lab/debug/session")
def lab_debug_session():
    token = request.args.get("token", "")
    if request.remote_addr not in {"127.0.0.1", "::1"} or token != LAB_BACKDOOR_TOKEN:
        return jsonify({"error": "forbidden"}), 403

    session["user_id"] = 999
    session["username"] = "lab_debug"
    session["role"] = "admin"
    return jsonify(
        {
            "status": "ok",
            "message": "Intentional local lab backdoor session created.",
            "user": {"id": 999, "username": "lab_debug", "role": "admin"},
        }
    )


@app.post("/lab/reset")
def lab_reset():
    token = request.form.get("token") or request.args.get("token", "")
    if request.remote_addr not in {"127.0.0.1", "::1"} or token != LAB_BACKDOOR_TOKEN:
        return jsonify({"error": "forbidden"}), 403

    init_db(seed=True)
    session.clear()
    return page(
        "Lab reset",
        """
        <h1>Database reset</h1>
        <p class="ok">Demo users and comments have been restored.</p>
        <p><a class="button" href="/">Back home</a></p>
        """,
        active="lab",
    )


if __name__ == "__main__":
    init_db(seed=True)
    app.run(host="127.0.0.1", port=5001, debug=True)
