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
    "这台九成新的校园自行车还在吗？可以今晚在东门交易吗？",
    "求购一台二手显示器，预算 300 以内，支持宿舍楼下自提。",
]

FEATURED_PRODUCTS = [
    {
        "title": "九成新山地车",
        "price": "￥320",
        "tag": "东区宿舍",
        "seller": "user1",
        "desc": "通勤代步，刹车和变速都正常，送车锁。",
    },
    {
        "title": "考研英语资料全套",
        "price": "￥45",
        "tag": "图书馆自取",
        "seller": "user2",
        "desc": "含真题、单词书和笔记，适合备考同学。",
    },
    {
        "title": "宿舍小冰箱",
        "price": "￥180",
        "tag": "南区 5 栋",
        "seller": "admin",
        "desc": "容量 46L，制冷正常，毕业出清。",
    },
    {
        "title": "机械键盘 87 键",
        "price": "￥99",
        "tag": "计算机学院",
        "seller": "user1",
        "desc": "茶轴，有轻微使用痕迹，支持当面验货。",
    },
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
        f'<span class="user">当前用户：{username}</span><a href="/logout">退出</a>'
        if username
        else '<a href="/login">登录 / 发布</a>'
    )
    nav_items = [
        ("/", "首页推荐", "home"),
        ("/comments", "商品留言", "comments"),
        ("/login", "登录发布", "login"),
        ("/profile/2", "卖家主页", "profile"),
        ("/advanced", "交易服务", "advanced"),
        ("/admin", "卖家中心", "admin"),
        ("/lab", "靶场控制", "lab"),
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
          --ink: #1f2933;
          --muted: #697586;
          --line: #ebe5dc;
          --panel: #ffffff;
          --wash: #f7f3ee;
          --brand: #ff6a00;
          --brand-2: #ffd14d;
          --danger: #b42318;
          --warn-bg: #fff7df;
          --ok-bg: #e9f8ef;
        }}
        * {{ box-sizing: border-box; }}
        body {{
          margin: 0;
          font-family: Arial, "Microsoft YaHei", "PingFang SC", sans-serif;
          background:
            linear-gradient(180deg, #fff2d0 0, #f7f3ee 230px),
            var(--wash);
          color: var(--ink);
          line-height: 1.55;
        }}
        header {{
          position: sticky;
          top: 0;
          z-index: 2;
          background: rgba(255, 255, 255, 0.92);
          color: var(--ink);
          padding: 12px 24px;
          display: flex;
          justify-content: space-between;
          gap: 18px;
          align-items: center;
          flex-wrap: wrap;
          border-bottom: 1px solid rgba(255, 106, 0, 0.16);
          backdrop-filter: blur(12px);
        }}
        header strong {{ font-size: 22px; color: var(--brand); letter-spacing: 0; }}
        header a {{ color: var(--ink); text-decoration: none; margin-left: 14px; font-weight: 700; }}
        .shell {{ max-width: 1160px; margin: 0 auto; padding: 22px 24px 36px; }}
        .topnav {{
          display: flex;
          gap: 8px;
          flex-wrap: wrap;
          margin-bottom: 18px;
        }}
        .topnav a {{
          border: 1px solid rgba(255, 106, 0, 0.14);
          color: var(--ink);
          background: rgba(255, 255, 255, 0.82);
          text-decoration: none;
          padding: 9px 14px;
          border-radius: 999px;
        }}
        .topnav a.active {{ border-color: var(--brand); color: var(--brand); background: #fff8ed; }}
        main {{
          background: var(--panel);
          border: 1px solid var(--line);
          border-radius: 14px;
          padding: 24px;
          box-shadow: 0 20px 44px rgba(119, 84, 48, 0.12);
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
          background: linear-gradient(135deg, var(--brand), #ff9b21);
          color: #fff;
          border: 0;
          border-radius: 999px;
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
          grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
          gap: 16px;
        }}
        .card {{
          border: 1px solid var(--line);
          border-radius: 12px;
          padding: 16px;
          background: #fff;
        }}
        .hero {{
          display: grid;
          grid-template-columns: minmax(0, 1.35fr) minmax(280px, 0.65fr);
          gap: 18px;
          align-items: stretch;
          margin-bottom: 18px;
        }}
        .hero-main {{
          min-height: 230px;
          border-radius: 18px;
          padding: 28px;
          color: #3c2600;
          background:
            linear-gradient(135deg, rgba(255, 209, 77, 0.96), rgba(255, 106, 0, 0.88)),
            #ffb000;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
        }}
        .hero-main h1 {{ max-width: 620px; font-size: 38px; line-height: 1.15; }}
        .hero-main p {{ color: #4a3000; max-width: 640px; font-size: 17px; }}
        .searchbar {{
          display: flex;
          gap: 10px;
          padding: 8px;
          border-radius: 999px;
          background: rgba(255, 255, 255, 0.9);
        }}
        .searchbar input {{ margin: 0; border: 0; background: transparent; }}
        .searchbar button {{ white-space: nowrap; }}
        .quick-panel {{
          border-radius: 18px;
          padding: 20px;
          background: #fff;
          border: 1px solid var(--line);
        }}
        .product-card {{
          display: grid;
          gap: 10px;
          min-height: 190px;
        }}
        .product-cover {{
          height: 96px;
          border-radius: 10px;
          background:
            linear-gradient(135deg, rgba(255, 106, 0, 0.24), rgba(50, 184, 112, 0.18)),
            #f7eee1;
          display: grid;
          place-items: center;
          color: #9a5a00;
          font-weight: 800;
        }}
        .price {{ color: var(--brand); font-size: 22px; font-weight: 900; }}
        .tag {{
          display: inline-block;
          width: fit-content;
          padding: 3px 8px;
          border-radius: 999px;
          color: #8a4b00;
          background: #fff2d0;
          font-size: 13px;
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
        .sr-only {{
          position: absolute;
          width: 1px;
          height: 1px;
          padding: 0;
          margin: -1px;
          overflow: hidden;
          clip: rect(0, 0, 0, 0);
          white-space: nowrap;
          border: 0;
        }}
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
          .hero {{ grid-template-columns: 1fr; }}
          .hero-main h1 {{ font-size: 30px; }}
        }}
      </style>
    </head>
    <body>
      <header>
        <strong>橙集校园</strong>
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
    product_cards = "\n".join(
        f"""
        <section class="card product-card">
          <div class="product-cover">{item["title"]}</div>
          <strong>{item["title"]}</strong>
          <span class="price">{item["price"]}</span>
          <span class="tag">{item["tag"]}</span>
          <p>{item["desc"]}</p>
          <p class="meta">卖家：{item["seller"]} · 支持线下验货</p>
        </section>
        """
        for item in FEATURED_PRODUCTS
    )
    return page(
        "橙集校园 - 校园二手交易",
        f"""
        <section class="hero">
          <div class="hero-main">
            <div>
              <h1>把闲置留在校园，把好物交给同学</h1>
              <p>橙集校园是面向课程演示的本地二手交易平台，包含商品浏览、留言咨询、卖家主页和交易服务等常见流程。</p>
            </div>
            <form class="searchbar" action="/comments" method="get">
              <input name="q" placeholder="搜索自行车、教材、键盘、宿舍小家电">
              <button type="submit">搜索好物</button>
            </form>
          </div>
          <aside class="quick-panel">
            <h2>今日校园热卖</h2>
            <p><span class="price">27</span> 件好物正在流转</p>
            <p>登录后可发布闲置、联系卖家、查看交易服务。</p>
            <p><a class="button" href="/login">登录并发布</a></p>
          </aside>
        </section>
        <h2>推荐闲置</h2>
        <div class="grid">
          {product_cards}
        </div>
        <h2>演示账号</h2>
        <table>
          <tr><th>账号</th><th>密码</th><th>身份</th><th>用途</th></tr>
          <tr><td><code>admin</code></td><td><code>admin123</code></td><td>平台运营</td><td>卖家中心演示</td></tr>
          <tr><td><code>user1</code></td><td><code>123456</code></td><td>普通学生</td><td>商品发布和留言</td></tr>
          <tr><td><code>user2</code></td><td><code>123456</code></td><td>普通学生</td><td>个人主页越权演示</td></tr>
          <tr><td><code>lab_backdoor</code></td><td><code>letmein-lab</code></td><td>本地调试</td><td>课程靶场辅助登录</td></tr>
        </table>
        <p class="notice">说明：这是本地授权课程靶场。页面伪装成正常交易平台，但保留故意设计的漏洞测试点。</p>
        """,
        active="home",
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return page(
            "登录发布 - 橙集校园",
            """
            <h1>登录橙集校园</h1>
            <p>登录后可以发布闲置、查看卖家中心、管理个人资料。</p>
            <form method="post">
              <label>校园账号</label>
              <input name="username" autocomplete="username" value="user1">
              <label>密码</label>
              <input name="password" type="password" autocomplete="current-password" value="123456">
              <button type="submit">登录并进入卖家中心</button>
            </form>
            <p class="meta">演示账号：user1 / 123456。课程扫描器仍会使用此路径测试登录安全。</p>
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
            "卖家中心",
            """
            <h1>欢迎回来，lab_backdoor</h1>
            <p class="ok">登录成功。当前身份：<code>平台运营</code></p>
            <p class="notice">这是本地课程靶场的调试入口。</p>
            <p><a class="button" href="/admin">进入卖家中心</a></p>
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
            "卖家中心",
            f"""
            <h1>欢迎回来，{user["username"]}</h1>
            <p class="ok">登录成功。当前身份：<code>{user["role"]}</code></p>
            <p>你可以继续发布校园闲置，或查看卖家中心的数据看板。</p>
            <p><a class="button" href="/admin">进入卖家中心</a></p>
            """,
            active="login",
        )

    return (
        page(
            "Login failed",
            "<h1>登录失败</h1><p>账号或密码不正确，请检查后重试。</p>",
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
        f'<div class="meta">留言人：{row["author"]} · 商品咨询区</div></div>'
        for row in rows
    )
    return page(
        "商品留言 - 橙集校园",
        f"""
        <h1>商品留言</h1>
        <p>买家可以在这里咨询商品成色、取货地点和交易时间。平台会把留言展示给卖家和其他同学。</p>
        <form method="post">
          <label>给卖家留言</label>
          <textarea name="comment" rows="4" placeholder="例如：显示器还在吗？今晚可以在图书馆门口交易吗？"></textarea>
          <button type="submit">发布留言</button>
        </form>
        <h2>最新留言</h2>
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
        "卖家中心 - 橙集校园",
        f"""
        <h1>卖家中心</h1>
        <span class="sr-only">admin dashboard</span>
        <p class="notice">当前用户：<code>{current_user_label()}</code>。这里伪装成平台运营数据看板，但故意缺少角色校验。</p>
        <div class="grid">
          <section class="card"><h2>今日发布</h2><p><span class="price">12</span> 件</p></section>
          <section class="card"><h2>待确认交易</h2><p><span class="price">5</span> 单</p></section>
          <section class="card"><h2>需要复核留言</h2><p><span class="price">3</span> 条</p></section>
        </div>
        <h2>平台用户</h2>
        <table>
          <tr><th>ID</th><th>账号</th><th>身份</th><th>邮箱</th><th>备注</th></tr>
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
        "卖家主页 - 橙集校园",
        f"""
        <h1>卖家主页：{user["username"]}</h1>
        <p class="notice">这里展示卖家公开资料和联系信息。当前实现故意没有校验资料归属。</p>
        <table>
          <tr><th>卖家 ID</th><td><code>{user["id"]}</code></td></tr>
          <tr><th>联系邮箱</th><td><code>{user["email"]}</code></td></tr>
          <tr><th>账号身份</th><td><code>{user["role"]}</code></td></tr>
          <tr><th>个人说明</th><td>{user["note"]}</td></tr>
        </table>
        <h2>在售闲置</h2>
        <div class="grid">
          <section class="card product-card"><div class="product-cover">教材</div><strong>课程教材打包</strong><span class="price">￥60</span><p>适合低年级同学。</p></section>
          <section class="card product-card"><div class="product-cover">键盘</div><strong>二手机械键盘</strong><span class="price">￥99</span><p>支持当面验货。</p></section>
        </div>
        <p><a href="/profile/1">卖家 #1</a> | <a href="/profile/2">卖家 #2</a> | <a href="/profile/3">卖家 #3</a></p>
        """,
        active="profile",
    )


@app.get("/advanced")
def advanced_home() -> str:
    return page(
        "交易服务 - 橙集校园",
        """
        <h1>交易服务</h1>
        <p>这里模拟二手平台的订单、资料下载、外部链接跳转、卖家设置和调试服务。</p>
        <div class="grid">
          <section class="card">
            <h2>校园币担保交易</h2>
            <p>买家向卖家支付校园币，确认收货后完成结算。</p>
            <p><a class="button" href="/transfer">打开交易</a></p>
          </section>
          <section class="card">
            <h2>交易凭证下载</h2>
            <p>下载商品说明、验货记录和交易凭证。</p>
            <p><a class="button" href="/download?file=public.txt">下载凭证</a></p>
          </section>
          <section class="card">
            <h2>外部商品链接预览</h2>
            <p>卖家可以粘贴商品参考链接，由平台生成预览。</p>
            <p><a class="button" href="/fetch?url=http://127.0.0.1:5001/health">生成预览</a></p>
          </section>
          <section class="card">
            <h2>站外联系跳转</h2>
            <p>平台会跳转到卖家填写的联系页面。</p>
            <p><a class="button" href="/redirect?next=/login">打开跳转</a></p>
          </section>
          <section class="card">
            <h2>卖家资料设置</h2>
            <p>修改邮箱、个人说明和展示信息。</p>
            <p><a class="button" href="/settings">打开设置</a></p>
          </section>
          <section class="card">
            <h2>平台诊断状态</h2>
            <p>模拟运营后台诊断接口。</p>
            <p><a class="button" href="/debug/config">查看诊断</a></p>
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
        "校园币担保交易 - 橙集校园",
        f"""
        <h1>校园币担保交易</h1>
        <p>买家可以向卖家支付校园币作为线下交易担保。</p>
        <p class="notice">该交易表单故意没有 CSRF token，保留课程靶场的安全测试点。</p>
        {message}
        <div class="split">
          <section>
            <form method="post">
              <label>收款卖家</label>
              <input name="to_user" value="user2">
              <label>校园币金额</label>
              <input name="amount" type="number" value="100">
              <label>交易备注</label>
              <input name="note" value="二手教材当面交易">
              <button type="submit">提交担保交易</button>
            </form>
          </section>
          <section>
            <h2>账户余额</h2>
            <table><tr><th>用户</th><th>校园币</th></tr>{balance_rows}</table>
          </section>
        </div>
        <h2>最近交易</h2>
        <table><tr><th>付款方</th><th>收款方</th><th>金额</th><th>备注</th></tr>{transfer_rows}</table>
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
            <h1>交易凭证下载</h1>
            <p>下载卖家上传的商品说明、验货照片记录和线下交易凭证。</p>
            <p class="notice">该下载接口故意把用户输入拼到文件路径中，保留路径穿越测试点。</p>
            <form method="get">
              <label>凭证文件</label>
              <input name="file" value="{filename}">
              <button type="submit">下载 / 预览</button>
            </form>
            <p>系统解析路径：<code>{target}</code></p>
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
        "外部商品链接预览 - 橙集校园",
        f"""
        <h1>外部商品链接预览</h1>
        <p>卖家可以粘贴参考链接，平台会尝试抓取页面片段生成商品预览。</p>
        <p class="notice">该功能故意由服务端按用户输入抓取 URL，保留 SSRF 测试点。</p>
        <form method="get">
          <label>参考链接</label>
          <input name="url" value="{url}">
          <button type="submit">生成预览</button>
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
            "卖家资料设置",
            "<h1>卖家资料设置</h1><p>请使用 user1 或 user2 演示普通卖家的资料编辑流程。</p>",
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
        "卖家资料设置 - 橙集校园",
        f"""
        <h1>卖家资料设置</h1>
        <p>维护卖家联系方式、个人说明和账号展示信息。</p>
        <p class="notice">该接口故意直接接收表单字段并更新数据库，普通用户可以提交 <code>role</code> 字段。</p>
        {message}
        <form method="post">
          <label>校园账号</label>
          <input value="{user['username']}" disabled>
          <label>联系邮箱</label>
          <input name="email" value="{user['email']}">
          <label>卖家说明</label>
          <input name="note" value="{user['note']}">
          <label>账号身份</label>
          <select name="role">
            <option value="user">user</option>
            <option value="admin">admin</option>
          </select>
          <label>找回密码备注字段</label>
          <input name="plain_password" value="{user['plain_password']}">
          <button type="submit">保存卖家资料</button>
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
        "靶场控制 - 橙集校园",
        """
        <h1>靶场控制台</h1>
        <p class="notice">这些入口只用于本地课程演示，方便扫描器前端和规则迭代时获得稳定状态。</p>
        <div class="grid">
          <section class="card">
            <h2>Health</h2>
            <p><code>GET /health</code></p>
            <p>返回 JSON，便于前端判断交易平台是否启动。</p>
            <p><a class="button" href="/health">打开健康检查</a></p>
          </section>
          <section class="card">
            <h2>Debug Session</h2>
            <p><code>/lab/debug/session?token=lab-backdoor-token</code></p>
            <p>仅本机可用，创建平台运营会话。</p>
            <p><a class="button" href="/lab/debug/session?token=lab-backdoor-token">创建调试会话</a></p>
          </section>
          <section class="card">
            <h2>Reset Data</h2>
            <p><code>POST /lab/reset</code></p>
            <form method="post" action="/lab/reset">
              <input type="hidden" name="token" value="lab-backdoor-token">
              <button type="submit">重置演示数据</button>
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
            "service": "campus-secondhand-market",
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
        <h1>演示数据已重置</h1>
        <p class="ok">用户、商品留言和交易记录已恢复为初始状态。</p>
        <p><a class="button" href="/">返回首页</a></p>
        """,
        active="lab",
    )


if __name__ == "__main__":
    init_db(seed=True)
    app.run(host="127.0.0.1", port=5001, debug=True)
