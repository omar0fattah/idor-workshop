"""
IDOR + SQL Injection Workshop Demo App
----------------------------------------
A deliberately vulnerable mini Flask app for teaching two bugs in one
sitting: SQL Injection (the way in) and Insecure Direct Object Reference
(what you do once you're in).

How the vuln chain works:
  - The login form builds its SQL query with raw string formatting, so a
    classic auth-bypass payload (e.g.  ' OR '1'='1' --  ) in the username
    field returns a row without needing a real password. No credentials
    are given out anywhere in the UI on purpose - this is the way in.
  - Because the query has no ORDER BY, the bypass payload lands you on
    whichever row SQLite returns first (a normal member, not staff), so
    you land as a regular user - not instantly at the flag.
  - From there, /profile?user_id=<id> never checks that the logged-in
    user actually owns that id. So changing the number in the URL shows
    you someone else's badge. One "staff" account (not id 1 - not the
    obvious guess) holds the flag, mixed in among several decoy profiles
    with no login of their own, so people have to actually enumerate IDs.

Run it with:  python3 app.py
Then visit:   http://127.0.0.1:5050
"""

import sqlite3
from pathlib import Path

from flask import Flask, request, redirect, session, render_template_string

app = Flask(__name__)
app.secret_key = "workshop-demo-not-for-production"  # fine for a local demo only

DB_PATH = Path(__file__).parent / "workshop.db"

# ---------------------------------------------------------------------------
# Seed data - inserted in this order, which matters: the classic
# ' OR '1'='1' --  bypass has no ORDER BY, so it returns the FIRST row
# SQLite has (Bob), not the admin. People still have to go find the
# admin's id themselves via IDOR afterward.
# ---------------------------------------------------------------------------
SEED_USERS = [
    # (username, password, display_name, role, team, joined, bio, secret, is_flag_account)
    ("bob", "bob123", "Bob", "MEMBER", "Networking", "Sep 2025",
     "Still figuring out regex. Send help.",
     "Forgot where I parked. Again.", 0),
    (None, None, "Youssef", "MEMBER", "OSINT", "Oct 2025",
     "Can find anyone's old Facebook in under 5 minutes.",
     "Still owes Karim 50 EGP from the pizza order.", 0),
    ("alice", "alice123", "Alice", "MEMBER", "Web Security", "Sep 2025",
     "First-year, into CTFs and bad puns.",
     "Meeting notes draft #3 due Thursday.", 0),
    (None, None, "Laila", "MEMBER", "Reverse Engineering", "Nov 2025",
     "Reads disassembly for fun, apparently.",
     "Still debugging the same segfault from Tuesday.", 0),
    (None, None, "Karim", "MEMBER", "Networking", "Sep 2025",
     "Brings snacks to every session. A true hero.",
     "Hid the good snacks from Youssef on purpose.", 0),
    ("mina", "mina123", "Mina", "MEMBER", "OSINT", "Oct 2025",
     "Here for the free pizza, staying for the CTFs.",
     "Don't forget to water the office plant.", 0),
    ("admin", "cl4ssif1ed", "Staff Admin", "SYSTEM OPERATOR", "Club Administration", "Feb 2024",
     "Club staff account. Do not share credentials.",
     "FLAG{1D0R_1S_N3V3R_TRUST_TH3_US3R}", 1),
    (None, None, "Noor", "MEMBER", "Web Security", "Oct 2025",
     "Broke the lab Wi-Fi once. Once.",
     "Actually broke it twice. Nobody noticed the second time.", 0),
    ("sara", "sara123", "Sara", "MEMBER", "Reverse Engineering", "Nov 2025",
     "Prefers Ghidra over everything else. Will fight you on this.",
     "Taking Thursday off to study for the networking midterm.", 0),
    (None, None, "Hassan", "MEMBER", "Web Security", "Sep 2025",
     "Joined for the free pizza. Stayed for more pizza.",
     "Still hasn't finished the onboarding checklist.", 0),
]


def init_db():
    """(Re)create the DB fresh every time the app starts, so the demo
    always begins in a known state."""
    con = sqlite3.connect(DB_PATH)
    con.execute("DROP TABLE IF EXISTS users")
    con.execute("""
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            password TEXT,
            display_name TEXT,
            role TEXT,
            team TEXT,
            joined TEXT,
            bio TEXT,
            secret TEXT,
            is_flag_account INTEGER
        )
    """)
    con.executemany(
        "INSERT INTO users (username, password, display_name, role, team, joined, bio, secret, is_flag_account) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        SEED_USERS,
    )
    con.commit()
    con.close()


def get_db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con


# ---------------------------------------------------------------------------
# Shared styles
# ---------------------------------------------------------------------------

BASE_STYLE = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Access Terminal</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #12151b;
    --bg-grid: #171b23;
    --panel: #1a1f29;
    --panel-2: #1f2530;
    --border: #2a3140;
    --text: #e7eaf0;
    --text-dim: #8a93a6;
    --accent: #52a9e8;
    --accent-dim: #2e5a80;
    --warn: #e8a33d;
    --danger: #e35b55;
    --ok: #4fb286;
    --radius: 14px;
  }

  * { box-sizing: border-box; }

  body {
    margin: 0;
    min-height: 100vh;
    background:
      radial-gradient(circle at 15% 10%, #1b2230 0%, transparent 45%),
      radial-gradient(circle at 85% 90%, #19202c 0%, transparent 45%),
      var(--bg);
    color: var(--text);
    font-family: 'Space Grotesk', sans-serif;
    display: flex;
    align-items: flex-start;
    justify-content: center;
    padding: 48px 16px;
  }

  .mono { font-family: 'JetBrains Mono', monospace; }

  a { color: var(--accent); }

  .topline {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    letter-spacing: 0.04em;
    color: var(--text-dim);
    margin-bottom: 18px;
    justify-content: center;
  }
  .dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--ok);
    box-shadow: 0 0 8px var(--ok);
  }

  .wrap { width: 100%; max-width: 380px; }

  /* ---------- Login / terminal gate ---------- */
  .gate {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    overflow: hidden;
  }
  .gate-head {
    padding: 20px 24px 16px;
    border-bottom: 1px solid var(--border);
  }
  .gate-head h1 {
    margin: 0 0 4px;
    font-size: 19px;
    font-weight: 600;
    letter-spacing: -0.01em;
  }
  .gate-head p {
    margin: 0;
    color: var(--text-dim);
    font-size: 13px;
  }
  .gate-body { padding: 24px; }

  .field { margin-bottom: 16px; }
  .field label {
    display: block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--text-dim);
    margin-bottom: 6px;
  }
  .field label::before { content: "> "; color: var(--accent); }
  .field input {
    width: 100%;
    padding: 11px 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: 14px;
  }
  .field input:focus {
    outline: none;
    border-color: var(--accent);
    box-shadow: 0 0 0 3px rgba(82,169,232,0.15);
  }

  button.submit {
    width: 100%;
    padding: 12px;
    margin-top: 6px;
    border-radius: 8px;
    border: none;
    background: var(--accent);
    color: #0c1118;
    font-family: 'Space Grotesk', sans-serif;
    font-weight: 600;
    font-size: 14px;
    cursor: pointer;
  }
  button.submit:hover { background: #69b7eb; }

  .error {
    background: rgba(227,91,85,0.12);
    border: 1px solid rgba(227,91,85,0.35);
    color: #f2a9a5;
    font-size: 13px;
    padding: 9px 12px;
    border-radius: 8px;
    margin-bottom: 16px;
    font-family: 'JetBrains Mono', monospace;
    word-break: break-word;
  }

  .hint {
    margin-top: 18px;
    padding-top: 16px;
    border-top: 1px dashed var(--border);
    font-size: 12px;
    color: var(--text-dim);
    line-height: 1.6;
  }
  .hint code {
    background: var(--bg);
    padding: 1px 6px;
    border-radius: 4px;
    font-family: 'JetBrains Mono', monospace;
    color: var(--accent);
  }

  /* ---------- Badge ---------- */
  .badge-url {
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    color: var(--accent);
    background: var(--panel-2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 8px 12px;
    margin-bottom: 18px;
    text-align: center;
    word-break: break-all;
  }

  .badge {
    position: relative;
    background: linear-gradient(180deg, var(--panel-2), var(--panel));
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 28px 24px 20px;
    overflow: hidden;
  }
  .badge::before {
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 5px;
    background: linear-gradient(90deg, var(--accent), var(--ok));
  }
  .punch-row {
    display: flex;
    justify-content: center;
    gap: 7px;
    margin-bottom: 18px;
  }
  .punch {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--bg);
    border: 1px solid var(--border);
  }

  .badge-top {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 18px;
  }
  .avatar {
    width: 56px; height: 56px;
    border-radius: 50%;
    background: linear-gradient(135deg, var(--accent), var(--accent-dim));
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 700;
    font-size: 20px;
    color: #0c1118;
    flex-shrink: 0;
  }
  .badge-name { font-size: 18px; font-weight: 600; line-height: 1.2; }
  .badge-role {
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    letter-spacing: 0.04em;
    color: var(--accent);
    margin-top: 3px;
  }

  .info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 16px;
  }
  .info-cell {
    background: var(--bg);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px 12px;
  }
  .info-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: var(--text-dim);
    margin-bottom: 4px;
  }
  .info-value {
    font-size: 14px;
    font-weight: 600;
    color: var(--text);
  }

  .bio {
    font-size: 13px;
    color: var(--text-dim);
    margin-bottom: 18px;
    line-height: 1.5;
  }

  .file-box {
    border-radius: 10px;
    padding: 14px;
    position: relative;
    border: 1px solid var(--border);
    background: var(--panel-2);
  }
  .file-box.classified {
    border-color: rgba(227,91,85,0.5);
    background: rgba(227,91,85,0.06);
  }
  .file-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 10px;
    color: var(--text-dim);
    margin-bottom: 8px;
  }
  .file-box.classified .file-label { color: var(--danger); }
  .stamp {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.08em;
    color: var(--danger);
    border: 2px solid var(--danger);
    border-radius: 4px;
    padding: 2px 8px;
    transform: rotate(-3deg);
    margin-bottom: 10px;
  }
  .file-content {
    font-size: 13px;
    line-height: 1.6;
    word-break: break-word;
  }
  .file-box.classified .file-content {
    font-family: 'JetBrains Mono', monospace;
    color: #f2b8b4;
  }

  .barcode {
    display: flex;
    gap: 2px;
    align-items: flex-end;
    height: 28px;
    margin: 20px 0 8px;
  }

  .badge-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-top: 6px;
    font-family: 'JetBrains Mono', monospace;
    font-size: 11px;
    color: var(--text-dim);
  }
  .badge-footer a { color: var(--text-dim); text-decoration: none; }
  .badge-footer a:hover { color: var(--accent); }
</style>
</head>
<body>
<div class="wrap">
<div class="topline"><span class="dot"></span>SYSTEM ONLINE</div>
__CONTENT__
</div>
</body>
</html>
"""

LOGIN_CONTENT = """
<div class="gate">
  <div class="gate-head">
    <h1>Club Access Terminal</h1>
    <p>Authenticate with your issued access code.</p>
  </div>
  <div class="gate-body">
    {% if error %}<div class="error">{{ error }}</div>{% endif %}
    <form method="POST" action="/login">
      <div class="field">
        <label>username</label>
        <input type="text" name="username" autofocus autocomplete="off">
      </div>
      <div class="field">
        <label>password</label>
        <input type="password" name="password">
      </div>
      <button class="submit" type="submit">Authenticate</button>
    </form>
    <div class="hint">
      No access code issued? You weren't given one on purpose.
    </div>
  </div>
</div>
"""

PROFILE_CONTENT = """
<div class="badge-url">GET /profile?user_id={{ user.id }}</div>
<div class="badge">
  <div class="punch-row">
    <div class="punch"></div><div class="punch"></div><div class="punch"></div>
  </div>
  <div class="badge-top">
    <div class="avatar">{{ user.initial }}</div>
    <div>
      <div class="badge-name">{{ user.display_name }}</div>
      <div class="badge-role">{{ user.role }}</div>
    </div>
  </div>

  <div class="info-grid">
    <div class="info-cell">
      <div class="info-label">TEAM</div>
      <div class="info-value">{{ user.team }}</div>
    </div>
    <div class="info-cell">
      <div class="info-label">JOINED</div>
      <div class="info-value">{{ user.joined }}</div>
    </div>
  </div>

  <div class="bio">{{ user.bio }}</div>

  <div class="file-box {{ 'classified' if user.is_flag_account else '' }}">
    <div class="file-label">{{ 'RESTRICTED FILE' if user.is_flag_account else 'PERSONAL NOTE' }}</div>
    {% if user.is_flag_account %}<div class="stamp">CLASSIFIED</div><br>{% endif %}
    <div class="file-content">{{ user.secret }}</div>
  </div>

  <div class="barcode">
    {% for h in bars %}<div style="width:3px;height:{{ h }}px;background:var(--text-dim);opacity:0.5;"></div>{% endfor %}
  </div>

  <div class="badge-footer">
    <span>logged in as {{ me.display_name }}</span>
    <a href="/logout">log out</a>
  </div>
</div>
"""


def render(content_template, **ctx):
    page = BASE_STYLE.replace("__CONTENT__", content_template)
    return render_template_string(page, **ctx)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(f"/profile?user_id={session['user_id']}")
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render(LOGIN_CONTENT, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # --- VULNERABILITY #1: SQL INJECTION ---
    # Raw string formatting straight into the query. No parameterization,
    # no escaping. A payload like  ' OR '1'='1' --  in the username field
    # turns this into "WHERE username = '' OR '1'='1' --' AND password=..."
    # which SQLite happily evaluates as always-true, and the trailing
    # "-- " comments out the rest of the line including the password check.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"

    con = get_db()
    try:
        row = con.execute(query).fetchone()
    except sqlite3.Error as e:
        # Deliberately not sanitized: a broken payload shows the raw DB
        # error, which is itself a common real-world way people first
        # notice an injection point.
        con.close()
        return render(LOGIN_CONTENT, error=f"Database error: {e}")
    con.close()

    if row is None:
        return render(LOGIN_CONTENT, error="Access denied. Check your credentials.")

    session["user_id"] = row["id"]
    return redirect(f"/profile?user_id={row['id']}")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")

    con = get_db()
    me_row = con.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()

    # --- VULNERABILITY #2: IDOR ---
    # We trust whatever user_id is in the URL instead of forcing it to
    # match session["user_id"]. This is a textbook IDOR.
    requested_id = request.args.get("user_id", type=int)
    shown_row = None
    if requested_id is not None:
        shown_row = con.execute("SELECT * FROM users WHERE id = ?", (requested_id,)).fetchone()
    if shown_row is None:
        shown_row = me_row
        requested_id = me_row["id"]
    con.close()

    shown_user = dict(shown_row)
    shown_user["initial"] = shown_user["display_name"][0].upper()

    # deterministic "barcode" pattern so it doesn't jump around on reload
    bars = [10 + ((requested_id * 37 + i * 13) % 18) for i in range(28)]

    return render(PROFILE_CONTENT, user=shown_user, me=dict(me_row), bars=bars)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False)
