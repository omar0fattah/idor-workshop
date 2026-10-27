"""
IDOR Workshop Demo App
-----------------------
A deliberately vulnerable mini Flask app for teaching Insecure Direct
Object Reference (IDOR) to beginners.

How the vuln works:
  - After logging in, a user lands on /profile?user_id=<their own id>
  - The server NEVER checks that the logged-in user actually owns that id
  - So changing the number in the URL shows you someone else's profile
  - One "staff" account (id 1) holds the flag

Run it with:  python3 app.py
Then visit:   http://127.0.0.1:5000  (or http://<your-local-ip>:5000 for others on the same WiFi)
"""

from flask import Flask, request, redirect, session, render_template_string

app = Flask(__name__)
app.secret_key = "workshop-demo-not-for-production"  # fine for a local demo only

# ---------------------------------------------------------------------------
# Fake user "database" - just a dict, no real DB needed for a 1-hour workshop
# ---------------------------------------------------------------------------
USERS = {
    1: {
        "username": "admin",
        "password": "cl4ssif1ed",
        "display_name": "Staff Admin",
        "bio": "Club staff account. Do not share credentials.",
        "secret": "FLAG{1D0R_1S_N3V3R_TRUST_TH3_US3R}",
        "is_flag_account": True,
    },
    2: {
        "username": "alice",
        "password": "alice123",
        "display_name": "Alice",
        "bio": "First-year, into CTFs and bad puns.",
        "secret": "Alice's private note: meeting notes draft #3 due Thursday.",
        "is_flag_account": False,
    },
    3: {
        "username": "bob",
        "password": "bob123",
        "display_name": "Bob",
        "bio": "Still figuring out regex. Send help.",
        "secret": "Bob's private note: forgot where I parked (again).",
        "is_flag_account": False,
    },
    4: {
        "username": "mina",
        "password": "mina123",
        "display_name": "Mina",
        "bio": "Here for the free pizza, staying for the CTFs.",
        "secret": "Mina's private note: don't forget to water the office plant.",
        "is_flag_account": False,
    },
}

# username -> id lookup for login
USERNAME_TO_ID = {u["username"]: uid for uid, u in USERS.items()}


# ---------------------------------------------------------------------------
# Templates (kept inline so this is a single-file app - easy to run anywhere)
# ---------------------------------------------------------------------------

BASE_STYLE = """
<style>
  body { font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:#0f1117; color:#e6e6e6; margin:0; padding:40px 20px; }
  .card { max-width:480px; margin:0 auto; background:#1a1d29; border:1px solid #2a2e3e; border-radius:12px; padding:32px; }
  h1 { font-size:22px; margin-top:0; }
  input { width:100%; padding:10px; margin:8px 0; border-radius:6px; border:1px solid #333; background:#0f1117; color:#fff; box-sizing:border-box; }
  button { width:100%; padding:10px; margin-top:10px; border-radius:6px; border:none; background:#5b8def; color:#fff; font-weight:600; cursor:pointer; }
  button:hover { background:#4877d1; }
  .error { color:#ff6b6b; font-size:14px; }
  .hint { color:#888; font-size:13px; margin-top:16px; }
  a { color:#5b8def; }
  .field { margin-bottom:14px; }
  .field label { font-size:13px; color:#999; }
  .bio { color:#aaa; font-style:italic; }
  .secret-box { margin-top:20px; padding:14px; background:#11141c; border:1px dashed #333; border-radius:8px; word-break:break-word; }
  .url-bar { background:#0b0d13; color:#8ab4f8; padding:8px 12px; border-radius:6px; font-family:monospace; font-size:13px; margin-bottom:20px; }
</style>
"""

LOGIN_PAGE = BASE_STYLE + """
<div class="card">
  <h1>🔐 Club Member Portal</h1>
  {% if error %}<p class="error">{{ error }}</p>{% endif %}
  <form method="POST" action="/login">
    <div class="field">
      <label>Username</label>
      <input type="text" name="username" autofocus>
    </div>
    <div class="field">
      <label>Password</label>
      <input type="password" name="password">
    </div>
    <button type="submit">Log in</button>
  </form>
  <p class="hint">Demo accounts: alice / bob / mina — password is &lt;username&gt;123</p>
</div>
"""

PROFILE_PAGE = BASE_STYLE + """
<div class="card">
  <div class="url-bar">GET /profile?user_id={{ user.id }}</div>
  <h1>👤 {{ user.display_name }}'s Profile</h1>
  <p class="bio">{{ user.bio }}</p>
  <div class="secret-box">
    <strong>Private note:</strong><br>
    {{ user.secret }}
  </div>
  <p class="hint">
    You are logged in as <b>{{ me.display_name }}</b>.
    <a href="/logout">Log out</a>
  </p>
</div>
"""


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
        return render_template_string(LOGIN_PAGE, error=None)

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    uid = USERNAME_TO_ID.get(username)
    if uid is None or USERS[uid]["password"] != password:
        return render_template_string(LOGIN_PAGE, error="Invalid username or password.")

    session["user_id"] = uid
    return redirect(f"/profile?user_id={uid}")


@app.route("/profile")
def profile():
    if "user_id" not in session:
        return redirect("/login")

    me = USERS[session["user_id"]]

    # --- THE VULNERABILITY ---
    # We trust whatever user_id is in the URL instead of forcing it to
    # match session["user_id"]. This is a textbook IDOR.
    requested_id = request.args.get("user_id", type=int)
    if requested_id is None or requested_id not in USERS:
        requested_id = session["user_id"]

    shown_user = dict(USERS[requested_id])
    shown_user["id"] = requested_id

    return render_template_string(PROFILE_PAGE, user=shown_user, me=me)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    # host="0.0.0.0" so people on the same WiFi can reach it via your local IP
    app.run(host="0.0.0.0", port=5050, debug=False)
