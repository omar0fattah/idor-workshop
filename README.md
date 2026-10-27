# IDOR Workshop — Run Instructions

## What this is
A tiny, self-contained vulnerable web app for a 1-hour beginner workshop on
IDOR (Insecure Direct Object Reference). No TryHackMe account, no VPN, no
setup for attendees — just a browser.

The bug: after logging in, the profile page is `/profile?user_id=<id>`.
The server never checks that the `user_id` in the URL actually belongs to
the logged-in user. So changing the number shows someone else's data.
User `id=1` ("admin") holds the flag.

## 1. Run it locally (just to test, or if only you're demoing)
```
pip install flask
python3 app.py
```
Then open http://127.0.0.1:5050 in your browser.

## 2. Run it so your club members can reach it (same WiFi)
Flask is already set to listen on `0.0.0.0`, so anyone on the same WiFi can
reach it via your laptop's local IP.

1. Find your local IP:
   - Mac/Linux: `ifconfig | grep inet` or `ip a`
   - Windows: `ipconfig` → look for "IPv4 Address" (usually starts with 192.168.x.x or 10.x.x.x)
2. Start the app: `python3 app.py`
3. Tell attendees to go to `http://<your-ip>:5050` — e.g. `http://192.168.1.42:5050`

**Important:** make sure everyone is on the same WiFi network (campus WiFi
sometimes isolates devices from each other — "client isolation" — which
would block this. Test with one other person's phone/laptop before the
session if you can.)

If WiFi isolation is a problem on the day, fallback options:
- Hotspot from your own phone and have people join that instead
- Deploy it for free on Render.com or PythonAnywhere ahead of time (I can help
  set that up if you want a backup that doesn't depend on venue WiFi)

## 3. Demo accounts to hand out
| Username | Password  |
|----------|-----------|
| alice    | alice123  |
| bob      | bob123    |
| mina     | mina123   |

Don't give out the `admin` account — that's the one they need to IDOR their
way into.

## 4. The flag
Logging in as any of alice/bob/mina and changing the URL to
`?user_id=1` reveals:
```
FLAG{1D0R_1S_N3V3R_TRUST_TH3_US3R}
```

## 5. Suggested flow during the session
1. Have everyone log in with their assigned account (split alice/bob/mina
   across the room, doesn't matter who gets which)
2. Have them look at the URL bar after logging in — point out the
   `?user_id=X` parameter
3. Ask: "What happens if you just... change that number?"
4. Let them try it themselves — first one to find the flag shouts it out
5. Then explain *why* it works (server trusts client input instead of
   checking the session) and how real sites prevent it (always verify the
   requested resource belongs to the authenticated user, server-side)

## 6. If you want it to feel less "toy"
You can rename it from "Club Member Portal" to your actual club's name by
editing the `<h1>` text in `app.py` (search for "Club Member Portal").
