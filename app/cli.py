"""Command-line admin tasks.

  pager-admin init                      create the database
  pager-admin add-user NAME [--role admin|viewer]
  pager-admin reset-password NAME
  pager-admin list-users
"""

import argparse
import getpass
import sys
import time

from . import auth, db, settings


def _ask_password() -> str:
    while True:
        pw = getpass.getpass("Password: ")
        problem = auth.password_problem(pw)
        if problem:
            print(problem)
            continue
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords don't match.")
            continue
        return pw


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pager-admin", description="Pager Monitor admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("init", help="create the database")
    a = sub.add_parser("add-user", help="add a user")
    a.add_argument("username")
    a.add_argument("--role", choices=["admin", "viewer"], default="admin")
    r = sub.add_parser("reset-password", help="reset a user's password and re-enable them")
    r.add_argument("username")
    sub.add_parser("list-users", help="list users")
    args = ap.parse_args(argv)

    db.init_db()
    conn = db.connect()
    try:
        if args.cmd == "init":
            print(f"Database ready at {settings.DB_PATH}")
        elif args.cmd == "add-user":
            if not auth.USERNAME_RE.match(args.username):
                print("Usernames are 2–32 letters, digits, dots, dashes or underscores.")
                return 1
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (args.username,)).fetchone():
                print(f"User {args.username} already exists.")
                return 1
            pw = _ask_password()
            conn.execute(
                "INSERT INTO users (username, pw_hash, role, created_at) VALUES (?, ?, ?, ?)",
                (args.username, auth.hash_password(pw), args.role, time.time()))
            db.audit(conn, "cli", "user_create", f"{args.username} ({args.role})")
            print(f"Created {args.role} {args.username}.")
        elif args.cmd == "reset-password":
            row = conn.execute("SELECT id FROM users WHERE username = ?", (args.username,)).fetchone()
            if not row:
                print(f"No user {args.username}.")
                return 1
            pw = _ask_password()
            conn.execute("UPDATE users SET pw_hash = ?, active = 1 WHERE id = ?",
                         (auth.hash_password(pw), row["id"]))
            db.audit(conn, "cli", "user_password_reset", args.username)
            print(f"Password reset for {args.username}.")
        elif args.cmd == "list-users":
            for u in conn.execute("SELECT * FROM users ORDER BY username"):
                state = "active" if u["active"] else "disabled"
                print(f"{u['username']:<20} {u['role']:<7} {state:<9} {u['capcode_filter'] or 'all'}")
    finally:
        conn.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
