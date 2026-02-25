#!/usr/bin/env python3
"""
Bootstrap or update a local Click2Fix user inside the backend container.

Usage:
  python tools/bootstrap_admin.py --username admin --password 'StrongPass!' --role admin
  python tools/bootstrap_admin.py --username admin --password 'NewPass!' --role admin --force-reset
"""

from __future__ import annotations

import argparse
from typing import Optional

from passlib.context import CryptContext
from sqlalchemy import text

from db.database import connect


PWD = CryptContext(schemes=["bcrypt"])


def _ensure_default_org(db) -> int:
    org_id: Optional[int] = db.execute(text("SELECT id FROM orgs ORDER BY id LIMIT 1")).scalar()
    if org_id:
        return int(org_id)
    db.execute(text("INSERT INTO orgs (name) VALUES (:name)"), {"name": "Default Org"})
    org_id = db.execute(text("SELECT id FROM orgs ORDER BY id LIMIT 1")).scalar()
    return int(org_id or 1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Bootstrap Click2Fix user")
    parser.add_argument("--username", required=True, help="Username to create/update")
    parser.add_argument("--password", required=True, help="Password value")
    parser.add_argument("--role", default="admin", choices=["analyst", "admin", "superadmin"], help="Role")
    parser.add_argument("--force-reset", action="store_true", help="Reset password/role if user already exists")
    args = parser.parse_args()

    username = str(args.username or "").strip()
    password = str(args.password or "")
    role = str(args.role or "admin").strip()
    if len(username) < 3:
        raise SystemExit("username must be at least 3 characters")
    if len(password) < 8:
        raise SystemExit("password must be at least 8 characters")

    db = connect()
    try:
        org_id = _ensure_default_org(db)
        row = db.execute(
            text("SELECT id FROM users WHERE username=:username"),
            {"username": username},
        ).fetchone()
        if row:
            if args.force_reset:
                db.execute(
                    text(
                        """
                        UPDATE users
                        SET password=:password, role=:role, org_id=:org_id
                        WHERE username=:username
                        """
                    ),
                    {
                        "username": username,
                        "password": PWD.hash(password),
                        "role": role,
                        "org_id": org_id,
                    },
                )
                db.commit()
                print(f"updated user={username} role={role}")
                return 0
            print(f"user already exists: {username} (use --force-reset to update)")
            return 0

        db.execute(
            text(
                """
                INSERT INTO users (username, password, role, org_id)
                VALUES (:username, :password, :role, :org_id)
                """
            ),
            {
                "username": username,
                "password": PWD.hash(password),
                "role": role,
                "org_id": org_id,
            },
        )
        db.commit()
        print(f"created user={username} role={role}")
        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
