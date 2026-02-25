from fastapi import APIRouter, Depends
from core.security import require_role
from db.database import connect, rows_to_list
from sqlalchemy import text

router = APIRouter(prefix="/orgs")

@router.get("")
def list_orgs(user=Depends(require_role("superadmin"))):

    db = connect()
    try:
        rows = db.execute(
            text("SELECT id, name, created_at FROM orgs ORDER BY created_at DESC")
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()

@router.post("")
def create_org(name: str, user=Depends(require_role("superadmin"))):

    db = connect()
    try:
        result = db.execute(
            text("INSERT INTO orgs (name) VALUES (:name) RETURNING id"),
            {"name": name},
        )
        org_id = result.scalar()
        db.commit()
        return {"id": org_id}
    finally:
        db.close()


@router.post("/{org_id}/users")
def create_user(
    org_id: int,
    username: str,
    password: str,
    role: str,
    user=Depends(require_role("superadmin"))
):

    from passlib.context import CryptContext
    pwd = CryptContext(schemes=["bcrypt"])

    db = connect()
    try:
        result = db.execute(
            text(
                """
                INSERT INTO users (username,password,role,org_id)
                VALUES (:username, :password, :role, :org_id)
                RETURNING id
                """
            ),
            {
                "username": username,
                "password": pwd.hash(password),
                "role": role,
                "org_id": org_id,
            },
        )

        db.commit()
        return {"id": result.scalar()}
    finally:
        db.close()


@router.get("/{org_id}/users")
def list_users(org_id: int, user=Depends(require_role("superadmin"))):

    db = connect()
    try:
        rows = db.execute(
            text("SELECT id, username, role, org_id, created_at FROM users WHERE org_id=:org_id"),
            {"org_id": org_id},
        ).fetchall()
        return rows_to_list(rows)
    finally:
        db.close()
