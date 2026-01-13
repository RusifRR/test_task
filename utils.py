import jwt
from passlib.hash import pbkdf2_sha256
from datetime import datetime, timedelta
from sqlalchemy import select
from models import RefreshTokens, User, Role, Permission, RolePermission
from database import SessionLocal
from models import RefreshTokens



SECRET_KEY = 'c1243959027271e192434c9aae4075e5f44334b5fbaaaa41dc2599cfa0abd734'
REFRESH_SECRET_KEY = '89410a7ddf4e7c3b4d61fe12def0ab4e1fc0768234f88de040dc4d2e46dd9496'
ALGORITHM = 'HS256'
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 30


def initial_data():
    with SessionLocal() as s: 
        if s.execute(select(Role)).all():
            return
        
        admin_role = Role(role='admin')
        user_role = Role(role='user')
        s.add_all([admin_role, user_role])
        s.commit()
        
        p1 = Permission(resource='documents', action='read')
        p2 = Permission(resource='documents', action='write')
        p3 = Permission(resource='orders', action='read')
        p4 = Permission(resource='admin', action='manage')
        s.add_all([p1, p2, p3, p4])
        s.commit()
        
        s.add_all([
            # права админа
            RolePermission(role_id=admin_role.id, permission_id=p1.id),
            RolePermission(role_id=admin_role.id, permission_id=p2.id),
            RolePermission(role_id=admin_role.id, permission_id=p3.id),
            RolePermission(role_id=admin_role.id, permission_id=p4.id),
            
            # права пользователя
            RolePermission(role_id=user_role.id, permission_id=p1.id),
            RolePermission(role_id=user_role.id, permission_id=p3.id)
        ])
        s.commit()



def verify_password(password, hashed_password):
    return pbkdf2_sha256.verify(password, hashed_password)

def get_password_hash(password):
    return pbkdf2_sha256.hash(password)


def create_access_token(data: dict):
    expire = datetime.now() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    data.update({'exp': expire})
    encode_jwt = jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt


def create_refresh_token(data: dict):
    expire = datetime.now() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    data.update({'exp': expire})
    encode_jwt = jwt.encode(data, REFRESH_SECRET_KEY, algorithm=ALGORITHM)
    return encode_jwt


def save_refresh_token(token: str, user_id: int):
    hashed_token = pbkdf2_sha256.hash(token)
    with SessionLocal() as s:
        refresh_token = s.execute(select(RefreshTokens).where(RefreshTokens.user_id == user_id)).scalars().first()
        if not refresh_token:
            s.add(RefreshTokens(user_id=user_id, hashed_token=hashed_token))
            s.commit()
        else:
            refresh_token.hashed_token = hashed_token
            refresh_token.is_revoked = False
            s.commit()
        
        
def validate_refresh_token(token: str):
    user_id = jwt.decode(token, REFRESH_SECRET_KEY, algorithms=ALGORITHM)['sub']
    with SessionLocal() as s:
        refresh_token = s.execute(select(RefreshTokens).where(RefreshTokens.user_id == user_id)).scalars().first()
        if refresh_token.is_revoked or datetime.now() > refresh_token.expires_at or not pbkdf2_sha256.verify(token, refresh_token.hashed_token):
            return None
    return user_id


def revoke_refresh_token(token: str):
    with SessionLocal() as s:
        active_tokens = s.execute(select(RefreshTokens).where(RefreshTokens.is_revoked == False)).scalars().all()
        for t in active_tokens:
            if pbkdf2_sha256.verify(token, t.hashed_token):
                t.is_revoked = True
                s.commit()
                break
            
            
def validate_token(token: str):
    user_id = jwt.decode(token, SECRET_KEY, algorithms=ALGORITHM)['sub']
    return user_id
    