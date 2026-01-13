from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session
from models import User, Role, Permission, RolePermission


def check_permission(user_id: int, resource: int, action: str, db: Session):
    user = db.execute(select(User).where(User.id == user_id)).scalars().first()
        
    role = db.execute(select(Role).where(Role.id == user.role_id)).scalars().first()
        
    permissions = db.execute(select(Permission).join(RolePermission, Permission.id == RolePermission.permission_id).where(RolePermission.role_id == role.id)).scalars().all()
        
    for p in permissions:
        if p.resource == resource and p.action == action:
            return True
            
    raise HTTPException(status_code=403, detail='Пользователь не имеет таких прав')


