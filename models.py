from database import Base
from sqlalchemy import DateTime, String, ForeignKey
from datetime import datetime, timedelta
from sqlalchemy.orm import Mapped, mapped_column


class Role(Base):
    __tablename__ = 'roles'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    role: Mapped[str] = mapped_column(String(50), unique=True)
    
    
class Permission(Base):
    __tablename__ = 'permissions'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    resource: Mapped[str] = mapped_column(String(50))
    action: Mapped[str] = mapped_column(String(50))
    
    
class RolePermission(Base):
    __tablename__ = 'role_permissions'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    role_id: Mapped[int] = mapped_column(ForeignKey('roles.id'))
    permission_id: Mapped[int] = mapped_column(ForeignKey('permissions.id'))


class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), unique=True)
    role_id: Mapped[int] = mapped_column(ForeignKey('roles.id'), default=2)
    created_at = mapped_column(DateTime, default=datetime.now())
    is_active: Mapped[bool] = mapped_column(default=True)
    

class RefreshTokens(Base):
    __tablename__ = 'refresh_tokens'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    hashed_token: Mapped[str] = mapped_column(String(255))
    created_at = mapped_column(DateTime, default=datetime.now(), onupdate=datetime.now())
    expires_at  = mapped_column(DateTime, default=datetime.now() + timedelta(days=30),
                                onupdate=datetime.now() + timedelta(days=30))
    is_revoked: Mapped[bool] = mapped_column(default=False)
    