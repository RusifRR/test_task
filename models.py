from database import Base
from sqlalchemy import DateTime, String, ForeignKey
from datetime import datetime, timedelta
from sqlalchemy.orm import Mapped, mapped_column


class User(Base):
    __tablename__ = 'users'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(30), nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), unique=True)
    created_at = mapped_column(DateTime, default=datetime.now())
    is_active: Mapped[bool] = mapped_column(default=True)
    

class RefreshTokens(Base):
    __tablename__ = 'refresh_tokens'
    
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"), unique=True)
    hashed_token: Mapped[str] = mapped_column(unique=True)
    created_at = mapped_column(DateTime, default=datetime.now(), onupdate=datetime.now())
    expires_at  = mapped_column(DateTime, default=datetime.now() + timedelta(days=30),
                                onupdate=datetime.now() + timedelta(days=30))
    is_revoked: Mapped[bool] = mapped_column(default=False)