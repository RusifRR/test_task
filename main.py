from fastapi import FastAPI, Depends, HTTPException, Response, Cookie
from fastapi.security import OAuth2PasswordBearer
from contextlib import asynccontextmanager
from typing import Optional, Annotated
from sqlalchemy import  select
from sqlalchemy.orm import Session
from database import get_session, create_tables
from models import User, Role, Permission, RolePermission
from pydantic import BaseModel
from email_validator import validate_email, EmailNotValidError
from datetime import datetime
from utils import initial_data, get_password_hash, verify_password
from utils import create_access_token, create_refresh_token,  save_refresh_token
from utils import validate_refresh_token, revoke_refresh_token, validate_token
from permissions import check_permission


@asynccontextmanager
async def lifespan(app: FastAPI):
    create_tables()
    initial_data()
    yield


app = FastAPI(lifespan=lifespan)


class UserRegister(BaseModel):
    username: str
    email: str
    password: str
    password_replay: str
    
    
class UserLog(BaseModel):
    email: str
    password: str
    

class UserUpdate(BaseModel):
    username: str = None
    email: str = None
    password: str = None
    
    
class Token(BaseModel):
    token: str


@app.post('/register')
def regist(user_reg: UserRegister, db: Annotated[Session, Depends(get_session)]):
    try:
        emailinfo = validate_email(user_reg.email)
        s = db.execute(select(User).where(User.email == user_reg.email)).scalars().first()
        if s and s.is_active:
            raise HTTPException(status_code=409, detail='Пользователь с таким email уже зарегистрирован')
            
        if user_reg.password != user_reg.password_replay:
            raise HTTPException(status_code=422, detail='Пароли не совпадают')
        
        if len(user_reg.password) < 8:
            raise HTTPException(status_code=422, detail='Пароль должен быть не менее 8 символов')
        
        if not any(sym.isdigit() for sym in user_reg.password) or not any(sym.isalpha() for sym in user_reg.password):
            raise HTTPException(status_code=422, detail='Пароль должен содержать хотя бы 1 букву и цифру')
        
        if s and not s.is_active:
            s.username = user_reg.username
            s.hashed_password = get_password_hash(user_reg.password)
            s.is_active = True
            s.created_at = datetime.now()
            
        else:
            user = User(username=user_reg.username, email=user_reg.email, hashed_password=get_password_hash(user_reg.password))
            db.add(user)
            
        db.commit()
            
        return {'message': 'Вы зарегистрировались'}
    except EmailNotValidError:
        return HTTPException(status_code=422, detail='Неверный формат email')

@app.post('/login')
def log(user_log: UserLog, db: Annotated[Session, Depends(get_session)], response: Response):
    s = db.execute(select(User).where(User.email == user_log.email)).scalars().first()
    if not s:
        raise HTTPException(status_code=401, detail='Пользователь не зарегистрирован')
    
    if not s.is_active:
        raise HTTPException(status_code=401, detail='Пользователь удалил аккаунт')
    
    if not verify_password(user_log.password, s.hashed_password):
        raise HTTPException(status_code=401, detail='Неверный пароль')
    
    
    access_token = create_access_token(data={'sub': f'{s.id}'})
    refresh_token = create_refresh_token(data={'sub': f'{s.id}'})
    
    save_refresh_token(refresh_token, s.id)
    
    response.set_cookie('access_token', access_token)
    
    return {'refresh_token': refresh_token,
            'user': {
                'id': s.id,
                'username': s.username
                }
            }
    
    
@app.post('/auth/refresh')
def refresh_access_token(refresh_token: Token, response: Response):
    user_id = validate_refresh_token(token=refresh_token.token)
    
    if not user_id:
        raise HTTPException(status_code=401, detail='Токен доступа истек')
    
    access_token = create_access_token(data={'sub': f'{user_id}'})
    
    response.set_cookie('access_token', access_token)
    return {'message': 'Токен обновился'}


@app.patch('/profile/update')
def profile_update(user_update: UserUpdate, db: Annotated[Session, Depends(get_session)], access_token: str = Cookie(None, alias='access_token')):
    if not access_token:
        raise HTTPException(status_code=401, detail='Нет токена')
    
    user_id = validate_token(token=access_token)
    user = db.execute(select(User).where(User.id == user_id)).scalars().first()
    
    if user_update.username:
        if user_update.username != user.username:
            user.username = user_update.username
            db.commit()
            
    if user_update.email:
        if user_update.email != user.email:
            used_email = db.execute(select(User).where(User.email == user_update.email)).scalars().first()
            if used_email:
                raise HTTPException(status_code=401, detail='Email уже зарегистрирован')
            try:
                email_info = validate_email(user_update.email)
                user.email = user_update.email
                db.commit()
            except EmailNotValidError:
                return HTTPException(status_code=422, detail='Неверный формат email')
            
    if user_update.password:
        if not verify_password(password=user_update.password, hashed_password=user.hashed_password):
            if len(user_update.password) < 8:
                raise HTTPException(status_code=422, detail='Пароль должен быть не менее 8 символов')
        
            if not any(sym.isdigit() for sym in user_update.password) or not any(sym.isalpha() for sym in user_update.password):
                raise HTTPException(status_code=422, detail='Пароль должен содержать хотя бы 1 букву и цифру')
            
            user.hashed_password = get_password_hash(user_update.password)
            db.commit()
        
    return {'message': 'Профиль успешно обновлен'}


@app.delete('/profile/delete')
def delete_profile(refresh_token: Token, response: Response, db: Annotated[Session, Depends(get_session)]):
    user_id = validate_refresh_token(token=refresh_token.token)
    user = db.execute(select(User).where(User.id == user_id)).scalars().first()
    user.is_active = False
    db.commit()
    
    revoke_refresh_token(token=refresh_token.token)
    
    response.delete_cookie('access_token', path='/')
    return {'message': 'Вы успешно удалили аккаунт'}
    
    
@app.get('/document')
def get_documents(db: Annotated[Session, Depends(get_session)], access_token: str = Cookie(None, alias='access_token')):
    if not access_token:
        raise HTTPException(status_code=401, detail='Нет токена')
    
    user_id = validate_token(token=access_token)
    
    check_permission(user_id=user_id, resource='documents', action='read', db=db)
    
    return [
        {'id': 1, 'title': 'Документ 1'},
        {'id': 2, 'title': 'Документ 2'}
    ]
    
    
@app.post('/documents')
def create_document(db: Annotated[Session, Depends(get_session)], access_token: str = Cookie(None, alias='access_token')):
    if not access_token:
        raise HTTPException(status_code=401, detail='Нет токена')
    
    user_id = validate_token(token=access_token)
    
    check_permission(user_id=user_id, resource='documents', action='write', db=db)
    
    return {'message': 'Создали документ'}


@app.get('/admin/roles')
def get_roles(db: Annotated[Session, Depends(get_session)], access_token: str = Cookie(None, alias='access_token')):
    if not access_token:
        raise HTTPException(status_code=401, detail='Нет токена')
    
    user_id = validate_token(token=access_token)
    check_permission(user_id=user_id, resource='admin', action='manage', db=db)
    
    roles = db.execute(select(Role)).scalars().all()
    result = []
    
    for role in roles:
        perms = db.execute(select(Permission).join(RolePermission, RolePermission.permission_id == Permission.id).where(RolePermission.role_id == role.id)).scalars().all()
        print(perms)
        result.append({
            'id': role.id,
            'name': role.role,
            'permissions': [{'resource': p.resource, 'action': p.action} for p in perms]
        })
        
    return result 

    
@app.post('/logout')
def logout(refresh_token: Token, response: Response):
    revoke_refresh_token(token=refresh_token.token)
    
    response.delete_cookie('access_token', path='/')
    return {'message': 'Вы успешно вышли из аккаунта'}




