Это проект системы аутентификации и авторизации.


Используемые технологии:
    - FastAPI
    - SQLAlchemy
    - SQLite


Структура базы данных.
В базе данных models.db реализовано 5 таблиц(models.py)
    - Role
    Хранит роли пользователей.
    Поля: id, role.

    - Permission
    Хранит разрешения в формате (resource, action).
    Поля: id, resource, action.

    - RolePermission
    Связующая таблица между ролями и правами.
    Поля: id, role_id, permission_id.

    - User
    Хранит данные пользователей.
    Поля: id, username, email, hashed_password, role_id, created_at, is_active.

    - RefreshTokens
    Хранит refresh‑токены.
    Поля: id, user_id, hashed_token, created_at, expires_at, is_revoked.


Архитектура аутентификации 
Регистрация — /register
Принимает: username, email, password, repeat_password.
Проверяется:
    - валидность email,
    - уникальность email,
    - валидность пароля,
    - совпадение паролей.
Пароль хэшируется, пользователь сохраняется в БД.


Вход — /login
Принимает: email, password.
Проверяется:
    - существует ли пользователь,
    - активен ли он,
    - корректен ли пароль.
Создаются:
access_token (30 минут) — отправляется в httpOnly cookie,
refresh_token (30 дней) — хэшируется и сохраняется в БД.


Обновление токена — /auth/refresh
Принимает: refresh_token.
Проверяется:
    - существует ли токен,
    - не истёк ли,
    - не отозван ли.
Создаётся новый access_token.


Обновление профиля — /profile/update
Принимает: username, email, password (все необязательные), access_token.
Проверяется:
    - валидность access_token,
    - какие поля переданы,
    - корректность новых данных.
Данные обновляются.


Удаление профиля — /profile/delete
Принимает: refresh_token.
Происходит:
soft delete (is_active = False),
отзыв refresh‑токена,
удаление access‑токена из куков.


Выход — /logout
Отзывает refresh‑токен и удаляет access‑токен.



В проекте реализована маленькая система ролей и прав.
Для них сделано 4 таблицы:
    - Role = роль пользователя (admin, user).
    - Permission = разрешение на действие (resource + action).
    - RolePermission = свзять ролей и прав.
    - User = содержит ссылку на роль.


Все права:
    - ("documents", "read")
    - ("documents", "write")
    - ("orders", "read")
    - ("admin", "manage")


Для проверки прав в эндпоинтах моковых бизнес-ресурсов, вызывается функция:
check_permission(user_id, resource, action)
Если:
    - токена нет = 401 Unauthorized
    - токен есть, но прав нет = 403 Forbidden
    - всё корректно = доступ разрешён


Для демонстрации работы RBAC реализованы простые эндпоинты:

GET /document
Доступ: documents:read

POST /documents
Доступ: documents:write

Админские эндпоинты
GET /admin/roles
Возвращает список ролей и их прав.
Доступ: admin:manage.


ЧТОБЫ ЗАПУСТИТЬ ПРОЕКТ ВВЕДИТЕ ЭТИ ДВЕ КОМАНДЫ В ТЕРМИНАЛ:
pip install -r requirements.txt
uvicorn main:app