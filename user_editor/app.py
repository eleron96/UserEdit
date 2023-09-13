import asyncio

import bcrypt
from decouple import config
from flask import Flask, render_template, request, redirect, url_for, flash, \
    session as flask_session
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import load_only

from user_editor.db import BaseDBModel, get_session, engine
from user_editor.models import User

app = Flask(__name__)

app.secret_key = config('SECRET_KEY', default='your_default_secret_key')


# DATABASE_URL = config('DATABASE_URL', default='your_default_database_url')
# engine = create_async_engine(DATABASE_URL)
# db_session = async_sessionmaker(bind=engine)


@app.route('/')
async def main():
    username = flask_session.get('username',
                                 None)  # Получаем имя пользователя из сессии
    return render_template('index.html')


@app.route('/registration', methods=['GET', 'POST'])
async def register():
    if request.method == 'GET':
        return render_template('register.html')
    # Получаем данные из формы
    username = request.form.get('username')
    email = request.form.get('email')
    password = request.form.get('password')

    # Хешируем пароль перед сохранением в базе данных
    hashed_password = bcrypt.hashpw(password.encode('utf-8'),
                                    bcrypt.gensalt()).decode('utf-8')

    # Создаем нового пользователя
    new_user = User(username=username, email=email,
                    password=hashed_password)

    # Добавляем пользователя в базу данных

    try:
        async with get_session() as db_session:
            db_session.add(new_user)
        flash("Пользователь успешно зарегистрирован!", "success")
        return redirect(
            url_for('main'))  # перенаправляем на главную страницу
    except Exception as e:
        flash("Пользователь уже зарегистрирован!", "danger")


@app.route('/add-user', methods=['GET', 'POST'])
async def add_user():
    if not flask_session.get('logged_in'):
        flash("Пожалуйста, войдите в систему для доступа к этой странице!",
              "danger")
        return redirect(url_for('login'))

    # Проверка права на создание пользователей
    if not current_user_can_create():
        flash("У вас нет прав на создание пользователей!", "danger")
        return redirect(url_for('main'))

    if request.method == 'GET':
        return render_template('users/add_user.html')

    username = request.form.get('username')
    async with get_session() as session:
        result = await session.execute(select(User).where(User.username == username))
        existing_user = result.scalars().first()

    if existing_user:
        flash("Пользователь с таким именем уже существует!", "danger")
        return redirect(url_for('add_user'))

    email = request.form.get('email')
    password = request.form.get('password')
    hashed_password = bcrypt.hashpw(password.encode('utf-8'),
                                    bcrypt.gensalt()).decode('utf-8')

    new_user = User(username=username, email=email,
                    password=hashed_password)
    roles = request.form.getlist('roles')  # проверить
    new_user.roles = ','.join(roles)
    new_user.is_admin = 'is_admin' in request.form
    new_user.is_editor = 'is_editor' in request.form
    new_user.can_create_users = 'can_create_users' in request.form

    try:
        async with get_session() as db_session:
            db_session.add(new_user)
        flash(f"Пользователь '{username}' был успешно добавлен!", "success")
        return render_template('register.html')
    except Exception as e:
        flash(f"Ошибка при добавлении пользователя: {str(e)}", "danger")


# async def create_super_user():
#     async with get_session() as db_session:
#         # Проверка наличия пользователя с именем admin в базе данных
#         query_user = await db_session.execute(select(User).where(User.username == 'admin'))
#         super_user = query_user.scalars().first()
#
#         if super_user:
#             return
#             # Хеширование пароля
#         hashed_password = bcrypt.hashpw('admin'.encode('utf-8'),
#                                         bcrypt.gensalt()).decode('utf-8')
#
#         # Создание суперпользователя
#         super_user = User(username='admin', email='admin@admin.com',
#                           password=hashed_password, is_admin=True,
#                           is_editor=True, can_create_users=True)
#         db_session.add(super_user)


def is_editor(user):
    return user.is_editor


def is_admin(user):
    return user.is_admin


async def current_user_is_editor(db_session):
    current_user = db_session.query(User).filter_by(
        username=flask_session['username']).first()
    return current_user.is_editor if current_user else False


async def current_user_is_admin(db_session):
    current_user = db_session.query(User).filter_by(
        username=flask_session['username']).first()
    return current_user.is_admin if current_user else False


async def current_user_can_create():
    async with get_session() as db_session:
        current_user = db_session.query(User).filter_by(
            username=flask_session['username']).first()
    return current_user.can_create_users if current_user else False


@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'GET':
        return render_template('login.html')
    username = request.form.get('username')
    password = request.form.get('password')

    async with get_session() as db_session:
        query_user = await db_session.execute(select(User).where(User.username == username))
        user = query_user.scalars().first()
        # user = await db_session.query(User).filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'),
                                   user.password.encode('utf-8')):
            flask_session['logged_in'] = True
            flask_session[
                'username'] = user.username  # Сохраняем имя пользователя в сессии
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('main'))
        else:
            flash('Неверное имя пользователя или пароль!', 'danger')


@app.route('/logout')
async def logout():
    flask_session.pop('logged_in', None)
    flash('Вы успешно вышли из системы!', 'success')
    return redirect(url_for('main'))


@app.route('/users')
async def users_list():
    if not flask_session.get('logged_in'):
        flash("Пожалуйста, войдите в систему для доступа к этой странице!",
              "danger")
        return redirect(url_for('login'))

    # async with get_session() as db_session:
    #     result = await db_session.execute(select(User).where(User.username != 'admin'))
    #     users = result.scalars().all()  # Получаем всех пользователей, кроме админа

    async with get_session() as db_session:
        result = await db_session.execute(
            select(User).options(load_only("id", "username")).where(
                User.username != 'admin')
        )
        users = result.scalars().all()  # Получаем всех пользователей, кроме админа

    return render_template('users/users_list.html', users=users)


@app.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
async def edit_user(user_id):
    async with get_session() as db_session:
        if not (current_user_is_admin(db_session) or current_user_is_editor(
                db_session)):
            flash("У вас нет прав для редактирования этого пользователя!",
                  "danger")
            return redirect(url_for('users_list'))

        user = db_session.query(User).filter_by(id=user_id).first()

        if not user:
            flash("Пользователь не найден!", "danger")
            return redirect(url_for('users_list'))

        if user.username == 'admin' and not current_user_is_admin(db_session):
            flash("Вы не можете редактировать суперпользователя!", "danger")
            return redirect(url_for('users_list'))

    if request.method == 'GET':
        return render_template('users/edit_user.html', user=user)

    user.username = request.form.get('username')
    user.email = request.form.get('email')
    roles = request.form.getlist('roles')
    user.roles = ','.join(roles)
    user.is_admin = 'is_admin' in request.form
    user.is_editor = 'is_editor' in request.form
    user.can_create_users = 'can_create_users' in request.form

    new_password = request.form.get('password')
    if new_password:
        hashed_password = bcrypt.hashpw(new_password.encode('utf-8'),
                                        bcrypt.gensalt()).decode('utf-8')
        user.password = hashed_password

    try:
        async with get_session() as db_session:
            db_session.add(user)
        flash(
            f"Данные пользователя '{user.username}' были успешно обновлены!",
            "success")

    except IntegrityError as error:
        if "users_email_key" in str(error):
            flash("Ошибка! Этот email уже зарегистрирован.", "danger")
        elif "users_username_key" in str(error):
            flash("Ошибка! Это имя пользователя уже занято.", "danger")
        else:
            flash("Ошибка обновления данных!", "danger")
    finally:
        return redirect(url_for('users_list'))


@app.route('/delete-user/<int:user_id>', methods=['GET', 'POST'])
async def delete_user(user_id):
    async with get_session() as db_session:
        if not current_user_is_admin(db_session):
            flash("Только администратор может удалять пользователей!", "danger")
            return redirect(url_for('users_list'))

        user = db_session.query(User).filter_by(id=user_id).first()

    if not user:
        flash("Пользователь не найден!", "danger")
        return redirect(url_for('users_list'))

    if request.method == 'GET':
        return render_template('users/delete_user.html', user=user)
    try:
        async with get_session() as db_session:
            db_session.delete(user)
        flash(f"Пользователь '{user.username}' был успешно удален!",
              "success")
    except Exception as e:
        flash(f"Ошибка при удалении пользователя: {str(e)}", "danger")
    return redirect(url_for('users_list'))


async def init_tables():
    async with engine.begin() as conn:
        await conn.run_sync(BaseDBModel.metadata.create_all)


if __name__ == '__main__':
    # loop = asyncio.get_event_loop()
    # loop.run_until_complete(init_tables())
    # loop.run_until_complete(create_super_user())

    app.run(debug=True)
