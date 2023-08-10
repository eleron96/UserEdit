import bcrypt
from flask import Flask, render_template, request, redirect, url_for, flash, \
    session
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from user_editor.db import BaseDBModel
from user_editor.models import User

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # это нужно для работы с flash сообщениями

# Подключаемся к базе данных
DATABASE_URL = "postgresql://nikogamsahurdia:password@localhost:5432/user_editor"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine)


@app.route('/')
def main():
    username = session.get('username',
                           None)  # Получаем имя пользователя из сессии
    return render_template('index.html')


@app.route('/registration', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
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
        db_session = SessionLocal()

        try:
            db_session.add(new_user)
            db_session.commit()
            flash("Пользователь успешно зарегистрирован!", "success")
            return redirect(
                url_for('main'))  # перенаправляем на главную страницу
        except Exception as e:
            db_session.rollback()
            flash("Пользователь уже зарегистрирован!", "danger")
        finally:
            db_session.close()
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        db_session = SessionLocal()
        user = db_session.query(User).filter_by(username=username).first()

        if user and bcrypt.checkpw(password.encode('utf-8'),
                                   user.password.encode('utf-8')):
            session['logged_in'] = True
            session[
                'username'] = user.username  # Сохраняем имя пользователя в сессии
            flash('Вы успешно вошли в систему!', 'success')
            return redirect(url_for('main'))
        else:
            flash('Неверное имя пользователя или пароль!', 'danger')

        db_session.close()  # Изменено здесь

    return render_template('login.html')


@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Вы успешно вышли из системы!', 'success')
    return redirect(url_for('main'))


@app.route('/users')
def users_list():
    if not session.get('logged_in'):
        flash("Пожалуйста, войдите в систему для доступа к этой странице!",
              "danger")
        return redirect(url_for('login'))

    db_session = SessionLocal()
    users = db_session.query(User).all()
    db_session.close()
    return render_template('users/users_list.html', users=users)


@app.route('/edit-user/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    db_session = SessionLocal()
    user = db_session.query(User).filter_by(id=user_id).first()

    if not user:
        flash("Пользователь не найден!", "danger")
        return redirect(url_for('users_list'))

    if request.method == 'POST':
        user.username = request.form.get('username')
        user.email = request.form.get('email')
        new_password = request.form.get('password')
        if new_password:
            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'),
                                            bcrypt.gensalt()).decode('utf-8')
            user.password = hashed_password

        try:
            db_session.commit()
            flash("Пользователь успешно обновлен!", "success")
        except IntegrityError as error:
            db_session.rollback()
            if "users_email_key" in str(error):
                flash("Ошибка! Этот email уже зарегистрирован.", "danger")
            elif "users_username_key" in str(error):
                flash("Ошибка! Это имя пользователя уже занято.", "danger")
            else:
                flash("Ошибка обновления данных!", "danger")
        finally:
            db_session.close()
            return redirect(url_for('users_list'))

    return render_template('users/edit_user.html', user=user)


@app.route('/delete-user/<int:user_id>', methods=['GET', 'POST'])
def delete_user(user_id):
    db_session = SessionLocal()
    user = db_session.query(User).filter_by(id=user_id).first()

    if not user:
        flash("Пользователь не найден!", "danger")
        return redirect(url_for('users_list'))

    if request.method == 'POST':
        db_session.delete(user)
        db_session.commit()
        flash("Пользователь успешно удален!", "success")
        return redirect(url_for('users_list'))

    return render_template('users/confirm_delete.html', user=user)


if __name__ == '__main__':
    BaseDBModel.metadata.create_all(
        bind=engine)  # Создаем таблицы в базе данных
    app.run(debug=True)
