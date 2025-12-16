from flask import Flask, render_template, redirect, url_for, flash, session, request
from models import db, User, Task
from forms import LoginForm, RegisterForm, TaskForm
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from flask_wtf import FlaskForm
from dotenv import load_dotenv
import os

load_dotenv()

# Словарь перевода месяцев на русский язык
MONTHS_RU = {
    'January': 'января', 'February': 'февраля', 'March': 'марта',
    'April': 'апреля', 'May': 'мая', 'June': 'июня',
    'July': 'июля', 'August': 'августа', 'September': 'сентября',
    'October': 'октября', 'November': 'ноября', 'December': 'декабря'
}

# Функция форматирования даты в русском формате
def format_russian_date(dt):
    eng = dt.strftime('%d %B %Y г.')
    for en, ru in MONTHS_RU.items():
        eng = eng.replace(en, ru)
    return eng


# Настройка Flask-приложения
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-if-missing')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0
app.jinja_env.globals['format_russian_date'] = format_russian_date

# Инициализация базы данных
db.init_app(app)
with app.app_context():
    db.create_all()


@app.after_request
def set_security_headers(response):

    new_headers = []
    for header, value in response.headers:
        if header.lower() != 'server':
            new_headers.append((header, value))

    response.headers.clear()

    for header, value in new_headers:
        response.headers[header] = value

    response.headers['Server'] = 'SecureServer'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, proxy-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self' https://cdnjs.cloudflare.com; img-src 'self' data:; font-src 'self' https://cdnjs.cloudflare.com; connect-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'self'; object-src 'none'"

    return response

# Пустая форма для CSRF-защиты при удалении задач
class DeleteForm(FlaskForm):
    pass

@app.route('/login_safe', methods=['GET', 'POST'])
def login_safe():
    message = ""
    if request.method == "POST":
        email = request.form.get("email", "")
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            message = "Успешный вход (БЕЗОПАСНАЯ ВЕРСИЯ)"
        else:
            message = "Неверные данные"

    return render_template("login_safe.html", message=message)

# Главная страница (вход и регистрация)
@app.route('/', methods=['GET', 'POST'])
def index():
    login_form = LoginForm(prefix='login')
    register_form = RegisterForm(prefix='register')

    # Проверка формы входа
    if login_form.submit.data and login_form.validate_on_submit():
        user = User.query.filter_by(email=login_form.email.data).first()
        if user and check_password_hash(user.password_hash, login_form.password.data):
            session['user_id'] = user.id
            flash('Вы успешно вошли!', 'success')
            return redirect(url_for('board'))
        else:
            flash('Неправильный Email или пароль.', 'danger')

    # Проверка формы регистрации
    elif register_form.submit.data and register_form.validate_on_submit():
        if User.query.filter_by(email=register_form.email.data).first():
            flash('Email уже используется.', 'danger')
        else:
            hashed_pw = generate_password_hash(register_form.password.data)
            new_user = User(
                username=register_form.username.data,
                email=register_form.email.data,
                password_hash=hashed_pw
            )
            db.session.add(new_user)
            db.session.commit()
            flash('Регистрация прошла успешно! Теперь войдите в систему.', 'success')
            return redirect(url_for('index'))

    # Отображение страницы
    return render_template('index.html', login_form=login_form, register_form=register_form)

# Страница с задачами (доска)
@app.route('/board')
def board():
    if 'user_id' not in session:
        flash('Сначала войдите в систему.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    tasks = Task.query.filter_by(owner_id=user.id).order_by(Task.created_at.desc()).all()
    delete_form = DeleteForm()
    return render_template('board.html', user=user, tasks=tasks, delete_form=delete_form, format_russian_date=format_russian_date)

# Создание новой задачи
@app.route('/create', methods=['GET', 'POST'])
def create_task():
    if 'user_id' not in session:
        flash('Сначала войдите в систему.', 'danger')
        return redirect(url_for('index'))

    user = User.query.get(session['user_id'])
    form = TaskForm()

    if form.validate_on_submit():
        new_task = Task(
            title=form.title.data.strip(),
            content=form.content.data.strip(),
            owner=user
        )
        db.session.add(new_task)
        db.session.commit()
        flash('Задача успешно добавлена!', 'success')
        return redirect(url_for('board'))

    return render_template('edit.html', form=form, title='Новая задача', submit_text='Создать')

# Редактирование задачи
@app.route('/edit/<int:task_id>', methods=['GET', 'POST'])
def edit_task(task_id):
    if 'user_id' not in session:
        flash('Сначала войдите в систему.', 'danger')
        return redirect(url_for('index'))

    task = Task.query.get_or_404(task_id)
    if task.owner_id != session['user_id']:
        flash('У вас нет доступа к этой задаче.', 'danger')
        return redirect(url_for('board'))

    form = TaskForm(obj=task)
    if form.validate_on_submit():
        task.title = form.title.data.strip()
        task.content = form.content.data.strip()
        db.session.commit()
        flash('Задача успешно обновлена!', 'success')
        return redirect(url_for('board'))

    return render_template('edit.html', form=form, title='Редактирование задачи', submit_text='Сохранить')

# Удаление задачи
@app.route('/delete/<int:task_id>', methods=['POST'])
def delete(task_id):
    if 'user_id' not in session:
        flash('Сначала войдите в систему.', 'danger')
        return redirect(url_for('index'))

    task = Task.query.get_or_404(task_id)
    if task.owner_id != session['user_id']:
        flash('Нет доступа к этой задаче.', 'danger')
        return redirect(url_for('board'))

    db.session.delete(task)
    db.session.commit()
    flash('Задача удалена.', 'info')
    return redirect(url_for('board'))

# Выход из системы
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('index'))


