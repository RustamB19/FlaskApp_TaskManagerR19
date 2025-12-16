from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

# Инициализация базы данных SQLAlchemy
db = SQLAlchemy()


# Модель пользователя (User)
# Хранит данные о зарегистрированных пользователях системы
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Уникальный идентификатор пользователя
    username = db.Column(db.String(50), nullable=False)  # Имя пользователя
    email = db.Column(db.String(120), unique=True, nullable=False)  # Электронная почта (уникальная)
    password_hash = db.Column(db.String(200), nullable=False)  # Хэшированный пароль
    tasks = db.relationship('Task', backref='owner', lazy=True)  # Связь с таблицей задач


# Модель задачи (Task)
# Описывает задачу, принадлежащую конкретному пользователю
class Task(db.Model):
    id = db.Column(db.Integer, primary_key=True)  # Уникальный идентификатор задачи
    title = db.Column(db.String(100), nullable=False)  # Название задачи
    content = db.Column(db.Text, nullable=False)  # Описание задачи
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Дата и время создания
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # ID владельца (внешний ключ)

