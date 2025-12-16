from flask_wtf import FlaskForm 
from wtforms import StringField, TextAreaField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, Length, EqualTo

# Форма для входа пользователя
class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired()])
    submit = SubmitField('Войти', render_kw={"id": "login_submit"})


# Форма для регистрации нового пользователя
class RegisterForm(FlaskForm):
    username = StringField('Имя', validators=[DataRequired(), Length(max=50)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Пароль', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Повторите пароль', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Зарегистрироваться', render_kw={"id": "register_submit"})


# Форма для создания и редактирования задач
class TaskForm(FlaskForm):
    title = StringField('Название задачи (макс. 25 символов)', validators=[DataRequired(), Length(max=25)])
    content = TextAreaField('Описание (макс. 200 символов)', validators=[DataRequired(), Length(max=200)])
    submit = SubmitField('Сохранить')


