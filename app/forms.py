from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo, Length
from app.models import User

# Pola formularzu logowania
class LoginForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired(message='Wypełnij to pole.')])
    password = PasswordField('Hasło', validators=[DataRequired(message='Wypełnij to pole.'), Length(min=8, message='Hasło powinno mieć co najmniej 8 znaków.')])
    crypted = TextAreaField('Tekst zaszyfrowany', validators=[DataRequired(message='Wypełnij to pole.')])
    remember_me = BooleanField('Pamiętaj logowanie')
    submit = SubmitField('Zaloguj się')

# Pola formularzu rejestracji    
class RegistrationForm(FlaskForm):
    username = StringField('Login', validators=[DataRequired(message='Wypełnij to pole.')])
    email = StringField('Adres e-mail', validators=[DataRequired(message='Wypełnij to pole.'), Email(message='Nieprawidłowy adres e-mail.')])
    password = PasswordField('Hasło', validators=[DataRequired(message='Wypełnij to pole.'), Length(min=8, message='Hasło powinno mieć co najmniej 8 znaków.')])
    password2 = PasswordField(
        'Powtórz hasło', validators=[DataRequired(message='Wypełnij to pole.'), EqualTo('password', message='Hasła się nie zgadzają.')])
    submit = SubmitField('Zarejestruj')

# Weryfikowanie, czy login został już użyty
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Login zajęty.')

# Weryfikowanie, czy e-mail został już użyty
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Adres e-mail zajęty.')