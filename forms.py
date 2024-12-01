from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, EqualTo, Email, EqualTo, Regexp
from flask_wtf.recaptcha import RecaptchaField


class LoginForm(FlaskForm):
    username = StringField(label='User name', validators=[
             DataRequired("Name is required"),
             Length(min=4, max=14, message="Min length - 4, max - 14 symbols"),
             Regexp('^[A-Za-z][A-Za-z0-9_.]*$',0, 'Username must have only lettters, numbers, dots or underscores')
         ])
    password = PasswordField(label='Password', validators=[
             DataRequired("Password is required"), 
             Length(min=7, message="Min length - 7 symbols")
         ])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField(label='User name', validators=[
            DataRequired("Name is required"),
            Length(min=4, max=14, message="Min length - 4, max - 14 symbols"),
            Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Username must have only letters numbers, dots or underscores')
        ])
    email = StringField(label='Email', validators=[DataRequired("Email is required"), Email()])
    password = PasswordField(label='Password', validators=[
            DataRequired("Password is required"), 
            Length(min=7, message="Min length - 7 symbols")
        ])
    confirm_password = PasswordField('Confirm Password', validators=[
                                     DataRequired(), EqualTo('password')])
    recaptcha = RecaptchaField() 
    submit = SubmitField('Register')
