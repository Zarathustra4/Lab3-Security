from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, Length, Regexp, EqualTo, Email
from flask_wtf.recaptcha import RecaptchaField

class LoginForm(FlaskForm):
    username = StringField(label='User name', validators=[
        DataRequired("Name is required"),
        Length(min=4, max=14, message="Min length - 4, max - 14 symbols"),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Username must have only letters, numbers, dots or underscores')
    ])
    password = PasswordField(label='Password', validators=[
        DataRequired("Password is required")
    ])
    submit = SubmitField('Login')


class RegistrationForm(FlaskForm):
    username = StringField(label='User name', validators=[
        DataRequired("Name is required"),
        Length(min=4, max=14, message="Min length - 4, max - 14 symbols"),
        Regexp('^[A-Za-z][A-Za-z0-9_.]*$', 0, 'Username must have only letters, numbers, dots or underscores')
    ])
    email = StringField(label='Email', validators=[DataRequired("Email is required"), Email()])
    password = PasswordField(label='Password', validators=[
        DataRequired("Password is required"),
        Length(min=8, message="Password must be at least 8 characters long"),
        Regexp('(?=.*[a-z])', 0, 'Password must contain at least one lowercase letter'),
        Regexp('(?=.*[A-Z])', 0, 'Password must contain at least one uppercase letter'),
        Regexp('(?=.*\d)', 0, 'Password must contain at least one digit'),
        Regexp('(?=.*[^\w\d])', 0, 'Password must contain at least one special character')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    recaptcha = RecaptchaField()
    submit = SubmitField('Register')


class EmailForm(FlaskForm):
    email = EmailField(label="Email", validators=[DataRequired("Email is required")])
    submit = SubmitField("Submit")


class ChangePasswordForm(FlaskForm):
    password = PasswordField(label='New Password', validators=[
        DataRequired("Password is required"),
        Length(min=8, message="Password must be at least 8 characters long"),
        Regexp('(?=.*[a-z])', 0, 'Password must contain at least one lowercase letter'),
        Regexp('(?=.*[A-Z])', 0, 'Password must contain at least one uppercase letter'),
        Regexp('(?=.*\d)', 0, 'Password must contain at least one digit'),
        Regexp('(?=.*[^\w\d])', 0, 'Password must contain at least one special character')
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')
