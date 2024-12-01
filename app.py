from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_mail import Message, Mail
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
from dotenv import dotenv_values
from datetime import timedelta, datetime
from datetime import timedelta, datetime

from models import db, User, LoginAttempt
from models import db, User, LoginAttempt
from forms import RegistrationForm, LoginForm, EmailForm, ChangePasswordForm


MAX_FAILED_ATTEMPTS = 5
LOCK_TIME = timedelta(minutes=15)



MAX_FAILED_ATTEMPTS = 5
LOCK_TIME = timedelta(minutes=15)


app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['RECAPTCHA_PUBLIC_KEY'] = '6LeIxAcTAAAAAJcZVRqyHh71UMIEGNQ_MXjiZKhI'  # Site Key
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'

config = dotenv_values(".env")

app.config['SQLALCHEMY_DATABASE_URI'] = config["SQLALCHEMY_DATABASE_URI"]
app.config['SECURITY_PASSWORD_SALT'] = config["SECURITY_PASSWORD_SALT"]
app.config["SECRET_KEY"] = config["SECRET_KEY"]
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = config['SQLALCHEMY_TRACK_MODIFICATIONS'] == "True"
app.config['MAIL_SERVER'] = config['MAIL_SERVER']
app.config['MAIL_PORT'] = int(config['MAIL_PORT'])
app.config['MAIL_USE_TLS'] = config['MAIL_USE_TLS'] == "True"
app.config['MAIL_USERNAME'] = config['MAIL_USERNAME']
app.config['MAIL_PASSWORD'] = config['MAIL_PASSWORD']

mail = Mail(app)
db.init_app(app)

with app.app_context():
    db.create_all()
    if User.query.filter_by(username="admin").first() is None:
        admin = User(
            email="admin@gmail.com",
            username="admin",
            password=generate_password_hash("admin"),
            confirmed=True,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()
    if User.query.filter_by(username="admin").first() is None:
        admin = User(
            email="admin@gmail.com",
            username="admin",
            password=generate_password_hash("admin"),
            confirmed=True,
            is_admin=True
        )
        db.session.add(admin)
        db.session.commit()


def generate_confirmation_token(email):
    serializer = URLSafeTimedSerializer(
        app.config['SECRET_KEY'], salt=app.config['SECURITY_PASSWORD_SALT'])
    return serializer.dumps(email)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(
        app.config['SECRET_KEY'], salt=app.config['SECURITY_PASSWORD_SALT'])
    try:
        email = serializer.loads(token, salt=app.config['SECURITY_PASSWORD_SALT'],
                                 max_age=expiration)
    except:
        return False
    return email


def send_mail(to, subject, template):
    msg = Message(subject, recipients=[to], html=template, sender=(
        "Your App", "your_email@gmail.com"))
    mail.send(msg)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = User.query.filter_by(username=username).first()

        login_attempt = LoginAttempt(username=username, success=False, timestamp=datetime.now())
        db.session.add(login_attempt)

        if user:
            if check_password_hash(user.password, password):
                if user.confirmed:
                    login_attempt.success = True
                    user.failed_attempts = 0
                    session['user_id'] = user.id
                    flash('Login successful!', 'success')
                    db.session.commit()
                    return redirect(url_for('account'))
                else:
                    flash('Please confirm your email to activate your account.', 'warning')
            else:
                user.failed_attempts += 1
                user.last_failed_attempt = datetime.now()
                db.session.commit()
                flash('Invalid username or password', 'danger')

        login_attempt = LoginAttempt(username=username, success=False, timestamp=datetime.now())
        db.session.add(login_attempt)

        if user:
            if check_password_hash(user.password, password):
                if user.confirmed:
                    login_attempt.success = True
                    user.failed_attempts = 0
                    session['user_id'] = user.id
                    flash('Login successful!', 'success')
                    db.session.commit()
                    return redirect(url_for('account'))
                else:
                    flash(
                        'Please confirm your email to activate your account.', 'warning')
            else:
                user.failed_attempts += 1
                user.last_failed_attempt = datetime.now()
                db.session.commit()
                flash('Invalid username or password', 'danger')
        else:
            flash('Invalid username or password', 'danger')

        db.session.commit()
        
        
        db.session.commit()
        
    return render_template('login.html', form=form)


@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        email = form.email.data

        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
        elif User.query.filter_by(email=email).first():
            flash("Email already exists", 'danger')
        else:
            hashed_password = generate_password_hash(password)
            new_user = User(username=username,
                            password=hashed_password, email=email)
            db.session.add(new_user)
            db.session.commit()

            token = generate_confirmation_token(new_user.email)
            activation_link = url_for(
                'confirm_email', token=token, _external=True)

            send_mail(email, "Activate Your Account",
                      f"Click the following link to activate your account: <a href='{activation_link}'>Activate</a>")

            session['user_id'] = new_user.id
            flash('Registration successful! Please check your email to activate your account.', 'success')
            return redirect(url_for('login'))

    return render_template('registration.html', form=form)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    form = EmailForm()
    if form.validate_on_submit():
        email = form.email.data
        if not User.query.filter_by(email=email).first():
            flash("There is no user with such email", category="danger")
            return redirect(url_for("forgot_password"))

        token = generate_confirmation_token(email)
        activation_link = url_for(
            'change_password', token=token, _external=True)
        send_mail(email, "Activate Your Account",
                  f"Click the following link to change your password: <a href='{activation_link}'>Change password</a>")
        flash("Check your email. The letter with password recovery link was sent.")

    return render_template("forgot_password.html", form=form)


@app.route("/change-password/<token>", methods=["GET", "POST"])
def change_password(token):
    email = confirm_token(token)
    if not email:
        flash('The password change link is invalid or expired.', 'danger')
        return redirect(url_for('login'))

    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if not user:
            flash("The user doesn't exist")
            return redirect(url_for("login"))
        user.password = generate_password_hash(form.password.data)
        db.session.add(user)
        db.session.commit()

        flash("The password was successfuly changed", "info")
        return redirect(url_for("login"))

    return render_template("change_password.html", form=form)



@app.route("/confirm/<token>")
def confirm_email(token):
    email = confirm_token(token)
    if not email:
        flash('The activation link is invalid or expired.', 'danger')
        return redirect(url_for('login'))

    user = User.query.filter_by(email=email).first_or_404()
    if user.confirmed:
        flash('Account already confirmed. Please log in.', 'success')
    else:
        user.confirmed = True
        db.session.commit()
        flash('Your account has been activated!', 'success')

    return redirect(url_for('login'))


@app.route('/account')
def account():
    if 'user_id' not in session:
        flash('Please log in first.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    attempts = LoginAttempt.query.order_by(LoginAttempt.timestamp.desc()).all()
    return render_template('account.html', user=user, attempts=attempts)


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)