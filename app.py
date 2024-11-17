# app.py
from flask import Flask, render_template, redirect, url_for, flash, request, session
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from models import User, users_db
from forms import RegistrationForm, LoginForm, TwoFactorForm
import pyotp
import qrcode
import os

app = Flask(__name__)
app.secret_key = 'your-secret-key'  # Replace with a strong secret key

# Configure Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure the directory for QR codes exists
os.makedirs('static/qrcodes', exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return users_db.get(user_id)

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        if form.username.data in users_db:
            flash('Username already exists.')
            return redirect(url_for('register'))
        # Create and save the new user
        user = User(form.username.data, form.password.data)
        users_db[user.id] = user
        flash('Registration successful. Please log in.')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = users_db.get(form.username.data)
        if user and user.verify_password(form.password.data):
            session['username'] = user.id
            if user.is_two_factor_enabled:
                # Redirect to 2FA verification if enabled
                return redirect(url_for('two_factor_verify'))
            login_user(user)
            flash('Logged in successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/two_factor_setup', methods=['GET', 'POST'])
@login_required
def two_factor_setup():
    user = current_user
    if user.is_two_factor_enabled:
        flash('Two-factor authentication is already enabled.')
        return redirect(url_for('index'))
    
    form = TwoFactorForm()

    # Generate a new secret key if not already set
    if '2fa_secret' not in session:
        session['2fa_secret'] = pyotp.random_base32()

    secret = session['2fa_secret']
    totp = pyotp.TOTP(secret)

    # Generate the QR Code URI
    qr_uri = totp.provisioning_uri(name=user.id, issuer_name="Flask2FAApp")

    # Save the QR code as an image
    img = qrcode.make(qr_uri)
    qr_code_path = f"static/qrcodes/{user.id}.png"
    img.save(qr_code_path)

    if form.validate_on_submit():
        token = form.token.data
        if totp.verify(token):
            # Enable 2FA for the user
            user.two_factor_secret = secret
            user.is_two_factor_enabled = True
            session.pop('2fa_secret', None)
            flash('Two-factor authentication enabled successfully.')
            return redirect(url_for('index'))
        else:
            flash('Invalid authentication token. Please try again.')

    return render_template('two_factor_setup.html', form=form, user=user, qr_code_path=qr_code_path)


@app.route('/two_factor_verify', methods=['GET', 'POST'])
def two_factor_verify():
    form = TwoFactorForm()
    username = session.get('username')
    user = users_db.get(username)
    if not user or not user.is_two_factor_enabled:
        flash('Invalid user or 2FA not enabled.')
        return redirect(url_for('login'))
    if form.validate_on_submit():
        totp = pyotp.TOTP(user.two_factor_secret)
        token = form.token.data
        if totp.verify(token):
            login_user(user)
            session.pop('username', None)
            flash('Two-factor authentication successful.')
            return redirect(url_for('index'))
        else:
            flash('Invalid token. Please try again.')
    return render_template('two_factor_verify.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
