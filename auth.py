# ─────────────────────────────────────────────────────────────────────────────
# auth.py  —  Gmail OAuth + Encrypted DB Authentication for MTVS
# ─────────────────────────────────────────────────────────────────────────────

from flask import (
    Blueprint, render_template, redirect, url_for,
    request, flash, session
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from authlib.integrations.flask_client import OAuth
import sqlite3, os
from datetime import datetime
from cryptography.fernet import Fernet

# ── Blueprint ──────────────────────────────────────────────────────────────
auth = Blueprint('auth', __name__)

# ── DB path ───────────────────────────────────────────────────────────────
import os
DATABASE_URL = os.environ.get('DATABASE_URL')
DB_PATH      = os.environ.get('DB_PATH', 'mtvs_scans.db')
DATABASE_URL = os.environ.get('DATABASE_URL')

def get_connection():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)

def ph():
    return '%s' if DATABASE_URL else '?'


def get_connection():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)


# ─────────────────────────────────────────────────────────────────────────────
# ENCRYPTION SETUP
# ─────────────────────────────────────────────────────────────────────────────
def get_fernet_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return Fernet(f.read())
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        print(f"[MTVS] New encryption key generated -> {KEY_FILE}")
        print("[MTVS] IMPORTANT: Back up db.key — losing it means losing all data!")
        return Fernet(key)

fernet = get_fernet_key()


def encrypt(text: str) -> str:
    if not text:
        return text
    return fernet.encrypt(text.encode()).decode()


def decrypt(token: str) -> str:
    if not token:
        return token
    try:
        return fernet.decrypt(token.encode()).decode()
    except Exception:
        return token


# ─────────────────────────────────────────────────────────────────────────────
# DATABASE
# ─────────────────────────────────────────────────────────────────────────────
# ─────────────────────────────────────────────────────────────────
# DATABASE CONNECTION
# ─────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get('DATABASE_URL')
DB_PATH      = os.environ.get('DB_PATH', 'mtvs_scans.db')

def get_connection():
    if DATABASE_URL:
        import psycopg2
        return psycopg2.connect(DATABASE_URL)
    return sqlite3.connect(DB_PATH)

def ph():
    return '%s' if DATABASE_URL else '?'


# ─────────────────────────────────────────────────────────────────
# DATABASE INIT
# ─────────────────────────────────────────────────────────────────
def init_users_db():
    conn = get_connection()
    c    = conn.cursor()
    if DATABASE_URL:
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id          SERIAL PRIMARY KEY,
                google_id   TEXT   NOT NULL UNIQUE,
                email_enc   TEXT   NOT NULL,
                name_enc    TEXT,
                picture_enc TEXT,
                plan        TEXT   DEFAULT 'basic',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login  TIMESTAMP
            )
        ''')
    else:
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                google_id   TEXT    NOT NULL UNIQUE,
                email_enc   TEXT    NOT NULL,
                name_enc    TEXT,
                picture_enc TEXT,
                plan        TEXT    DEFAULT 'basic',
                created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login  TIMESTAMP
            )
        ''')
    conn.commit()
    conn.close()

init_users_db()


# ─────────────────────────────────────────────────────────────────
# USER MODEL
# ─────────────────────────────────────────────────────────────────
class User(UserMixin):
    def __init__(self, id, google_id, email, name, picture, plan):
        self.id        = id
        self.google_id = google_id
        self.email     = email
        self.name      = name
        self.picture   = picture
        self.plan      = plan

    @property
    def full_name(self):
        return self.name or self.email.split('@')[0]

    @property
    def first_name(self):
        return (self.name or '').split()[0] if self.name else self.email.split('@')[0]


# ─────────────────────────────────────────────────────────────────
# DATABASE FUNCTIONS
# ─────────────────────────────────────────────────────────────────
def get_user_by_id(user_id):
    conn = get_connection()
    c    = conn.cursor()
    c.execute(
        f'SELECT id, google_id, email_enc, name_enc, picture_enc, plan FROM users WHERE id = {ph()}',
        (user_id,)
    )
    row = c.fetchone()
    conn.close()
    if row:
        return User(row[0], row[1], decrypt(row[2]), decrypt(row[3]), decrypt(row[4]), row[5])
    return None


def get_or_create_user(google_id, email, name, picture):
    conn = get_connection()
    c    = conn.cursor()

    # Check if user exists
    c.execute(
        f'SELECT id, google_id, email_enc, name_enc, picture_enc, plan FROM users WHERE google_id = {ph()}',
        (google_id,)
    )
    row = c.fetchone()

    if row:
        # Update existing user
        c.execute(
            f'UPDATE users SET last_login={ph()}, name_enc={ph()}, picture_enc={ph()} WHERE google_id={ph()}',
            (datetime.now(), encrypt(name), encrypt(picture), google_id)
        )
        conn.commit()
        user = User(row[0], row[1], decrypt(row[2]), name, picture, row[5])

    else:
        # Create new user
        c.execute(
            f'''INSERT INTO users 
                (google_id, email_enc, name_enc, picture_enc, last_login) 
                VALUES ({ph()},{ph()},{ph()},{ph()},{ph()})''',
            (google_id, encrypt(email), encrypt(name), encrypt(picture), datetime.now())
        )
        conn.commit()

        # Get new user ID
        if DATABASE_URL:
            c.execute("SELECT lastval()")
            new_id = c.fetchone()[0]
        else:
            new_id = c.lastrowid

        user = User(new_id, google_id, email, name, picture, 'basic')

    conn.close()
    return user


# ─────────────────────────────────────────────────────────────────────────────
# OAUTH
# ─────────────────────────────────────────────────────────────────────────────
oauth = OAuth()

def init_oauth(app):
    oauth.init_app(app)
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
        client_kwargs={'scope': 'openid email profile'},
    )


# ─────────────────────────────────────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────────────────────────────────────

@auth.route('/login')
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    return render_template('login.html')


@auth.route('/login/google')
def google_login():
    redirect_uri = url_for('auth.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri, prompt='select_account')


@auth.route('/login/google/callback')
def google_callback():
    try:
        token = oauth.google.authorize_access_token()
        userinfo = token.get('userinfo')
        if not userinfo:
            flash('Google login failed — no user info returned.', 'error')
            return redirect(url_for('auth.login'))

        google_id = userinfo['sub']
        email     = userinfo.get('email', '')
        name      = userinfo.get('name', '')
        picture   = userinfo.get('picture', '')

        user = get_or_create_user(google_id, email, name, picture)
        login_user(user, remember=True)

        next_page = request.args.get('next')
        return redirect(next_page or url_for('home'))

    except Exception as e:
        flash(f'Login error: {str(e)}', 'error')
        return redirect(url_for('auth.login'))


@auth.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('auth.login'))
