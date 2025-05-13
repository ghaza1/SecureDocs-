from flask import Flask, render_template, redirect, url_for, session, request, flash, jsonify, send_from_directory, Response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
# Flask-Dance for Google & GitHub are removed
from authlib.integrations.flask_client import OAuth # For Okta/Auth0
from flask_migrate import Migrate 

from dotenv import load_dotenv
import os
import pyotp
import qrcode
from io import BytesIO, StringIO 
import base64
from datetime import timedelta, datetime
from functools import wraps 
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException # For handling HTTP exceptions in errorhandler
import hashlib
import uuid
import json
import csv 
import re 
import traceback # For logging exception tracebacks

# Cryptography imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa 
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'default_flask_secret_key_change_me_!') 
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)
app.config['PREFERRED_URL_SCHEME'] = 'https' 

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

CERT_FILE = os.path.join('certs', 'server.crt')
KEY_FILE = os.path.join('certs', 'server.key')

MASTER_KEY_HEX = os.getenv('MASTER_ENCRYPTION_KEY')
if not MASTER_KEY_HEX:
    app.logger.critical("CRITICAL: MASTER_ENCRYPTION_KEY not set in .env.")
    raise ValueError("MASTER_ENCRYPTION_KEY must be set in .env and be a 64-char hex string (32 bytes)") 
elif len(bytes.fromhex(MASTER_KEY_HEX)) != 32:
    raise ValueError("MASTER_ENCRYPTION_KEY must be a 64-char hex string (32 bytes) if set.")
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

PRIVATE_KEY_PATH = "private_key.pem"
PUBLIC_KEY_PATH = "public_key.pem"
SERVER_PRIVATE_KEY = None
SERVER_PUBLIC_KEY = None

try:
    with open(PRIVATE_KEY_PATH, "rb") as key_file:
        SERVER_PRIVATE_KEY = serialization.load_pem_private_key(key_file.read(), password=None, backend=default_backend())
    with open(PUBLIC_KEY_PATH, "rb") as key_file:
        SERVER_PUBLIC_KEY = serialization.load_pem_public_key(key_file.read(), backend=default_backend())
    app.logger.info("RSA keys loaded successfully.")
except FileNotFoundError:
    app.logger.error(f"RSA key files ({PRIVATE_KEY_PATH}, {PUBLIC_KEY_PATH}) not found. Digital signatures will fail.")
except Exception as e:
    app.logger.error(f"Error loading RSA keys: {e}. Digital signatures will fail.")

oauth = OAuth(app) 
okta_domain_env = os.getenv('OKTA_DOMAIN')
okta_domain_for_url = "https://example.okta.com" 
if not okta_domain_env:
    app.logger.warning("CRITICAL: OKTA_DOMAIN not set in .env. Okta/Auth0 login WILL FAIL.")
else:
    okta_domain_for_url = okta_domain_env.strip()
    if '"' in okta_domain_for_url or '#' in okta_domain_for_url or ' ' in okta_domain_for_url.split('//', 1)[-1]:
        app.logger.error(
            f"CRITICAL: OKTA_DOMAIN in .env ('{okta_domain_env}') appears to be malformed. "
            "It should be a clean URL (e.g., https://your-tenant.us.auth0.com) "
            "without extra quotes, spaces after 'https://', or inline comments within the value."
        )
oauth.register(
    name='okta', 
    client_id=os.getenv('OKTA_CLIENT_ID'),
    client_secret=os.getenv('OKTA_CLIENT_SECRET'),
    server_metadata_url=f"{okta_domain_for_url}/.well-known/openid-configuration",
    client_kwargs={'scope': 'openid email profile', 'token_endpoint_auth_method': 'client_secret_post'}
)

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# --- User Model ---
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150), nullable=True)
    role = db.Column(db.String(50), nullable=False, default='user') 
    password_hash = db.Column(db.String(255), nullable=True) 
    oauth_provider = db.Column(db.String(50), nullable=True) 
    oauth_uid = db.Column(db.String(255), nullable=True) 
    otp_secret = db.Column(db.String(100), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    __table_args__ = (db.UniqueConstraint('oauth_provider', 'oauth_uid', name='uq_oauth_provider_uid'),)
    documents = db.relationship('Document', backref='owner', lazy='dynamic', cascade="all, delete-orphan") 
    audit_logs = db.relationship('AuditLog', backref='user_acted', lazy='dynamic', foreign_keys='AuditLog.user_id') 
    target_audit_logs = db.relationship('AuditLog', backref='user_targeted', lazy='dynamic', foreign_keys='AuditLog.target_user_id') 

    def set_password(self, password): self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        if not self.password_hash: return False
        return check_password_hash(self.password_hash, password)
    def __repr__(self): return f"<User {self.email}>"

# --- Document Model ---
class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    filename = db.Column(db.String(255), nullable=False)
    saved_filename = db.Column(db.String(255), nullable=False, unique=True)
    filesize = db.Column(db.Integer, nullable=False) 
    encrypted_filesize = db.Column(db.Integer, nullable=True)
    filetype = db.Column(db.String(50), nullable=True)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False) 
    sha256_hash = db.Column(db.String(64), nullable=True)
    is_encrypted = db.Column(db.Boolean, default=False)
    encryption_salt = db.Column(db.LargeBinary(16), nullable=True)
    encryption_nonce = db.Column(db.LargeBinary(12), nullable=True)
    digital_signature = db.Column(db.Text, nullable=True) 
    def __repr__(self): return f"<Document {self.filename} (Owner: {self.user_id})>"

# --- AuditLog Model ---
class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True) 
    action_type = db.Column(db.String(100), nullable=False) 
    target_user_id = db.Column(db.Integer, db.ForeignKey('users.id', ondelete='SET NULL'), nullable=True) 
    target_document_id = db.Column(db.Integer, db.ForeignKey('documents.id', ondelete='SET NULL'), nullable=True) 
    details = db.Column(db.Text, nullable=True) 
    ip_address = db.Column(db.String(45), nullable=True) 
    user_agent = db.Column(db.String(255), nullable=True) 
    request_method = db.Column(db.String(10), nullable=True) 
    resource_path = db.Column(db.String(255), nullable=True) 
    referer = db.Column(db.String(512), nullable=True)
    http_version = db.Column(db.String(10), nullable=True) 
    status_code = db.Column(db.Integer, nullable=True)    
    response_size = db.Column(db.Integer, nullable=True) 
    def __repr__(self): return f"<AuditLog {self.timestamp} - User: {self.user_id} - Action: {self.action_type}>"

# --- Helper function to record audit logs ---
def record_audit_log(action_type, details=None, user_id=None, 
                     target_user_id=None, target_document_id=None,
                     status_code=None, response_size=None, exception_info=None):
    try:
        log_user_id = user_id if user_id is not None else (current_user.id if current_user.is_authenticated else None)
        ip, ua_string, method, path, ref, http_ver = None, None, None, None, None, None
        if request: 
            ip = request.remote_addr
            if request.user_agent: ua_string = request.user_agent.string
            method = request.method
            path = request.path
            ref = request.referrer
            http_ver = request.environ.get('SERVER_PROTOCOL')
        details_to_store = {}
        if isinstance(details, dict): details_to_store.update(details)
        elif details is not None: details_to_store['message'] = str(details)
        if exception_info: details_to_store['exception'] = str(exception_info) 
        log_entry = AuditLog(
            user_id=log_user_id, action_type=action_type, target_user_id=target_user_id, 
            target_document_id=target_document_id, details=json.dumps(details_to_store, ensure_ascii=False, indent=2) if details_to_store else None, 
            ip_address=ip, user_agent=ua_string, request_method=method, resource_path=path, 
            referer=ref, http_version=http_ver, status_code=status_code, response_size=response_size
        )
        db.session.add(log_entry); db.session.commit()
    except Exception as e: 
        app.logger.error(f"CRITICAL: Error recording audit log itself for action '{action_type}': {e}")
        app.logger.error(f"Original audit details: {details_to_store if 'details_to_store' in locals() else details}")
        db.session.rollback()

# --- Global Error Handler for Unhandled Exceptions ---
@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        record_audit_log(
            action_type=f"HTTP_ERROR_{e.code}", 
            details={"error": str(e.description if hasattr(e, 'description') else str(e.name if hasattr(e, 'name') else 'Unknown HTTP Error'))},
            status_code=e.code,
            exception_info=traceback.format_exc()
        )
        return e
    exception_trace = traceback.format_exc()
    app.logger.error(f"Unhandled exception: {e}\n{exception_trace}")
    record_audit_log(
        action_type="UNHANDLED_EXCEPTION", 
        details={"error": str(e)},
        status_code=500, 
        exception_info=exception_trace
    )
    return render_template("500.html", error=str(e)), 500

# --- After Request Logger ---
@app.after_request
def after_request_logger(response):
    if request and not request.path.startswith('/static'):
        is_unhandled_exception_response = False 
        try:
            if response.status_code >= 500 and response.is_sequence: 
                if b"Internal Server Error" in response.get_data() or b"An unhandled exception occurred" in response.get_data():
                    is_unhandled_exception_response = True
        except Exception: pass 

        if not is_unhandled_exception_response:
            action = f"REQUEST_SERVED_{request.method}"
            if response.status_code >= 400:
                action = f"REQUEST_FAILED_{request.method}_{response.status_code}"
            
            record_audit_log(
                action_type=action,
                details={"path": request.path, "args": dict(request.args)},
                status_code=response.status_code,
                response_size=response.content_length
            )
    return response

# --- Password Complexity Function ---
def check_password_complexity(password):
    if len(password) < 8: return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password): return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password): return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password): return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?~`]", password): return False, "Password must contain at least one special character (e.g., !@#$%^&*)."
    return True, "Password meets complexity requirements."

# --- Cryptography Helper Functions ---
def derive_key(salt, master_key=MASTER_KEY):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=default_backend())
    return kdf.derive(master_key)
def encrypt_data(data_bytes, key):
    nonce = os.urandom(12); aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, data_bytes, None), nonce
def decrypt_data(ciphertext, nonce, key):
    aesgcm = AESGCM(key); return aesgcm.decrypt(nonce, ciphertext, None)
def sign_data_hash(data_hash_bytes, private_key=SERVER_PRIVATE_KEY):
    if not private_key: app.logger.error("Cannot sign data: Server private key not loaded."); return None
    signature = private_key.sign(data_hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return base64.b64encode(signature).decode('utf-8')
def verify_data_signature(data_hash_bytes, signature_b64_str, public_key=SERVER_PUBLIC_KEY):
    if not public_key: app.logger.error("Cannot verify signature: Server public key not loaded."); return False
    try:
        signature_bytes = base64.b64decode(signature_b64_str)
        public_key.verify(signature_bytes, data_hash_bytes, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except InvalidSignature: app.logger.warning("Signature verification failed: InvalidSignature"); return False
    except Exception as e: app.logger.error(f"Error during signature verification: {e}"); return False

# --- Flask-Login Configuration ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
@login_manager.user_loader
def load_user(user_id): return User.query.get(int(user_id))

# --- Helper function to create/update user from OAuth (Now only for Okta/Auth0) ---
def create_or_update_oauth_user(provider_name, user_info_from_provider):
    email = user_info_from_provider.get("email")
    name = user_info_from_provider.get("name") or user_info_from_provider.get("preferred_username")
    oauth_id_from_provider = user_info_from_provider.get("sub") 
    if not email: flash(f"Email not provided by {provider_name.capitalize()}.", "danger"); return None
    if not oauth_id_from_provider: flash(f"UID not provided by {provider_name.capitalize()}.", "danger"); return None
    is_new_user = False
    user = User.query.filter_by(oauth_provider=provider_name, oauth_uid=oauth_id_from_provider).first()
    if user: user.name, user.email = name, email 
    else: 
        user_by_email = User.query.filter_by(email=email).first()
        if user_by_email: 
            user = user_by_email
            if not user.oauth_provider or not user.oauth_uid: 
                user.oauth_provider = provider_name; user.oauth_uid = oauth_id_from_provider; user.name = name 
            elif user.oauth_provider != provider_name or user.oauth_uid != oauth_id_from_provider:
                flash(f"Email {email} is associated with a different login method.", "warning"); return None
        else: user = User(email=email, name=name, oauth_provider=provider_name, oauth_uid=oauth_id_from_provider, role='user'); db.session.add(user); is_new_user = True
    try: 
        db.session.commit()
        if is_new_user: record_audit_log("USER_REGISTER_OAUTH", details={"provider": provider_name, "email": user.email}, user_id=user.id)
    except Exception as e: db.session.rollback(); app.logger.error(f"DB error OAuth user {provider_name}: {e}"); flash("Error processing login.", "danger"); return None
    return user

# --- Authlib Okta Routes ---
@app.route('/login/okta_authlib') 
def okta_authlib_login(): 
    redirect_uri = url_for('okta_authlib_authorize', _external=True)
    return oauth.okta.authorize_redirect(redirect_uri)

@app.route('/authorize/okta') 
def okta_authlib_authorize():
    try: 
        token = oauth.okta.authorize_access_token()
        user_info = token.get('userinfo') 
        if not user_info: 
            resp = oauth.okta.get(oauth.okta.server_metadata.get('userinfo_endpoint'))
            resp.raise_for_status(); user_info = resp.json()
    except Exception as e: 
        app.logger.error(f"Okta Authlib authorization error: {e}")
        flash(f"Okta authentication failed. Please try again or contact support.", "danger")
        record_audit_log("USER_LOGIN_OAUTH_FAILED_OKTA", details={"error": str(e)}, exception_info=traceback.format_exc())
        return redirect(url_for('login'))
    if not user_info: 
        flash("Could not retrieve user information from Okta.", "danger")
        record_audit_log("USER_LOGIN_OAUTH_NO_INFO_OKTA")
        return redirect(url_for('login'))
    app_user = create_or_update_oauth_user("okta", user_info) 
    if app_user:
        login_user(app_user)
        record_audit_log("USER_LOGIN_OAUTH_SUCCESS", details={"provider": "okta"}, user_id=app_user.id)
        flash(f"Logged in as {app_user.name} via Okta/Auth0!", "success") 
        return redirect(url_for("dashboard"))
    else: record_audit_log("USER_LOGIN_OAUTH_NO_APP_USER_OKTA", details=user_info)
    return redirect(url_for("login"))

# --- Basic Routes (Home, Dashboard) ---
@app.route('/')
@login_required
def home(): return redirect(url_for('dashboard'))

@app.route('/dashboard')
@login_required
def dashboard():
    user_doc_count = current_user.documents.count() 
    user_total_size = db.session.query(db.func.sum(Document.filesize)).filter_by(user_id=current_user.id).scalar() or 0
    total_doc_count, total_user_count = 0, 0
    if current_user.role == 'admin':
        total_doc_count = Document.query.count()
        total_user_count = User.query.count()
    show_2fa_prompt = (not current_user.is_2fa_enabled and not current_user.oauth_provider)
    return render_template('dashboard.html', name=current_user.name, is_admin=(current_user.role == 'admin'), 
                           user_doc_count=user_doc_count, user_total_size=user_total_size,
                           total_doc_count=total_doc_count, total_user_count=total_user_count,
                           show_2fa_prompt=show_2fa_prompt)

# --- Signup & Login Routes ---
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        name = request.form.get('name'); email = request.form.get('email')
        password = request.form.get('password'); confirm_password = request.form.get('confirm_password')
        form_data = {'name': name, 'email': email}
        if not all([name, email, password, confirm_password]): flash('All fields are required.', 'danger'); return render_template('signup.html', **form_data)
        is_complex, message = check_password_complexity(password)
        if not is_complex: flash(message, 'danger'); return render_template('signup.html', **form_data)
        if password != confirm_password: flash('Passwords do not match.', 'danger'); return render_template('signup.html', **form_data)
        if User.query.filter_by(email=email).first(): flash('Email already exists. Please login or use a different email.', 'warning'); return render_template('signup.html', name=name)
        new_user = User(email=email, name=name, role='user'); new_user.set_password(password)
        try: 
            db.session.add(new_user); db.session.commit()
            record_audit_log("USER_REGISTER_EMAIL", details={"email": new_user.email}, user_id=new_user.id)
            flash('Account created successfully! Please log in.', 'success'); return redirect(url_for('login'))
        except Exception as e: db.session.rollback(); app.logger.error(f"Error creating user: {e}"); record_audit_log("USER_REGISTER_FAILED", details={"email": email, "error": str(e)}, exception_info=traceback.format_exc()); flash('An error occurred while creating your account. Please try again.', 'danger'); return render_template('signup.html', **form_data)
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email, password = request.form.get('email'), request.form.get('password')
        if not email or not password: flash('Email and password required.', 'danger'); return redirect(url_for('login'))
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password): 
            if user.is_2fa_enabled: 
                session['2fa_user_id'], session['2fa_next_url'] = user.id, url_for('dashboard')
                record_audit_log("USER_LOGIN_2FA_REQUIRED_EMAIL", user_id=user.id) 
                return redirect(url_for('verify_2fa'))
            login_user(user)
            record_audit_log("USER_LOGIN_EMAIL_SUCCESS", user_id=user.id) 
            flash(f'Logged in as {user.name}!', 'success'); return redirect(url_for('dashboard'))
        else: record_audit_log("USER_LOGIN_FAILED_EMAIL", details={"attempted_email": email}); flash('Invalid email or password.', 'danger')
    return render_template('login.html')

# --- Logout Route ---
@app.route('/logout')
@login_required
def logout():
    user_id_before_logout = current_user.id 
    logout_user(); session.clear(); record_audit_log("USER_LOGOUT", user_id=user_id_before_logout); flash('Logged out.', 'success'); return redirect(url_for('login'))

# --- 2FA Routes ---
@app.route('/setup_2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    if current_user.oauth_provider: flash("2FA is managed by your identity provider (e.g., Okta/Auth0).", "info"); return redirect(url_for('dashboard'))
    if current_user.is_2fa_enabled: flash('2FA is already enabled.', 'info'); return redirect(url_for('dashboard'))
    if request.method == 'POST':
        token, otp_secret_from_session = request.form.get('token'), session.get('new_otp_secret')
        if not otp_secret_from_session: flash('Session expired. Try 2FA setup again.', 'danger'); return redirect(url_for('setup_2fa'))
        if pyotp.TOTP(otp_secret_from_session).verify(token):
            user_to_update = User.query.get(current_user.id)
            if user_to_update:
                user_to_update.otp_secret, user_to_update.is_2fa_enabled = otp_secret_from_session, True
                try: db.session.commit(); current_user.otp_secret, current_user.is_2fa_enabled = otp_secret_from_session, True; del session['new_otp_secret']; record_audit_log("2FA_ENABLED", user_id=current_user.id); flash('2FA enabled!', 'success'); return redirect(url_for('dashboard'))
                except Exception as e: db.session.rollback(); app.logger.error(f"DB error enabling 2FA: {e}"); flash('DB error enabling 2FA.', 'danger')
            else: flash('User not found for 2FA.', 'danger')
        else: flash('Invalid 2FA token.', 'danger')
    if 'new_otp_secret' not in session: session['new_otp_secret'] = pyotp.random_base32()
    otp_secret = session['new_otp_secret']
    provisioning_name = current_user.email if current_user.email else str(current_user.id)
    totp_uri = pyotp.totp.TOTP(otp_secret).provisioning_uri(name=provisioning_name, issuer_name="SecureDocs")
    img = qrcode.make(totp_uri); buf = BytesIO(); img.save(buf); buf.seek(0); qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    return render_template('2fa_setup.html', otp_secret=otp_secret, qr_code_b64=qr_code_b64)

@app.route('/verify_2fa', methods=['GET', 'POST'])
def verify_2fa():
    user_id_for_2fa = session.get('2fa_user_id')
    if not user_id_for_2fa: flash("No 2FA process started.", "warning"); return redirect(url_for('login'))
    user = User.query.get(user_id_for_2fa)
    if not user or not user.is_2fa_enabled or not user.otp_secret or user.oauth_provider:
        flash("2FA not applicable or user issue.", "danger"); session.pop('2fa_user_id', None); session.pop('2fa_next_url', None); return redirect(url_for('login'))
    if request.method == 'POST':
        token = request.form.get('token')
        if pyotp.TOTP(user.otp_secret).verify(token):
            login_user(user); next_url = session.get('2fa_next_url', url_for('dashboard'))
            session.pop('2fa_user_id', None); session.pop('2fa_next_url', None)
            record_audit_log("USER_LOGIN_2FA_SUCCESS", user_id=user.id, details={"original_method_hint": "EMAIL"})
            flash('2FA successful!', 'success'); return redirect(next_url)
        else: record_audit_log("USER_LOGIN_2FA_FAILED", user_id=user.id); flash('Invalid 2FA token.', 'danger')
    return render_template('2fa_verify.html')

# --- Document Management Routes ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
def calculate_sha256(file_stream_or_bytes):
    hash_sha256 = hashlib.sha256()
    if hasattr(file_stream_or_bytes, 'read'): 
        for chunk in iter(lambda: file_stream_or_bytes.read(4096), b""): hash_sha256.update(chunk)
        file_stream_or_bytes.seek(0)
    else: hash_sha256.update(file_stream_or_bytes)
    return hash_sha256.hexdigest()

@app.route('/documents')
@login_required
def documents_list():
    if current_user.role == 'admin': docs = Document.query.order_by(Document.upload_date.desc()).all()
    else: docs = Document.query.filter_by(user_id=current_user.id).order_by(Document.upload_date.desc()).all()
    return render_template('documents_list.html', documents=docs)

@app.route('/upload_document', methods=['GET', 'POST'])
@login_required
def upload_document():
    if request.method == 'POST':
        if 'file' not in request.files: flash('No file part.', 'danger'); return redirect(request.url)
        file = request.files['file']
        if file.filename == '': flash('No selected file.', 'danger'); return redirect(request.url)
        if file and allowed_file(file.filename):
            original_filename = secure_filename(file.filename)
            file_ext = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
            original_file_bytes = file.read(); file.seek(0) 
            original_filesize = len(original_file_bytes)
            file_hash_hex = calculate_sha256(original_file_bytes)
            file_hash_bytes = bytes.fromhex(file_hash_hex)
            salt = os.urandom(16); derived_key = derive_key(salt)
            ciphertext, nonce = encrypt_data(original_file_bytes, derived_key)
            signature_b64 = sign_data_hash(file_hash_bytes)
            if signature_b64 is None: flash('Error creating digital signature. Upload aborted.', 'danger'); return redirect(request.url)
            saved_filename = f"{uuid.uuid4().hex}.{file_ext}.enc" 
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], saved_filename)
            try:
                with open(file_path, 'wb') as f_enc: f_enc.write(ciphertext)
                encrypted_filesize = os.path.getsize(file_path)
                new_doc = Document(filename=original_filename, saved_filename=saved_filename, filesize=original_filesize, encrypted_filesize=encrypted_filesize, filetype=file_ext, user_id=current_user.id, sha256_hash=file_hash_hex, is_encrypted=True, encryption_salt=salt, encryption_nonce=nonce, digital_signature=signature_b64)
                db.session.add(new_doc); db.session.commit()
                record_audit_log("DOC_UPLOAD", details={"filename": original_filename, "size": original_filesize}, user_id=current_user.id, target_document_id=new_doc.id, status_code=200)
                flash(f"Doc '{original_filename}' uploaded, encrypted, and signed!", 'success'); return redirect(url_for('documents_list'))
            except Exception as e:
                db.session.rollback(); app.logger.error(f"Error uploading/encrypting/signing file: {e}")
                if os.path.exists(file_path):
                    try: os.remove(file_path)
                    except OSError as ose: app.logger.error(f"Error deleting partially uploaded file {file_path}: {ose}")
                flash('Error during upload/encryption/signing.', 'danger'); return redirect(request.url)
        else:
            ext_attempted = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'unknown'
            flash(f"File type '{ext_attempted}' not allowed. Allowed: {', '.join(ALLOWED_EXTENSIONS)}", 'danger'); return redirect(request.url)
    return render_template('upload_document.html')

@app.route('/download_document/<int:document_id>')
@login_required
def download_document(document_id):
    doc = Document.query.get_or_404(document_id)
    if doc.user_id != current_user.id and current_user.role != 'admin': flash('Permission denied.', 'danger'); return redirect(url_for('documents_list'))
    file_path_on_disk = os.path.join(app.config['UPLOAD_FOLDER'], doc.saved_filename)
    if not os.path.exists(file_path_on_disk): app.logger.error(f"Encrypted file not found: {file_path_on_disk}"); flash('File not found.', 'danger'); return redirect(url_for('documents_list'))
    status_code_for_log, response_size_for_log = 200, 0
    try:
        with open(file_path_on_disk, 'rb') as f_enc: ciphertext = f_enc.read()
        decrypted_data = ciphertext
        if doc.is_encrypted and doc.encryption_salt and doc.encryption_nonce:
            derived_key = derive_key(doc.encryption_salt)
            try: decrypted_data = decrypt_data(ciphertext, doc.encryption_nonce, derived_key)
            except Exception as e: app.logger.error(f"Decryption failed doc ID {doc.id}: {e}"); flash('Decryption failed. File may be corrupted/tampered.', 'danger'); record_audit_log("DOC_DOWNLOAD_DECRYPT_FAIL", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=500); return redirect(url_for('documents_list'))
        elif doc.is_encrypted: app.logger.error(f"Doc ID {doc.id} encrypted but missing salt/nonce."); flash('Cannot decrypt: missing metadata.', 'danger'); record_audit_log("DOC_DOWNLOAD_META_ERR", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=500); return redirect(url_for('documents_list'))
        response_size_for_log = len(decrypted_data)
        calculated_hash_hex = calculate_sha256(decrypted_data)
        if doc.sha256_hash and calculated_hash_hex != doc.sha256_hash:
            app.logger.warning(f"Integrity (SHA256) check failed DECRYPTED doc ID {doc.id}. Stored: {doc.sha256_hash}, Calc: {calculated_hash_hex}");
            flash('Warning: Document content integrity check (SHA256) failed after decryption!', 'warning')
            record_audit_log("DOC_DOWNLOAD_SHA_FAIL", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=status_code_for_log, response_size=response_size_for_log)
        if doc.digital_signature and SERVER_PUBLIC_KEY:
            calculated_hash_bytes = bytes.fromhex(calculated_hash_hex)
            if verify_data_signature(calculated_hash_bytes, doc.digital_signature, SERVER_PUBLIC_KEY):
                flash('Digital signature verified successfully.', 'success'); record_audit_log("DOC_DOWNLOAD_SIG_OK", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=status_code_for_log, response_size=response_size_for_log)
            else:
                flash('CRITICAL: Digital signature verification FAILED! The document or signature may have been tampered with.', 'danger'); record_audit_log("DOC_DOWNLOAD_SIG_FAIL", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=403) 
                return redirect(url_for('documents_list')) 
        elif doc.digital_signature and not SERVER_PUBLIC_KEY:
            flash('Digital signature present but server public key not loaded. Cannot verify.', 'warning'); record_audit_log("DOC_DOWNLOAD_SIG_NO_KEY", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=status_code_for_log, response_size=response_size_for_log)
        else: record_audit_log("DOC_DOWNLOAD", details={"filename": doc.filename}, user_id=current_user.id, target_document_id=doc.id, status_code=status_code_for_log, response_size=response_size_for_log)
        return Response(BytesIO(decrypted_data), mimetype='application/octet-stream', headers={"Content-Disposition": f"attachment;filename=\"{doc.filename}\""})
    except Exception as e:
        app.logger.error(f"Error during download/decryption for doc ID {doc.id}: {e}"); flash('Error preparing download.', 'danger'); record_audit_log("DOC_DOWNLOAD_ERROR", details={"filename": doc.filename, "error": str(e)}, user_id=current_user.id, target_document_id=doc.id, status_code=500); return redirect(url_for('documents_list'))

# --- Profile Page Route ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        new_name = request.form.get('name')
        if new_name and new_name != current_user.name:
            old_name = current_user.name; current_user.name = new_name
            try: db.session.commit(); record_audit_log("USER_PROFILE_UPDATE", details={"field": "name", "old_value": old_name, "new_value": new_name}, user_id=current_user.id); flash('Profile updated successfully!', 'success')
            except Exception as e: db.session.rollback(); app.logger.error(f"Error updating profile for user {current_user.id}: {e}"); flash('Error updating profile. Please try again.', 'danger')
        elif new_name == current_user.name: flash('No changes detected in name.', 'info')
        else: flash('Name cannot be empty.', 'warning')
        return redirect(url_for('profile')) 
    show_app_2fa = not current_user.oauth_provider 
    return render_template('profile.html', user=current_user, show_app_2fa=show_app_2fa)

# --- Admin Decorator and Panel Routes ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash("You do not have permission to access this page.", "danger"); return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin') 
@login_required
@admin_required 
def admin_panel():
    user_count = User.query.count(); document_count = Document.query.count()
    return render_template('admin_panel.html', user_count=user_count, document_count=document_count)

@app.route('/admin/users', methods=['GET'])
@login_required
@admin_required
def admin_users_list():
    users = User.query.order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/user/<int:user_id>/update_role', methods=['POST'])
@login_required
@admin_required
def admin_update_user_role(user_id):
    user_to_update = User.query.get_or_404(user_id)
    new_role, old_role = request.form.get('role'), user_to_update.role
    if current_user.id == user_to_update.id and new_role != 'admin': flash("Admins cannot remove their own admin role.", 'danger'); return redirect(url_for('admin_users_list'))
    if new_role in ['user', 'admin']:
        user_to_update.role = new_role
        try:
            db.session.commit(); record_audit_log("ADMIN_ROLE_CHANGE", details={"old_role": old_role, "new_role": new_role}, user_id=current_user.id, target_user_id=user_to_update.id)
            flash(f"User {user_to_update.email}'s role updated to {new_role}.", 'success')
        except Exception as e: db.session.rollback(); app.logger.error(f"Error updating role for user {user_to_update.email}: {e}"); flash('Error updating user role.', 'danger')
    else: flash('Invalid role selected.', 'warning')
    return redirect(url_for('admin_users_list'))

@app.route('/admin/audit_logs')
@login_required
@admin_required 
def admin_audit_logs():
    page = request.args.get('page', 1, type=int)
    logs_pagination = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(page=page, per_page=20) 
    return render_template('admin_audit_logs.html', logs_pagination=logs_pagination)

# --- Export Audit Logs Route ---
@app.route('/admin/audit_logs/export_csv')
@login_required
@admin_required
def export_audit_logs_csv():
    logs = AuditLog.query.order_by(AuditLog.timestamp.asc()).all()
    si = StringIO(); cw = csv.writer(si)
    header = ['Timestamp (UTC)', 'User ID', 'User Email', 'Action Type', 'Target User ID', 'Target User Email', 'Target Doc ID', 'IP Address', 'User Agent', 'Request Method', 'Resource Path', 'Referer', 'HTTP Version', 'Status Code', 'Response Size', 'Details']
    cw.writerow(header)
    for log in logs:
        user_email = log.user_acted.email if log.user_acted else 'N/A'
        target_user_email = log.user_targeted.email if log.user_targeted else 'N/A'
        cw.writerow([
            log.timestamp.strftime('%Y-%m-%d %H:%M:%S'), log.user_id if log.user_id else 'System', user_email,
            log.action_type, log.target_user_id if log.target_user_id else '', target_user_email if log.target_user_id else '',
            log.target_document_id if log.target_document_id else '', log.ip_address if log.ip_address else '',
            log.user_agent if log.user_agent else '', log.request_method if log.request_method else '',
            log.resource_path if log.resource_path else '', log.referer if log.referer else '',
            log.http_version if log.http_version else '', log.status_code if log.status_code is not None else '',
            log.response_size if log.response_size is not None else '', log.details if log.details else ''
        ])
    output = si.getvalue()
    record_audit_log("ADMIN_EXPORT_AUDIT_LOGS", user_id=current_user.id)
    return Response(output, mimetype="text/csv", headers={"Content-disposition": "attachment; filename=securedocs_audit_logs.csv"})

# --- Delete Document Route ---
@app.route('/delete_document/<int:document_id>', methods=['POST'])
@login_required
def delete_document(document_id):
    doc = Document.query.get_or_404(document_id)
    if doc.user_id != current_user.id and current_user.role != 'admin': flash('You do not have permission to delete this document.', 'danger'); return redirect(url_for('documents_list'))
    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.saved_filename)
        doc_filename_for_log = doc.filename 
        if os.path.exists(file_path): os.remove(file_path); app.logger.info(f"Deleted physical file: {file_path}")
        else: app.logger.warning(f"Physical file not found for deletion: {file_path} (Doc ID: {doc.id})")
        db.session.delete(doc); db.session.commit()
        record_audit_log("DOC_DELETE", details={"filename": doc_filename_for_log}, user_id=current_user.id, target_document_id=document_id)
        flash(f"Document '{doc_filename_for_log}' has been successfully deleted.", 'success')
    except Exception as e: db.session.rollback(); app.logger.error(f"Error deleting document ID {document_id}: {e}"); flash('An error occurred while trying to delete the document.', 'danger')
    return redirect(url_for('documents_list'))

# --- Admin Delete User Route ---
@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def admin_delete_user(user_id):
    user_to_delete = User.query.get_or_404(user_id)
    if user_to_delete.id == current_user.id:
        flash("You cannot delete your own account.", 'danger')
        return redirect(url_for('admin_users_list'))
    
    user_email_for_log = user_to_delete.email
    deletion_details = {"deleted_user_email": user_email_for_log}

    try:
        record_audit_log("ADMIN_ATTEMPT_DELETE_USER", details=deletion_details, user_id=current_user.id, target_user_id=user_id)
        docs_to_delete = list(user_to_delete.documents) 
        for doc in docs_to_delete: 
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.saved_filename)
            if os.path.exists(file_path):
                try: os.remove(file_path); app.logger.info(f"Admin: Deleted physical file {file_path} for user {user_email_for_log} during user deletion.")
                except OSError as ose: app.logger.error(f"Admin: Error deleting physical file {file_path} for user {user_email_for_log}: {ose}")
        
        AuditLog.query.filter_by(user_id=user_to_delete.id).update({"user_id": None})
        AuditLog.query.filter_by(target_user_id=user_to_delete.id).update({"target_user_id": None})
        
        db.session.delete(user_to_delete)
        db.session.commit()
        
        record_audit_log("ADMIN_DELETE_USER_SUCCESS", details=deletion_details, user_id=current_user.id, target_user_id=user_id)
        flash(f"User '{user_email_for_log}' and their associated documents have been deleted.", 'success')
    except Exception as e:
        db.session.rollback()
        exception_trace = traceback.format_exc()
        app.logger.error(f"Error deleting user {user_email_for_log}: {e}\nTraceback: {exception_trace}")
        record_audit_log("ADMIN_DELETE_USER_FAILED", details={"deleted_user_email": user_email_for_log, "error": str(e)}, user_id=current_user.id, target_user_id=user_id, exception_info=exception_trace)
        flash('An error occurred while trying to delete the user. Check logs for details.', 'danger')
    
    return redirect(url_for('admin_users_list'))

# --- Other Routes & Main ---
@app.before_request
def make_session_permanent(): session.permanent = True
# Removed Google and GitHub specific login start routes as they are not used

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER); print(f"Created upload folder: {UPLOAD_FOLDER}")
    
    ssl_context = None
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        ssl_context = (CERT_FILE, KEY_FILE)
        app.logger.info(f"Attempting to start HTTPS server with cert: {CERT_FILE}, key: {KEY_FILE}")
    else:
        app.logger.warning("SSL certificate or key not found. Starting in HTTP mode.")
        app.logger.warning(f"Looked for: {CERT_FILE} and {KEY_FILE}")

    with app.app_context():
        try:
            print("Flask-Migrate should be used to manage database schema.")
        except Exception as e:
            print(f"Error during app context setup: {e}")
            
    app.run(debug=True, port=5000, ssl_context=ssl_context)

