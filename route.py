import time

from authlib.integrations.flask_oauth2 import current_token
from flask import Blueprint, request, redirect, jsonify
from flask_login import LoginManager, login_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash, gen_salt

from models import Client, User, db
from oauth import auth_server, require_oauth

bp = Blueprint('auth', __name__)

login_manager = LoginManager()
login_manager.login_view = "auth.login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


def init_data():
    user = User.query.filter_by(email="clarkson@gmail.com").first()
    if not user:
        user = User()
        user.name = "Clarkson University"
        user.email = "clarkson@gmail.com"
        user.password = generate_password_hash("Cu2026!")

        db.session.add(user)
        db.session.commit()

    client = Client.query.filter_by(client_id="client_123").first()
    if not client:
        client = Client()
        client.client_id = "client_123"
        client.client_secret = gen_salt(48)
        client.client_id_issued_at = time.time()
        client.client_secret_expires_at = 0  # never expires
        client.set_client_metadata({
            "redirect_uris": ["http://127.0.0.1:5000/login/custom"],
            "response_types": ["code", "token"],
            "scope": "profile",
            "grant_types": ["authorization_code"],
            "client_name": "My Example Client",
            "token_endpoint_auth_method": "client_secret_basic",
            "logo_uri": "https://cdn.freebiesupply.com/logos/large/2x/united-states-of-america-logo-png-transparent.png",
        })
        db.session.add(client)
        db.session.commit()

    return user, client


@bp.route('/oauth/authorize', methods=['GET', 'POST'])
@login_required
def authorize():
    if request.method == 'GET':
        grant = auth_server.get_consent_grant(end_user=current_user)
        return (f"<h1>Authorization Request</h1>"
                f"<form method='post'> "
                f"<img src='{grant.client.logo_uri}' width='200px' alt='Client Logo'/><br/>"
                f"<h3>{grant.client.client_name} ({grant.client.client_id}) want to access your resources</h3>"
                f"<button type='submit' name='approve' value='1'>Approve</button>"
                f"<button type='submit' name='deny' value='1'>Deny</button>"
                f"</(form>")
    else:  # POST
        grant_user = current_user if 'approve' in request.form else None
        return auth_server.create_authorization_response(grant_user=grant_user)


@bp.route('/oauth/token', methods=['POST'])
def issue_token():
    return auth_server.create_token_response()


@bp.route('/oauth/userinfo')
@require_oauth('profile')
def userinfo():
    user = User.query.get(current_token.user_id)
    return jsonify({
        'name': user.name,
        'email': user.email,
        'picture': 'https://upload.wikimedia.org/wikipedia/en/f/f1/Clarkson-seal.png'
    })


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(request.args.get('next') or '/')
        return 'Invalid credentials', 401
    return (f"<h1>Login</h1>"
            f"<form method='post'>"
            f"<label>Email: <input type='text' name='email'></label><br>"
            f"<label>Password: <input type='password' name='password'></label><br>"
            f"<button type='submit'>Login</button>"
            f"</form>")
