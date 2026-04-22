import os

from flask import Flask

from models import db, Client
from oauth import configure_oauth
from route import login_manager, bp, init_data

import logging
import sys

def update_env_variable(key, value):
    lines = []
    found = False

    try:
        with open(".env", "r") as f:
            for line in f:
                if line.startswith(f"{key}="):
                    lines.append(f"{key}=\"{str(value)}\"\n")
                    found = True
                else:
                    lines.append(line)
    except FileNotFoundError:
        pass

    if not found:
        lines.append(f"{key}=\"{str(value)}\"\n")

    with open(".env", "w") as f:
        f.writelines(lines)

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', '049qwmc-scweccvw883h04')
    SESSION_COOKIE_NAME = 'session_auth_server' # Ensure unique session cookie name
    # Error handling for database connection issues
    try:
        SQLALCHEMY_DATABASE_URI = os.environ.get(
            # Replace with your actual database URI and password if not using environment variable
            'DATABASE_URI', 'mysql+mysqlconnector://root:MySQL26!@localhost/ee368_oauth'
        )
    except Exception as e:
        print(f"Error occurred while connecting to database URI: {e}")
    
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    OAUTH2_TOKEN_EXPIRES_IN = 3600  # Token expiration time in seconds (1 hour)


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    login_manager.init_app(app)

    with app.app_context():
        db.create_all()
        init_data()
        client = Client.query.filter_by(client_id="client_123").first()
        update_env_variable('CUSTOM_CLIENT_ID', 'client_123')
        update_env_variable('CUSTOM_CLIENT_SECRET', client.client_secret)

    configure_oauth(app)
    app.register_blueprint(bp)
    log = logging.getLogger('authlib')
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.DEBUG)
    return app


if __name__ == '__main__':
    app = create_app()
    app.run(debug=True, port=5001)
