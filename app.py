from flask import Flask
from werkzeug.contrib.fixers import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager,
)
from flask_cors import CORS
import psycopg2
from flask_login import login_user, login_required, LoginManager, logout_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://flask:flask@localhost/flask_recruiter"
CORS(app)
db = SQLAlchemy(app)
db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)

from models import user
from models.user import UserApi

migrate = Migrate(app, db)

# Setup the Flask-JWT-Extended extension
app.config['RESTPLUS_MASK_SWAGGER'] = False # remove default X-Fields field in swagger
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
app.config["SECRET_KEY"] = "OCML3BRawWEUeaxcuKHLpw"
jwt = JWTManager(app)

app.wsgi_app = ProxyFix(app.wsgi_app)

from endpoints import api
api.init_app(app)


@app.cli.command("seeder")
def seed():
    from faker import Faker
    from models.user import UserApi

    fake = Faker()
    for x in range(3):
        UserApi.seed(fake)

@app.route('/login')
def user_login():
    user =  UserApi.query.first()
    login_user(user)
    return 'login'

@app.route('/authenticated')
@login_required
def user_authenticated():
    return 'user is login!'

@app.route('/logout')
def user_logout():
    logout_user()
    return 'logout!'

@login_manager.unauthorized_handler
def unauthorized():
    # do stuff
    return 'unauthorized'

if __name__ == "__main__":
  app.run(host='127.0.0.1', port=5000)