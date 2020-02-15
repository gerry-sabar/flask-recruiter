from flask import Flask, url_for, redirect
from werkzeug.contrib.fixers import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager,
)
from flask_cors import CORS
import json
from flask_login import login_user, LoginManager

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://postgres:root@localhost/flask_recruiter"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
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

from auth.auth import auth_bp
app.register_blueprint(auth_bp)
from admin.admin import admin_bp
app.register_blueprint(admin_bp)

from endpoints import blueprint as api
app.register_blueprint(api, url_prefix='/api/v1')


def has_no_empty_params(rule):
    defaults = rule.defaults if rule.defaults is not None else ()
    arguments = rule.arguments if rule.arguments is not None else ()
    return len(defaults) >= len(arguments)

@app.cli.command("seeder")
def seed():
    from faker import Faker
    from models.user import UserApi

    fake = Faker()
    for x in range(3):
        UserApi.seed(fake)

@app.route('/testing')
def testing():
    from faker import Faker
    fake = Faker()
    from datetime import datetime
    me = UserApi(email = fake.email(),
            password = 'password',
            created_at = datetime.now())
    db.session.add(me)
    db.session.commit()
    return 'testing'


@app.route('/login')
def user_login():
    user =  UserApi.query.first()
    login_user(user)
    return 'login'

@app.route("/site-map")
def site_map():
    links = []
    for rule in app.url_map.iter_rules():
        # Filter out rules we can't navigate to in a browser
        # and rules that require parameters
        if "GET" in rule.methods and has_no_empty_params(rule):
            url = url_for(rule.endpoint, **(rule.defaults or {}))
            #links.append((url, rule.endpoint))
            #links.update({'link': url})
            links.append(url)
    return json.dumps(links)
    # links is now a list of url, endpoint tuples

@login_manager.unauthorized_handler
def unauthorized():
    return redirect('/login')

@login_manager.user_loader
def load_user(user_id):
    return UserApi.query.get(user_id)

"""
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
"""

if __name__ == "__main__":
  app.run(host='127.0.0.1', port=5000)