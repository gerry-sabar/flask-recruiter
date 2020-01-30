from flask import Flask
from werkzeug.contrib.fixers import ProxyFix
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import (
    JWTManager,
)
from flask_cors import CORS
import psycopg2

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://flask:flask@localhost/flask_recruiter"
CORS(app)
db = SQLAlchemy(app)
db.init_app(app)

from models import user

migrate = Migrate(app, db)

# Setup the Flask-JWT-Extended extension
app.config['RESTPLUS_MASK_SWAGGER'] = False # remove default X-Fields field in swagger
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Change this!
app.config['JWT_BLACKLIST_ENABLED'] = True
app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']
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

if __name__ == "__main__":
  app.run(host='127.0.0.1', port=5000)