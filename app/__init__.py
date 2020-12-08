from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from os import environ 

from sqlalchemy import Table, Column, Integer, String, ForeignKey
from flask_login import LoginManager

app = Flask(__name__)


app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://postgres:mysecretpassword@localhost:5433/postgres'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
SECRET = environ.get('SECRET')
db = SQLAlchemy(app)
lm = LoginManager(app)

from app import views, models

migrate = Migrate(app, db)
app.config['OAUTH_CREDENTIALS'] = {
    'github': {
        'id': environ.get('GIT_ID'),
        'secret': environ.get('GIT_SECRET')
    }
}




