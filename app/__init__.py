from flask import Flask
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate, MigrateCommand
from os import environ 
from flask_login import LoginManager, UserMixin

from sqlalchemy import Table, Column, Integer, String, ForeignKey


app = Flask(__name__)
CORS(app)

app.config['SQLALCHEMY_DATABASE_URI'] =  environ.get('DBURL')
SECRET = environ.get('SECRET')
db = SQLAlchemy(app)
migrate = Migrate(app, db)
app.config['OAUTH_CREDENTIALS'] = {
    'github': {
        'id': environ.get('GIT_ID'),
        'secret': environ.get('GIT_SECRET')
    }
}
db = SQLAlchemy(app)
lm = LoginManager(app)

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    social_id = db.Column(db.String(64), nullable=False, unique=True)
    nickname = db.Column(db.String(64), nullable=False)
    email = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String())
    refresh_token = db.Column(db.String())
    def refresh_allow(self, refresh_token, fingerprint):
        if (refresh_token == self.refresh_token):
            if fingerprint == self.fingerprint:
                return 'ok'
            return 'fingerprint_error'
        return 'internal_server_error'######


@lm.user_loader
def load_user(id):
    return User.query.get(int(id))

# class UserModel(db.Model):
#     __tablename__ = 'User'
#     id = db.Column(db.Integer, primary_key=True)
#     fingerprint = db.Column(db.String())
#     # login = db.Column(db.String())
#     secret = db.Column(db.String())
#     status = db.Column(db.String())
#     refresh_token = db.Column(db.String())

    # def __repr__(self):
    #     return f"<User {self.login}>"

    # def set_password(self, password):
    #     self.password_hash = generate_password_hash(password)

    # def check_password(self, password):
    #     return check_password_hash(self.password_hash, password)

    # def __init__(self, login, password):
    #     self.login = login
    #     self.password_hash = set_password(password)
    # def refresh_allow(self, refresh_token, fingerprint):
    #     if (refresh_token == self.refresh_token):
    #         if fingerprint == self.fingerprint:
    #             return 'ok'
    #         return 'fingerprint_error'
    #     return 'internal_server_error'######
        

def get_user_by_pk(pk):
    return db.session.query(User).get(pk)

# def login(secret):
#     # user = db.session.query(UserModel).filter_by(login=login).first()
#     # if user and user.check_password(password):
#     #     return db.session.query(UserModel).get(pk)
#     return db.session.query(User).filter_by(secret=secret).first()
    


from app import views
