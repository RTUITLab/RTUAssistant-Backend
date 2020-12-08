from app import app
from flask import Flask, flash, request, redirect, url_for, session, jsonify, render_template, make_response
import requests
import jwt
from os import environ 
import datetime
from .get_AMI import get_AMI
from requests_oauthlib import OAuth2Session
from .oauth import GitHubSignIn, OAuthSignIn

SECRET = environ.get('SECRET')
SCHEDULE_URL = environ.get('SCHEDULE_URL')
FRONT_URL = environ.get('FRONT_URL')

####
@app.route('/auth/login', methods=["POST", "GET", "OPTIONS"])
def login():
    req = request.get_json(force=True)
    secret = req['secret']
    fingerprint = req['fingerprint']
    status = ""
    user = login(secret)
    
    if user: #if secret exist
        if user.status == 'ok':
            status = 'ok'
            res = {"status": status}
            access_token = jwt.encode({'user_id': user.id, 
                                        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
                                        SECRET, algorithm='HS256')

            refresh_token = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=60)}, 
                                        SECRET, algorithm='HS256')
            
            res['access_token'] = encoded_jwt
            res['refresh_token'] = refresh_token
            user.update({'refresh_token': refresh_token, 'fingerprint': fingerprint})
            db.session.commit()

        elif user.status == 'account_suspended':
            status = 'error'
            error = 'account_suspended'
            res = {"status": status}
            res['error'] = error

    else:
        status = 'error'
        error = 'secret_incorrect'
        res = {"status": status}
        res['error'] = error

    response = jsonify(res)
    return make_response(response)

#############
@app.route('/auth/refresh_token', methods=["POST", "GET", "OPTIONS"])
def refresh_token():
    req = request.get_json(force=True)
    refresh_token = req['refresh_token']
    fingerprint = req['fingerprint']
    status = ""

    try:
        data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
        user_id = data["user_id"]
        user = get_user_by_pk(user_id)
        if user:
            if user.status == 'ok':
                error = user.refresh_allow(refresh_token, fingerprint)
                if error == 'ok':
                    status = 'ok'
                    res = {"status": status}
                    access_token = jwt.encode({'user_id': user.id, 
                                                'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
                                                SECRET, algorithm='HS256')

                    refresh_token = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=60)}, 
                                                SECRET, algorithm='HS256')
                    
                    res['access_token'] = encoded_jwt
                    res['refresh_token'] = refresh_token
                    user.update({'refresh_token': refresh_token})
                    db.session.commit()
                else:
                    status = 'error'
                    res = {"status": status}
                    res['error'] = error
            elif user.status == 'account_suspended':
                status = 'error'
                error = 'account_suspended'
                res = {"status": status}
                res['error'] = error
        else:
            status = 'error'
            error = 'internal_server_error'
            res = {"status": status}
            res['error'] = error
    # Signature has expired
    except jwt.ExpiredSignatureError:
        status = 'error'
        error = 'token_expired'
        res = {"status": status}
        res['error'] = error
    except jwt.DecodeError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error
    except jwt.InvalidSignatureError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error
    response = jsonify(res)
    return make_response(response)

###
@app.route('/auth/logout', methods=["POST", "GET", "OPTIONS"])
def logout():
    req = request.get_json(force=True)
    refresh_token = req['refresh_token']
    fingerprint = req['fingerprint']
    status = ""

    try:
        data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
        user_id = data["user_id"]
        user = get_user_by_pk(user_id)
        if user:
            if user.status == 'ok':
                error = user.refresh_allow(refresh_token, fingerprint)
                if error == 'ok':
                    status = 'ok'
                    res = {"status": status}
                    refresh_token = jwt.encode({'exp': datetime.datetime.utcnow()}, 
                                                SECRET, algorithm='HS256')
                    
                    user.update({'refresh_token': refresh_token})
                    db.session.commit()
                else:
                    status = 'error'
                    res = {"status": status}
                    res['error'] = error
            elif user.status == 'account_suspended':
                status = 'error'
                error = 'account_suspended'
                res = {"status": status}
                res['error'] = error
        else:
            status = 'error'
            error = 'internal_server_error'
            res = {"status": status}
            res['error'] = error
    # Signature has expired
    except jwt.ExpiredSignatureError:
        status = 'error'
        error = 'token_expired'
        res = {"status": status}
        res['error'] = error
    except jwt.DecodeError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error
    except jwt.InvalidSignatureError:
        status = 'error'
        error = 'internal_server_error'
        res = {"status": status}
        res['error'] = error

    data = jwt.decode(refresh_token, SECRET, algorithms=['HS256'])
    user_id = data["user_id"]
    user = get_user_by_pk(user_id)

@app.route('/get_schedule', methods=["POST"])
def get_schedule():
    try:
        print(SCHEDULE_URL+"/"+str(req["group"])+"/today"+str(req["day"]))
        r = requests.get(SCHEDULE_URL+"/"+str(req["group"])+"/"+str(req["day"])).json()
        return make_response(r)
    except:
        return make_response({"schedule": "Не найдено :("})

# @app.route('/get_ami', methods=["POST"])
# def get_ami():
#     get_AMI()

@app.route('/callback/<provider>')
def oauth_callback(provider):
    # if not current_user.is_anonymous():
    #     return redirect(url_for('index'))
    # oauth = OAuthSignIn.get_provider(provider)
    # print(type(oauth))
    # social_id, username, email = oauth.callback()
    # if social_id is None:
    #     flash('Authentication failed.')
    #     return redirect(url_for('FRONT_URL'))
    # user = User.query.filter_by(social_id=social_id).first()
    # if not user:
    #     user = User(social_id=social_id, nickname=username, email=email)
    #     db.session.add(user)
    #     db.session.commit()
    # login_user(user, True)
    return redirect(FRONT_URL)

@app.route('/authorize/<provider>')
def oauth_authorize(provider):
    oauth = OAuthSignIn.get_provider(provider)
    git = GitHubSignIn()
    url = git.service.get_authorize_url(
            scope='email',
            response_type='code',
            redirect_url=url_for('oauth_callback', provider='github',
                       _external=True))
    return make_response({'url':url})