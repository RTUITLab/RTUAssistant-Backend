from app import app, db
from flask import Flask, flash, request, redirect, url_for, session, jsonify, render_template, make_response
import requests
import jwt
from os import environ 
import datetime
from .get_AMI import get_AMI
from requests_oauthlib import OAuth2Session
from .oauth import GitHubSignIn, OAuthSignIn, OAuth2Service
from .models import User
import json

SECRET = environ.get('SECRET')
SCHEDULE_URL = environ.get('SCHEDULE_URL')
FRONT_URL = environ.get('FRONT_URL')

####
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
                    
                    res['access_token'] = access_token
                    res['refresh_token'] = refresh_token
                    user.refresh_token = refresh_token
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
                    
                    user.refresh_token = refresh_token
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
        req = request.get_json(force=True)
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
    git = GitHubSignIn()
    uri = url_for('oauth_callback', provider='github', _external=True)
                
    session = git.service.get_auth_session(data={
                'code': request.args.get('code'), 
                'grant_type': 'authorization_code',
                'redirect_uri': 'http://127.0.0.1:5000/callback/github'})
    client_id = session.client_id
    if client_id is None:
        url = FRONT_URL+ "/index"
        return redirect(url)
    user = User.query.filter_by(social_id=client_id).first()
    if user: #if exist
        if user.status == 'ok':
            status = 'ok'
            res = {"status": status}

            refresh_token = jwt.encode({'exp': datetime.datetime.utcnow() + datetime.timedelta(days=60)}, 
                                         SECRET, algorithm='HS256')
            print(refresh_token)
            user.refresh_token = str(refresh_token)
            db.session.commit()

        elif user.status == 'account_suspended':
            status = 'error'
            error = 'account_suspended'
            res = {"status": status}
            res['error'] = error

    else:
        status = 'error'
        error = 'user_incorrect'
        res = {"status": status}
        res['error'] = error
    
    
    # requests.post(FRONT_URL+"/after_login", json=res)
    if res['status'] == 'error':
        return ""
    return redirect(FRONT_URL+ "/after_login")


@app.route('/authorize/<provider>')
def oauth_authorize(provider):
        uri = url_for('oauth_callback', provider='github', _external=True)
        req = request.get_json(force=True)
        oauth = OAuthSignIn.get_provider(provider)
        git = GitHubSignIn()
        fingerprint = req['fingerprint']
        secr = req['secret']
        user = User.query.filter_by(secret=secr).first()
        #, log_in=False
        if user:
            url = git.service.get_authorize_url(
                scope='read_stream',
                response_type='code',
                redirect_uri='http://127.0.0.1:5000/callback/github'
                )
            user.fingerprint = fingerprint
            db.session.commit()
            return make_response({'url':url, 'err':'ok'})
        else:
            return make_response({'err':'not_exist'})



@app.route('/after_login')
def after_login():
    req = request.get_json(force=True)
    print(0)
    fingerprint = req['fingerprint']
    secret = req['secret']
    user = User.query.filter_by(secret=secret, fingerprint=fingerprint).first()
    print(1)
    res = {}
    if user:
        if user.refresh_token!="":
            status = 'ok'
            res = {"status": status}
            access_token = jwt.encode({'user_id': user.id, 
                                         'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, 
                                         SECRET, algorithm='HS256')
            res['access_token'] = str(access_token)
            res['refresh_token'] = user.refresh_token
            user.log_in =True
            print(2)
            db.session.commit()
        else:
            status = 'error'
            error = 'user_incorrect'
            res = {"status": status}
            res['error'] = error
    else:
        status = 'error'
        error = 'user_incorrect'
        res = {"status": status}
        res['error'] = error
    print(res)
    response = jsonify(res)
    print(3)
    return make_response(response)

