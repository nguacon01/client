from flask import Flask, make_response, redirect, jsonify, request
from flask.globals import session
from flask.helpers import url_for
from flask_jwt_extended import verify_jwt_in_request, decode_token
from functools import wraps
from datetime import datetime

def epoch_utc_to_datetime(timestamp):
    """ converts epoch timestamp to datetime format"""
    return datetime.fromtimestamp(timestamp)

def is_expired_token(token):
    decode_tk = decode_token(token)
    exp = epoch_utc_to_datetime(decode_token["exp"])
    if exp < datetime.now():
        return True
    return False

def decorator_is_exp_token(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            decode_tk = decode_token(session['refresh_token'])
            exp = epoch_utc_to_datetime(decode_tk["exp"])
            if exp < datetime.now():
                return func(*args, **kwargs)
            return redirect(url_for('login'))    
        except:
            return redirect(url_for('login'))  
    return wrapper