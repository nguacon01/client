import http
from flask import Flask, redirect, render_template, url_for, request, make_response, jsonify, session
from flask import helpers
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_raw_jwt
from flask_jwt_extended.utils import decode_token
from flask_jwt_extended.view_decorators import jwt_refresh_token_required
from flask_session import Session
import requests
import json
from helpers import epoch_utc_to_datetime, decorator_is_exp_token
import schedule
import time

app = Flask(__name__)
app.config["FLASK_ENV"] = "development"
app.config["SECRET_KEY"] = "X8slQiQWkvC0Zytlrntx9NQB009oOOg5r5kiah68NkckksDyuguwkz0KCV9lK3P5"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
jwt = JWTManager(app)

<<<<<<< HEAD
api_uri = "http://10.18.0.24:8080/auth"
=======
api_uri = "http://167.99.133.206:5000/auth"
>>>>>>> 5a9d0ed5ad16d69832f6e49c00afb8044897c18b

@app.route('/index')
@app.route('/')
def index():
<<<<<<< HEAD
    return "client site run on docker"
=======
    return "index site Do Manh Dung"
>>>>>>> 5a9d0ed5ad16d69832f6e49c00afb8044897c18b


@app.route('/login', methods=["POST","GET"])
def login():
    url_login = api_uri + "/login"
    if request.method == "POST":
        email = request.form.get("email", None)
        password = request.form.get("password", None)
        login_dict = {
            "email":email,
            "password":password
        }
        headers = {
            "dataType":"application/json"
        }
        response = requests.post(url=url_login, json=login_dict, headers=headers)
        if response.status_code == 201:
<<<<<<< HEAD
            res_content = json.loads(response.content)
            session["access_token"] = res_content["access_token"]
            session["refresh_token"] = res_content["refresh_token"]
            session["can_refresh"] = True
            decode_tk = decode_token(res_content["access_token"])
            during = epoch_utc_to_datetime(decode_tk["exp"]) - epoch_utc_to_datetime(decode_tk["iat"])
            return redirect(url_for('index'))
        else:
            return render_template("login.html")
    return render_template("login.html")
=======
            return jsonify(response.cookies.items())
            return "dang nhap thanh cong"
    return render_template('login.html')
>>>>>>> 5a9d0ed5ad16d69832f6e49c00afb8044897c18b

@app.route('/signup/', methods=["POST","GET"])
def signup():
    url_signup = api_uri + "/signup/"
    if request.method == "POST":
        email = request.form.get("email", None)
        password = request.form.get("password", None)
        username = request.form.get("username", None)
        signup_dict = {
            "email":email,
            "password":password,
            "username":username
        }
        headers = {
            "dataType":"application/json"
        }

        response = requests.post(url=url_signup, json=signup_dict, headers=headers)
        return str(response.text)
        if response.status == "success":
            return "signup successfully"
            
    return render_template('signup.html')

@app.route('/logout/', methods=["POST", "GET"])
def logout():
    if "access_token" not in session or not session["access_token"]:
        return redirect(url_for('login'))
    if "refresh_token" not in session or not session["refresh_token"]:
        return "User has been logged out"
    
    
    refresh_token = session['refresh_token']
    url_logout = api_uri + "/logout/"
    headers = {
        "Authorization":"Bearer {}".format(refresh_token)
    }
    response = requests.delete(url=url_logout, headers=headers)
    response_cont = json.loads(response.text)

    return response_cont

    if response_cont["status"] != 201:
        return "error"
    else:
        res = make_response(jsonify({"msg":"logged out successfully"}))

        return res
        
@app.route('/view/<string:arg>', methods=["POST", "GET"])
def view(arg):
    # if "access_token" not in session or not session["access_token"]:
    #     return redirect(url_for('login'))
    # headers = {
    # "Authorization": "Bearer "+ session["access_token"]
    # }

    # return session["access_token"]
    protected_url = "http://192.168.1.16/{arg}/".format(arg=arg)


    response = requests.get(url=protected_url)
    
    if response.status_code == 200:
        response_cont = response.text
        return response_cont
    else:
        if session["refresh_token"]:
            refresh_url = "http://192.168.1.16:8080/auth/refresh_token/"
            ref_headers = {
                "Authorization": "Bearer "+ session["refresh_token"]
            }
            ref_reponse = requests.post(url=refresh_url, headers=ref_headers)
            ref_reponse_cont = ref_reponse.json()
            if ref_reponse_cont["status"] != "success":
                return redirect(url_for('login'))
            session["access_token"] = ref_reponse_cont["access_token"]
            return response.json()

@app.route("/users")
@decorator_is_exp_token
def users():
    session = requests.Session()
    users_uri = api_uri + "/users"
    response = requests.get(url=users_uri)
    return response.text


def silent_refresh(refresh_token, at_time):
    url_refresh = api_uri + "/refresh_token"
    try:
        headers = {
            "Authorization": "Bearer "+ session["refresh_token"]
        }

        res = requests.post(url_refresh, headers)
        return res.text
    except Exception:
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)