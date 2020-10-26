from flask import Flask, redirect, render_template, url_for, request, make_response, jsonify, session
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, get_raw_jwt
from flask_jwt_extended.utils import decode_token
from flask_jwt_extended.view_decorators import jwt_refresh_token_required
from flask_session import Session
import requests
import json
from helper import epoch_utc_to_datetime
from http import cookiejar

app = Flask(__name__)
app.config["ENVIRONMENT"] = "development"
app.config["SECRET_KEY"] = "X8slQiQWkvC0Zytlrntx9NQB009oOOg5r5kiah68NkckksDyuguwkz0KCV9lK3P5"
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
jwt = JWTManager(app)

api_uri = "http://167.99.133.206:5000/auth"

@app.route('/index')
@app.route('/')
def index():
    return "index site Do Manh Dung"


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
            return jsonify(response.cookies.items())
            return "dang nhap thanh cong"
    return render_template('login.html')

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

@app.route("/protected/")
@jwt_required
def protected():
    return get_jwt_identity()
    token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpYXQiOjE2MDMzNzUzODgsIm5iZiI6MTYwMzM3NTM4OCwianRpIjoiNDJjYTk4ZTUtYzU3MS00M2VhLThhZTgtYzhkYWE3N2UyYjU5IiwiZXhwIjoxNjA1OTY3Mzg4LCJpZGVudGl0eSI6eyJpZCI6MSwidXNlcm5hbWUiOiJuZ3VhY29uMDEifSwidHlwZSI6InJlZnJlc2gifQ.rrzW7MdkfR5YrY1SRsCzPZsgEOCqVOVyjKK4nHkC1bQ"
    # return str(epoch_utc_to_datetime(decode_token(token)['exp']))
    return render_template('index.html')
        
@app.route('/view/<string:arg>', methods=["POST", "GET"])
def view(arg):
    # if "access_token" not in session or not session["access_token"]:
    #     return redirect(url_for('login'))
    # headers = {
    # "Authorization": "Bearer "+ session["access_token"]
    # }

    # return session["access_token"]
    protected_url = "http://192.168.1.16/{arg}/".format(arg=arg)


    response = requests.get(url=protected_url,headers=headers)
    
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
def users():
    users_uri = api_uri + "/users"
    response = requests.get(url=users_uri)
    return response.text

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)