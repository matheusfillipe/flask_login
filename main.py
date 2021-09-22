#!/usr/bin/env python3
import os
from flask import Flask, redirect, render_template, request, send_from_directory, jsonify, flash, url_for, Response
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import check_password_hash

from users import User


from urllib.parse import urlparse, urljoin
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def create_app():
    app = Flask(__name__)
    app.config["DEBUG"] = True
    app.config['SECRET_KEY'] = b'whatshoulditbe'

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        return User.get(user_id)

    return app


app = create_app()
limiter = Limiter(
    app,
    key_func=get_remote_address,
)

@app.route('/login', methods=['POST'])
@limiter.limit("50/day;3/minute")
def login_post():
    username = request.form['username']
    password = request.form['password']
    remember = True if request.form.get('remember') else False
    for user_id, user in enumerate(User.get_users()):
        if user['username'] == username and check_password_hash(user['hash'], password):
            login_user(User.get(user_id), remember=remember)
            next = request.args.get('next')
            next = None if next == url_for("logout") else next
            return redirect(next or url_for('index'))
    flash('Please check your login details and try again.')
    return render_template('login.html')

@app.route('/login', methods=['GET'])
def login():
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response('<p>Logged out</p>')

@app.route("/")
@login_required
def index():
    return render_template('index.html')

def main():
    app.run(host="0.0.0.0")

if __name__ == "__main__":
    main()
