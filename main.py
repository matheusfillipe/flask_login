#!/usr/bin/env python3
import os
from flask import Flask, redirect, render_template, request, send_from_directory, jsonify, flash, url_for, Response
from flask_login import LoginManager, login_required, login_user, logout_user
from flask_mobility import Mobility
from werkzeug.security import check_password_hash

from ampf_report import ampf_report_init, get_t, get_ampf_refresh, process_form
from users import User


from urllib.parse import urlparse, urljoin
def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

def create_app():
    app = Flask(__name__, static_folder='data', static_url_path='/data')
    app.config["DEBUG"] = True
    app.config['SECRET_KEY'] = b'whatshoulditbe'

    login_manager = LoginManager()
    login_manager.login_view = "login"
    login_manager.init_app(app)

    @login_manager.user_loader
    def load_user(user_id):
        app.logger.debug(f"load_user: {user_id}")
        return User.get(user_id)

    Mobility(app)

    return app


app = create_app()

@app.route('/login', methods=['GET', 'POST'])
def login():
    # TODO ip hit limiting
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        remember = True if request.form.get('remember') else False
        for user_id, user in enumerate(User.users):
            if user['username'] == username and check_password_hash(user['hash'], password):
                login_user(User.get(user_id), remember=remember)
                next = request.args.get('next')
                return redirect(next or url_for('index'))
        flash('Please check your login details and try again.')
    return render_template('login.html')

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return Response('<p>Logged out</p>')

# ----------------------------------------------------------------------------------------------------

@app.route('/')
@login_required
def index():
    return Response("Hello World!")

def main():
    app.run()


if __name__ == "__main__":
    main()
