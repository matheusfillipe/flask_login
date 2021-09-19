# Flaks login demo

My simple demo of how to use [flask_login](https://flask-login.readthedocs.io/en/latest/) module without the need of a database or anything fancy. I also tried to implement an ip based limiter on the `login` route to try to avoid bruteforce based attacks. 

## Usage

``` sh
# install dependencies
pip install flask flask-login Flask-Limiter

# Add users
./users.py

# run
flask run
# or
python3 main.py

```
The users folder will be created where each user get his file on the format: `{username}.hash` which containing his hashed password.
