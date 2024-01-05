from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import os

class MyForm(FlaskForm):
   name = StringField('Name', validators=[DataRequired()])
   submit = SubmitField('Submit')

def create_app():
   app = Flask(__name__)
   Talisman(app)
   app.config['SECRET_KEY'] = 'your-secret-key'
   csrf = CSRFProtect(app)

   app.config.update(
       SESSION_COOKIE_SECURE=True,
       SESSION_COOKIE_HTTPONLY=True,
       SESSION_COOKIE_SAMESITE='Lax',
   )

   @app.route("/", methods=['GET', 'POST'])
   def index():
       form = MyForm()
       if form.validate_on_submit():
           return 'Success!'
       return render_template('index.html', form=form)

   @app.route("/")
   def hello():
     nonce = os.urandom(16).hex()
     csp = f"default-src 'self'; script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'"
     response = make_response(render_template('index.html'))
     response.headers["Content-Security-Policy"] = csp
     response.headers["Nonce"] = nonce
     return response


   @app.route('/', methods=['GET'])
   def home():
       return 'Hello world'

   @app.route('/register', methods=['GET', 'POST'])
   def signup_user():
       return 'Registration page'

   @app.route('/login', methods=['GET', 'POST']) 
   def login_user():
       return 'Login page'

   return app


