from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_wtf import Form
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask import Flask, request, session
import logging
import uuid
import os
from werkzeug.security import generate_password_hash

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.INFO)
users = [
 {'id': 1, 'username': 'user1', 'password': 'pass1'},
 {'id': 2, 'username': 'user2', 'password': 'pass2'},
 # Agrega más usuarios aquí
]

class User(UserMixin):
 def __init__(self, id, username, password):
  self.id = id
  self.username = username
  self.password = password

 def is_active(self):
     return True

class LoginForm(FlaskForm):
  username = StringField('Username')
  password = PasswordField('Password')

class MyForm(FlaskForm):
   username = StringField('Username', validators=[DataRequired()])
   password = PasswordField('Password', validators=[DataRequired()])
   submit = SubmitField('Submit')

def create_app():
 app = Flask(__name__)
 Talisman(app)
 app.config['SECRET_KEY'] = 'your-secret-key'
 csrf = CSRFProtect(app)
 # Configuración de Flask-Login
 login_manager = LoginManager()
 login_manager.init_app(app)
 login_manager.login_view = 'login'

 app.config.update(
 SESSION_COOKIE_SECURE=True,
 SESSION_COOKIE_HTTPONLY=True,
 SESSION_COOKIE_SAMESITE='Lax',
 )
 @app.route('/logout')
 @login_required
 def logout():
  logout_user()
  return redirect(url_for('login'))
                  
 @app.route('/', methods=['GET', 'POST'])
 def index():
  logging.info('Index page accessed')
  form = MyForm()
  if form.validate_on_submit():
      logging.info('Form submitted successfully')
      return 'Success!'
  return render_template('index.html', form=form)

 @login_manager.user_loader
 def load_user(user_id):
  # Busca al usuario en la lista de usuarios
  user_data = next((u for u in users if u['id'] == int(user_id)), None)
  if user_data is not None:
      return User(user_data['id'], user_data['username'], user_data['password'])
  else:
      return None
 
 @app.route('/register', methods=['GET', 'POST'])
 def signup_user():
  form = MyForm()
  if form.validate_on_submit():
   username = request.form.get('username')
   password = generate_password_hash(request.form.get('password'))
   new_user = User(len(users)+1, username, password)
   users.append(new_user.__dict__)
   print(users) # Imprime la lista de usuarios
   return redirect(url_for('dashboard'))
  return render_template('register.html', form=form)

 @app.route('/login', methods=['GET', 'POST'])
 def login():
  form = LoginForm()
  if form.validate_on_submit():
     # Busca al usuario en la lista de usuarios
     user = next((u for u in users if u['username'] == form.username.data), None)
     if user and user['password'] == form.password.data:
         # Inicia sesión del usuario
         user_instance = User(user['id'], user['username'], user['password'])
         login_user(user_instance)
         return redirect(url_for('dashboard'))
  return render_template('login.html', form=form)

 @app.route('/dashboard')
 def dashboard():
    # Aquí va el código para tu página de panel de control
    return render_template('dashboard.html')
 
 @app.after_request
 def apply_csp(response):
  nonce = os.urandom(16).hex()
  csp = f"default-src 'self'; script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'"
  response.headers["Content-Security-Policy"] = csp
  response.headers["Nonce"] = nonce
  response.headers['Server'] = ''
  timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S") # Agrega esta línea
  session["ctx"] = {"request_id": str(uuid.uuid4())}
  app.logger.info('%s - "%s" "%s" "%s" "%s"', timestamp, request.method, request.path, request.remote_addr, str(session["ctx"]))
  return response

 # Add StreamHandler to the application's logger
 stream_handler = logging.StreamHandler()
 app.logger.addHandler(stream_handler)

 return app





