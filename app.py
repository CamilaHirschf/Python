from flask import Flask, render_template, request, redirect, url_for
from flask_login import LoginManager, UserMixin, login_required, login_user, logout_user
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import Form
from werkzeug.security import check_password_hash
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired
from datetime import datetime
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
import logging
import uuid
import os
from werkzeug.security import generate_password_hash

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.INFO)


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

 app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
 db = SQLAlchemy(app)

 login_manager = LoginManager()
 login_manager.init_app(app)
 login_manager.login_view = 'login'

 class User(db.Model, UserMixin):
   id = db.Column(db.Integer, primary_key=True)
   username = db.Column(db.String(30), unique=True, nullable=False)
   password_hash = db.Column(db.String(128))

   def set_password(self, password):
       self.password_hash = generate_password_hash(password)

   def check_password(self, password):
       return check_password_hash(self.password_hash, password)

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
   return User.query.get(int(user_id))

 @app.route('/register', methods=['GET', 'POST'])
 def signup_user():
    form = MyForm()
    if form.validate_on_submit():
        username = request.form.get('username')
        password = generate_password_hash(request.form.get('password'))
        new_user = User(username=username, password_hash=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

 @app.route('/login', methods=['GET', 'POST'])
 def login():
  form = LoginForm()
  if form.validate_on_submit():
      user = User.query.filter_by(username=form.username.data).first()
      if user and user.check_password(form.password.data):
          login_user(user)
          return redirect(url_for('dashboard'))
  return render_template('login.html', form=form)

 @app.route('/dashboard')
 @login_required
 def dashboard():
   return render_template('dashboard.html')

 @app.after_request
 def apply_csp(response):
    nonce = os.urandom(16).hex()
    csp = f"default-src 'self'; script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'"
    response.headers["Content-Security-Policy"] = csp
    response.headers["Nonce"] = nonce
    response.headers['Server'] = ''
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    session["ctx"] = {"request_id": str(uuid.uuid4())}
    app.logger.info('%s - "%s" "%s" "%s" "%s"', timestamp, request.method, request.path, request.remote_addr, str(session["ctx"]))
    return response

 stream_handler = logging.StreamHandler()
 app.logger.addHandler(stream_handler)

 with app.app_context():
  db.create_all()

 return app
