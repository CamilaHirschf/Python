from flask_login import LoginManager
from flask_login import login_required
from flask_security import Security, SQLAlchemyUserDatastore, UserMixin, RoleMixin
from flask import Flask, render_template, request
from flask_wtf import FlaskForm
from datetime import datetime
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from flask import Flask, request, session
import logging
import uuid
import os

logging.basicConfig(filename='app.log', filemode='w', format='%(name)s - %(levelname)s - %(message)s', level=logging.INFO)
# Configura Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# Configura Flask-Security
user_datastore = SQLAlchemyUserDatastore(db, User, Role)
security = Security(app, user_datastore)

class Role(db.Model, RoleMixin):
 id = db.Column(db.Integer(), primary_key=True)
 name = db.Column(db.String(80), unique=True)

class User(db.Model, UserMixin):
 id = db.Column(db.Integer, primary_key=True)
 email = db.Column(db.String(255), unique=True)
 password = db.Column(db.String(255))
 roles = db.relationship('Role', secondary=roles_users, backref=db.backref('users', lazy='dynamic'))
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

 #@app.before_request
 #def log_request_info():
   #session["ctx"] = {"request_id": str(uuid.uuid4())}
   #app.logger.info('"%s" "%s" "%s" "%s"', request.method, request.path, request.remote_addr, str(session["ctx"]))
   #app.logger.info('Headers: %s', request.headers)
   #app.logger.info('Body: %s', request.get_data())

 @app.route("/", methods=['GET', 'POST'])
 def index():
   logging.info('Index page accessed')
   form = MyForm()
   if form.validate_on_submit():
       logging.info('Form submitted successfully')
       return 'Success!'
   return render_template('index.html', form=form)

 @app.route("/")
 def hello():
  logging.info('Hello page accessed')
  return render_template('index.html')

 @app.route('/', methods=['GET'])
 def home():
   logging.info('Home page accessed')
   return 'Hello world'

 @app.route('/logout')
 @login_required
 def logout():
   logout_user()
   return redirect(url_for('index'))
 
 @app.route('/register', methods=['GET', 'POST'])
 def signup_user():
   if request.method == 'POST':
       email = request.form['email']
       password = request.form['password']
       user = User(email=email)
       user.set_password(password)
       db.session.add(user)
       db.session.commit()
       return redirect(url_for('login'))
   return render_template('register.html')

 @app.route('/login', methods=['GET', 'POST']) 
 def login_user():
   if request.method == 'POST':
       email = request.form['email']
       password = request.form['password']
       user = User.query.filter_by(email=email).first()
       if user and user.check_password(password):
           login_user(user)
           return redirect(url_for('dashboard'))
       else:
           flash('Invalid email or password')
   return render_template('login.html')

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




