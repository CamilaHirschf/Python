from flask import Flask
from flask_wtf.csrf import CSRFProtect


def create_app():
   app = Flask(__name__)
   csrf = CSRFProtect(app)

   # Configuración de seguridad
   app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
   )
   
   @app.route('/', methods=['GET'])
   def home():
      return 'Hello world'
      
   # Ruta de registro
   @app.route('/register', methods=['GET', 'POST'])
   def signup_user():
      return 'Registration page'
    # Tu código para registrar al usuario va aquí
     

   # Ruta de login
   @app.route('/login', methods=['GET', 'POST']) 
   def login_user():
      return 'Login page'
    # Tu código para iniciar sesión va aquí
   

   return app


