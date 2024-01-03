from flask import Flask

@app.route('/', methods=['GET'])
def create_app():
   app = Flask(__name__)

   # Configuración de seguridad
   app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
   )
   def hello():
   # Generate a new random nonce value for every response.
      nonce = os.urandom(16).hex()
   # Set the strict nonce-based CSP response header
      csp = f"default-src 'self'; script-src 'nonce-{nonce}'; object-src 'none'; base-uri 'none'"
      response = app.make_response(render_template_string("Hello World!"))
      response.headers["Content-Security-Policy"] = csp
      response.headers["Nonce"] = nonce
      return response
   
   @app.after_request
   def apply_caching(response):
      response.headers['X-Frame-Options'] = 'SAMEORIGIN'
      return response
   
   
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


