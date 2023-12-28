from flask import Flask, jsonify, request, make_response
from werkzeug.security import generate_password_hash, check_password_hash
import os

app = Flask(__name__)

# Configuración de seguridad
app.config.update(
 SESSION_COOKIE_SECURE=True,
 SESSION_COOKIE_HTTPONLY=True,
 SESSION_COOKIE_SAMESITE='Lax',
)

# Ruta de registro
@app.route('/register', methods=['GET', 'POST'])
def signup_user():
 pass
 # Tu código para registrar al usuario va aquí

# Ruta de login
@app.route('/login', methods=['GET', 'POST']) 
def login_user():
 pass
 # Tu código para iniciar sesión va aquí

if __name__ == "__main__":
  app.run(debug=True)

