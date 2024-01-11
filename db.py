from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin

db = SQLAlchemy()

class User(db.Model, UserMixin):
 __table_args__ = {'extend_existing': True}
 id = db.Column(db.Integer, primary_key=True)
 username = db.Column(db.String(30), unique=True, nullable=False)
 password_hash = db.Column(db.String(128))

 def set_password(self, password):
    self.password_hash = generate_password_hash(password)

 def check_password(self, password):
    return check_password_hash(self.password_hash, password)
