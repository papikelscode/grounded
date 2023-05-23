
import re
from flask import Flask, render_template, request, redirect, url_for,jsonify,abort
# from flask.json import jsonify
from flask_sqlalchemy import SQLAlchemy
import sqlite3
from werkzeug.security  import generate_password_hash, check_password_hash
from  flask_login import UserMixin, LoginManager, login_required, login_user, logout_user,current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
import os
#from flask_migrate import Migrate, MigrateCommand
#from flask_script import Manager
#from sys import argv

#from flask_mail import Mail
from random import randint
from datetime import datetime
#from flask_marshmallow import Marshmallow







#Position all of this after the db and app have been initialised


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname((__file__)))
database = "database.db"
con = sqlite3.connect(os.path.join(basedir,database))
#mail = Mail(app)
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'
# app.config['MAIL_SERVER'] = 'intexcoin.com'
# app.config['MAIL_PORT'] = 465
# app.config['MAIL_USERNAME'] = 'info@intexcoin.com'
# app.config['MAIL_SERVER'] = 'server148.web-hosting.com'

db = SQLAlchemy(app)

#migrate = Migrate(app, db,render_as_batch=True)
#manager = Manager(app)
#manager.add_command('db', MigrateCommand)



class AdminUsers(db.Model, UserMixin):
    id= db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(500), unique=True)
    email = db.Column(db.String(500), unique=True)
    password = db.Column(db.String(500), unique=True)
    is_admin = db.Column(db.Boolean, default = False)

    def create(self, username='', email='', password='',):
        self.username = username
        self.email = email
        self.password = password
        
    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()
class ModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    def not_auth(self):
        return "not allowed"        
        
admin = Admin(app, name='administration', template_mode='bootstrap3')
# admin.add_view(Secure(Users, db.session))
# admin.add_view(Secure(Settings, db.session))
# admin.add_view(Secure(Payments, db.session))
admin.add_view(ModelView(AdminUsers, db.session))

# admin.add_view(Secure(Transactions, db.session))

login_manager = LoginManager()
login_manager.login_view = "signin"
login_manager.init_app(app)
@login_manager.user_loader
def user_loader(user_id):
    return AdminUsers.query.get(user_id)












@app.route("/db")
def database():
    db.drop_all()
    db.create_all()
    return "Hello done!!!"
    

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8050, debug=True)