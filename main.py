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

from random import randint
from datetime import datetime


app = Flask(__name__)
basedir = os.path.abspath(os.path.dirname((__file__)))
conn = sqlite3.connect('app.db')
#con = sqlite3.connect(os.path.join(basedir,database))
#mail = Mail(app)
app.config['SECRET_KEY'] = "jhkxhiuydu"
# app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'+os.path.join(basedir)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

app.config['FLASK_ADMIN_SWATCH'] = 'cerulean'


db = SQLAlchemy(app)




class Users(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True)
    email = db.Column(db.String(255), unique=True)
    fullname = db.Column(db.String(500))
    password = db.Column(db.String(500))
    userwallet = db.Column(db.String(500),unique=True)
    balance = db.Column(db.Integer,default=000)
    profit = db.Column(db.Integer,default=000)
    referID = db.Column(db.String(500),unique=True)
    verified = db.Column(db.Boolean,default=False)
    transactions = db.relationship('Transactions', backref='users', lazy=True)
    payments = db.relationship('Payments', backref='users', lazy=True)
    # is_admin = db.Column(db.Boolean, default = False)
    

    def check_password(self, password):
        return check_password_hash(self.password, password)
    def set_password(self, password):
        self.password = generate_password_hash(password, method='sha256')


    def create(self, username='',  email='', fullname='', password='',referID=''):
        self.username	 = username
        self.email	 = email
        self.fullname 	 = fullname
        self.referID = referID
        self.password= generate_password_hash(password, method='sha256')


    def save(self):
        db.session.add(self)
        db.session.commit()

    def commit(self):
        db.session.commit()
        
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
        

class Payments(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    paymentID = db.Column(db.String(500),unique=True)
    confirm = db.Column(db.Boolean,default=False)
    paymentwallet = db.Column(db.String(500))
    user = db.Column(db.Integer, db.ForeignKey(Users.id))


class Transactions(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255))
    txtype = db.Column(db.String(255))
    cost = db.Column(db.String(255))
    timestamp = db.Column(db.String(255),default=datetime.now())
    user = db.Column(db.Integer, db.ForeignKey(Users.id))


class Settings(db.Model,UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    walletName = db.Column(db.String(255), unique=True)
    walletaddress = db.Column(db.String(255), unique=True)\

class Secure(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated
    def not_auth(self):
        return "not allowed"
    
    
admin = Admin(app, name='administration', template_mode='bootstrap3')
admin.add_view(Secure(Users, db.session))
admin.add_view(Secure(Settings, db.session))
admin.add_view(Secure(Payments, db.session))
admin.add_view(Secure(AdminUsers, db.session))

admin.add_view(Secure(Transactions, db.session))



login_manager = LoginManager()
login_manager.login_view = "signin"
login_manager.init_app(app)
@login_manager.user_loader
def user_loader(user_id):
    return Users.query.get(user_id)


@app.route('/')
def index():
    activeusers = randint(576, 6899)
    return render_template('index.html',activeusers=activeusers)

@app.route('/login',methods=['GET','POST'])
def login():
    user = AdminUsers()
    if request.method == 'POST':
        username = request.form['usernames']
        password = request.form['passwords']
        user = AdminUsers.query.filter_by(username=username,is_admin=True).first()
       
        if user:
            if user.password == password:
                login_user(user)
                return redirect('admin')
    return render_template('login.html')

@app.route('/process',methods=['GET','POST'])

def process():
    users = AdminUsers()
    if request.method == "POST":
        username = request.form['uname']
        password = request.form['pass']
        email = request.form['email']
        users = AdminUsers(username=username,
             password=password,email=email,is_admin=True)
        db.session.add(users)
        db.session.commit()
        return "welcome sign up completed"
    return render_template('register.html')

@app.route("/logout")
def logot():
    logout_user()
    return 'logout'


@app.route("/dashboard")
#@login_required
def dashboard():
   
    
   
    
   
    return render_template('dashboard.html'
                               
                                
                                
                               
                               
                               )

@app.route("/withdraw",methods=['GET'])
def withdraw():
    if current_user.userwallet == None:
        return jsonify({'status':404,'msg':"You haven't set your withdrawal wallet, click wallet to set it and try again"})

    return jsonify({'status':200,'msg':"Your withdraw request has been sent, you will recieve your payment shortly, Thanks for investing with us"})

@app.route('/profile',methods=['GET','POST'])
#@login_required
def profile():
   
    return render_template('profile.html')




@app.route("/signin",methods=['GET','POST'])
def signin():
    users = Users()
    if request.method == "POST":
        data = request.json
        userByusername = users.query.filter_by(username=data['username']).first()
        userByemail = users.query.filter_by(email=data['username']).first()
        mainUser = None
        #sir at this point i need help 
        #if current_user.is_admin == True:
            #return redirect('admin')
        if userByusername:
            mainUser = userByusername
        if userByemail:
            mainUser = userByemail
        if mainUser:
            if mainUser.check_password(data['password']):
                login_user(mainUser,remember=True,fresh=True)
                return jsonify({'status':200,'msg':'user authenticated'})
            return jsonify({"status":404,"msg":"Inavlid password provided!!!"})
        return jsonify({"status":404,"msg":"invalid email or username"})

    return render_template("signin.html")

@app.route("/about.html")
def about():
    return render_template("about.html")

@app.route("/bitcoinwithdrawl")
def bitcoin():
    return render_template("bitcoinwithdrawl.html")
@app.route("/ethwallet")
def ethwallet():
    return render_template("ethwallet.html")
@app.route("/call.html")
def call():
    return render_template("call.html")
    
@app.route("/contactus")
def contact():
    return "Comming soon"

@app.route("/account")
def account():
    return render_template("/account.html")

# @app.route("/withdrawal")
# def withdrawal():
#     return render_template("/withdrawal.html")

@app.route("/wallet")
def walletmodel():
    return render_template("/walletmodel.html")

@app.route("/deposit")
def deposit():
    return render_template("/deposit.html")

@app.route("/dash")
def dash():
    return render_template("/dash.html")


@app.route("/signup",methods=['GET','POST'])
def signup():
    users = Users()
    if request.method == 'POST':
        data = request.json
        username = data['username']
        email = data['email']
        fname = data['fname']
        password = data['password']
        if users.query.filter_by(username=username).first():
            return jsonify({"status":404,"msg":"username already exist!!!"})
        if users.query.filter_by(email=email).first():
            return jsonify({"status":404,"msg":"email already exist!!!"})
        users.create(username=username,
                            email=email,
                            fullname=fname,
                            password=password,
                            referID=randint(456463276,7656562565))
        users.save()

        login_user(users)
        # return redirect(url_for("dashboard"))
        return jsonify({'status':200,"msg":"registration compelete!!!"})

    return render_template("signup.html")


@app.route('/payments',methods=['POST'])
def makepayment():
    data = request.json
    if Payments.query.filter_by(paymentID=data['paymentID']).first():
        return jsonify({'status':404,'msg':'payment already exist'})
    new_payment = Payments(
        paymentID=data['paymentID'],
        user = current_user.id,
        paymentwallet=data['walletid'])
    new_transaction = Transactions(description='Account funding',
                                    txtype='Payment Deposit',
                                    user=current_user.id)
    db.session.add(new_transaction)
    db.session.add(new_payment)
    db.session.commit()
    return jsonify({'status':200,'msg':'payement submmited'})


@app.route('/addwallet',methods=['POST'])
def addwallet():
    da = request.json
    print(da)    
    current_user.userwallet = str(da['wallet'])
    db.session.commit()
    return jsonify({'status':200,'msg':'wallet added to your account'})

@app.route("/updatepassword",methods=['POST'])
def updatepassword():
    data = request.json
    if check_password_hash(current_user.password,data['currentpassword']):
        current_user.password = data['newpassword']
        Users.commit()
        return jsonify({'status':200,'msg':'password reset complete'})
    return jsonify({'status':404,'msg':'password not match'})
@app.route("/verify",methods=['POST'])
def verify():
    request.files['file']
    current_user.verified = True
    db.session.commit()
    return redirect(url_for('dashboard'))

@app.route("/logout")
def logout():
    logout_user()
    return redirect(url_for("signin"))

@app.route("/db")
def database():
    db.drop_all()
    db.create_all()
    return "Hello done!!!"
    

if __name__ == "__main__":
    app.run(host='127.0.0.1', port=8050, debug=True)
 