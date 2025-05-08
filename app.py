from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, send_file
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet
from flask_cors import CORS
from functools import wraps
from datetime import datetime, timezone, timedelta
from time import sleep
import sqlite3

#Initialise the flask app, socketIO and CORS
app = Flask(__name__, static_folder="/home/eson/timezone_static", static_url_path="/static")
app.secret_key = "super_duper_secret_key"
socketio = SocketIO(app)
CORS(app)

#Inistialize the login manager
login_manager = LoginManager()
login_manager.login_view = 'login'
login_manager.init_app(app)

#Database path
database = "TimeZone.db"

#Create database connection
def db_connect():
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    return conn

#User class for Flask-Login
class User(UserMixin):
    def __init__(self, row):
        self.id             = row['id']
        self.username       = row['username']
        self.password       = row['password']
        self.name           = row['name']
        self.lastname       = row['lastname']
        self.password       = row['password']
        self.email          = row['email']
        self.salary         = row['salary']
        self.hourly_rate    = row['hourly_rate']
        self.role           = row['role']
    
    #Check if user is sysadmin
    @property
    def is_sysadmin(self):
        return self.role == 'sysadmin'

    #Check if user is org admin
    @property
    def is_org_admin(self):
        return self.role == 'org_admin'

    #Check if user is employee
    @property
    def is_employee(self):
        return self.role == 'employee'

#Load selected user from database
@login_manager.user_loader
def load_user(user_id):
    conn = db_connect()
    row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None

#Send unauthorized response if user tries to connect to API endpoints, but is not logged in
@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith('/api/'):
        return jsonify({"Status": "Error 401", "Message": "Unauthorized access attempted, please login"}), 401
    elif request.path.startswith('/'):
        return render_template("forbidden.html"), 403

#Decorator, only allow sysadmin access
def sysadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_sysadmin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)
    return decorated_function

#Decorator, only allow org admin access
def org_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_org_admin or current_user.is_sysadmin):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

############################################# WEBSITE ROUTES BELOW #############################################

#Index
@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html')

#Meet the team
@app.route('/team')
def team():
    return render_template('team.html')

#Contact
@app.route('/contact')
def contact():
    return render_template('contact.html')

#Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated and current_user.is_employee:
        return render_template('dashboard.html')
    elif current_user.is_authenticated and current_user.is_org_admin:
        return render_template('orgadmin_dashboard.html')
    elif current_user.is_authenticated and current_user.is_sysadmin:
        return render_template('sysadmin_dashboard.html')
    else:
        return render_template('forbidden.html')

#Dashboard
@app.route('/admin')
@login_required
def admin():
    if current_user.is_authenticated and current_user.is_org_admin:
        return render_template('orgadmin_admin.html')
    elif current_user.is_authenticated and current_user.is_sysadmin:
        conn = db_connect()
        users = conn.execute('SELECT * FROM users').fetchall()
        return render_template('admin.html', users=users)
    else:
        return render_template('forbidden.html')

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        conn = db_connect()
        row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()

        if row and check_password_hash(row['password'], password):
            user = User(row)
            login_user(user)
            flash('Logged in successfully.', 'success')
            next_page = request.args.get('next') or url_for('index')
            return redirect(next_page)
        else:
            flash('Invalid username or password.', 'danger')

    return render_template('login.html')

#Logout
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/manifest.json')
def serve_manifest():
    return send_file('manifest.json', mimetype='application/manifest+json')

@app.route('/sw.js')
def serve_sw():
    return send_file('sw.js', mimetype='application/javascript')

#Config, app runs locally on port 5000. NGINX proxies outisde requests to this port.
if __name__ == '__main__':
    app.run(debug=True, port=5000, host="127.0.0.1")