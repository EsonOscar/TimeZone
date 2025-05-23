from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort, make_response, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
#from flask_socketio import SocketIO, emit
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler
from cryptography.fernet import Fernet
#from flask_cors import CORS
from functools import wraps
from datetime import datetime, timezone, timedelta
from time import sleep
import sqlite3
import json

# Tell Flask to show the actual request IP in the log, instead of 127.0.0.1 (NGINX)
# The request handler is used in the app.run() method
class ProxiedRequestHandler(WSGIRequestHandler):
    def address_string(self):
        # trust the first entry in X-Forwarded-For
        forwarded = self.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return super().address_string()

#Initialise the flask app and CORS
app = Flask(__name__, static_folder="/home/eson/timezone_static", static_url_path="/static")
app.secret_key = "super_duper_secret_key"

# Tell flask to trust the third entry in X-Forwarded-For
# The app is behind cloudflare, and a reverse proxy, so the third entry is the real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1)
#socketio = SocketIO(app)

# CORS would be used to allow cross-origin requests, but it's not needed for this app,
# since all HTML rendering and API requests are done from the same domain
#CORS(app)

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

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, row):
        self.id             = row['id']
        self.username       = row['username']
        self.password       = row['password']
        self.name           = row['name']
        self.lastname       = row['lastname']
        self.password       = row['password']
        self.email          = row['email']
        self.role           = row['role']
        self.paytype        = row['paytype']
        self.pay            = row['pay']
    
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
#Survivor from before Kotlin app was disregarded
#Maybe useful in the future
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

#Decorator, only allow admin access, both org admin and sysadmin
def admin_required(f):
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
@app.route('/home')
def index():
    return render_template('indexV3.html')

#Meet the team
@app.route('/team')
def team():
    return render_template('team.html')

#Contact
@app.route('/contact')
def contact():
    return render_template('contactV3.html')

#Dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_authenticated and current_user.is_employee:
        user = current_user.username

        try: 
            conn = db_connect()
            times = conn.execute('''SELECT start_time, end_time FROM timeentries
                         WHERE user = ?
                         AND start_time >= DATE("now", "start of month")
                         AND end_time IS NOT NULL
                         ORDER BY start_time ASC''', (user,)).fetchall()
        except Exception as e:
            print(f"Database error: {e}")
            flash('Database error, please contact support', 'danger')
            return redirect(url_for('index'))
        finally:
            conn.close()



        return render_template('dashboard.html', times=times)
    elif current_user.is_authenticated and current_user.is_org_admin:
        conn = db_connect()
        users = conn.execute("""SELECT name, lastname, email FROM users 
                             WHERE role = "employee" 
                             AND lastname != "root"
                             AND deleted_at IS NULL
                             ORDER BY role DESC""").fetchall()
        times = conn.execute("""SELECT user, start_time, end_time FROM timeentries
                             WHERE machine IS NULL
                             AND date(start_time, "start of month");""").fetchall()
        
        users = list(users)
        i = 0
        for user in users:
            print(dict(users[i]))
            i += 1

        times = list(times)
        i = 0
        for entry in times:
            print(dict(times[i]))
            i += 1


        conn.close()

        return render_template("orgadmin_dashboard.html", users=users)
    elif current_user.is_authenticated and current_user.is_sysadmin:
        return render_template('sysadmin_dashboard.html')
    else:
        return render_template('forbidden.html')

#Administration panel
@app.route('/admin')
@login_required
@admin_required
def admin():
    if current_user.is_authenticated and current_user.is_org_admin:
        conn = db_connect()
        users = conn.execute("""SELECT * FROM users 
                             WHERE role = "employee" 
                             AND lastname != "root"
                             AND deleted_at IS NULL
                             ORDER BY role DESC""").fetchall()
        conn.close()
        return render_template('orgadmin_admin.html', users=users)
    elif current_user.is_authenticated and current_user.is_sysadmin:
        conn = db_connect()
        
        users = conn.execute("""SELECT * FROM users 
                             WHERE lastname != "root"
                             AND deleted_at IS NULL 
                             ORDER BY role DESC""").fetchall()
        

        if current_user.id == 1:
            root_users = conn.execute("""SELECT * FROM users 
                                      WHERE lastname = "root"
                                      AND deleted_at IS NULL
                                      ORDER BY role DESC""").fetchall()

            count = 0
            for account in root_users:
                count += 1

            count -= 1
            for account in root_users:
                users.insert(0, root_users[count])
                count -= 1
            
            conn.close()
            return render_template('admin.html', users=users)
        
        conn.close()
        return render_template('admin.html', users=users)
    else:
        return render_template('forbidden.html')

# My profile
@app.route("/user")
@login_required
def user():
    if current_user.is_authenticated:
        conn = db_connect()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (current_user.id,)).fetchone()
        conn.close()
        return render_template('user.html', user=user)
    else:
        return render_template('forbidden.html')

# TimeZone route
# Employee time tracking and BLE scanning
@app.route('/timezone')
@login_required
def time_zone():
    if current_user.is_authenticated and current_user.is_employee:
        try:
            conn = db_connect()
            # Get the list of machines from the database
            machines = conn.execute("""SELECT id, name, uuid FROM machines
                                    ORDER BY id""").fetchall()
            # Get the list of active machines from the database
            active_machines = conn.execute("""SELECT machine FROM timeentries
                                            WHERE active = 1
                                            AND MACHINE IS NOT NULL
                                            ORDER BY id""").fetchall()
            active_machines = [str(machine[0]) for machine in active_machines]
            if len(active_machines) == 0:
                active_machines = None
            print(f"Active machines: {active_machines}")
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            flash('Database error, please contact support', 'danger')
            return redirect(url_for('index'))
        finally:
            conn.close()
        # Convert the machine data to a list of dictionaries
        machines = [dict(machine) for machine in machines]
        for machine in machines:
            for entry in machine:
                print(f"{entry}:{machine[entry]}")

        print(f"Machines: {machines}")
        return render_template('timezone.html', machines=machines, active_machines=active_machines)
    elif current_user.is_authenticated and current_user.is_org_admin:

        return render_template('timezone.html')
    elif current_user.is_authenticated and current_user.is_sysadmin:

        return render_template('timezone.html')
    else:
        return render_template('forbidden.html')

#Login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()

        try:
            conn = db_connect()
            row = conn.execute("""SELECT * FROM users 
                               WHERE username = ?
                               """, (username,)).fetchone()
        except Exception as e:
            print(f"Database error: {e}")
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
        finally:
            conn.close()

        pass_check = check_password_hash(row['password'], request.form.get('password', ''))
        print(f"Password check: {pass_check}")

        if row['deleted_at'] is not None:
            flash('Your account has been deleted. Please contact support.', 'danger')
            return redirect(url_for('login'))
        elif row and pass_check:
            user = User(row)
            login_user(user)
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


"""
@app.route('/robots.txt')
def robots():
    resp = make_response(
        send_from_directory(app.root_path, 'robots.txt', mimetype='text/plain')
    )
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    return resp
"""
# Favicon
# For the app
@app.route('/favicon.ico')
def favicon():
    return send_from_directory(app.static_url_path,'happy_logo.png', mimetype='image/vnd.microsoft.icon')

# Manifest
# This is used for PWA support, and is required for the app to be installable on mobile devices
@app.route('/manifest.json')
def serve_manifest():
    return send_from_directory(app.root_path, 'manifest.json', mimetype='application/manifest+json')

# Service Worker
@app.route('/sw.js')
def serve_sw():
    return send_from_directory(app.root_path, 'sw.js', mimetype='application/javascript')

############################################# API ENDPOINTS BELOW ##############################################

# API Route for changing the user password
@app.route('/api/change_password', methods=['POST'])
@login_required
def change_password():
    print(f"Change password API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")
    
    username = current_user.username

    try:
        conn = db_connect()
        old_password = conn.execute("""SELECT password FROM users 
                               WHERE username = ?
                               """, (username,)).fetchone()
        old_password = str(old_password[0])
    except Exception as e:
        print(f"Database error: {e}")
        flash('Invalid username or password.', 'danger')
        return redirect(url_for('user'))
    finally:
        conn.close()

    old_check = check_password_hash(old_password, request.form.get('oldPassword', ''))
    new_password = generate_password_hash(request.form.get('newPassword', ''))
    print(f"Old password check: {old_check}, Old password hash: {old_password}")

    if not new_password:
        flash('All fields are required.', 'danger')
        print("All fields are required")
        return redirect(url_for('user'))

    if not old_check:
        flash('Your old password was incorrect, please try again', 'warning')
        print("All fields are required")
        return redirect(url_for('user'))

    
    print(f"Old password check: {old_check}, New password hash: {new_password}")

    try:
        conn = db_connect()
        conn.execute("""UPDATE users SET password = ? WHERE username = ?""", (new_password, username))
        conn.commit()
        flash('Password changed successfully.', 'success')
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database error', 'danger')
        return redirect(url_for('user'))
    finally:
        conn.close()

    return redirect(url_for('user'))        

# API Route for machine timestamp creation
@app.route("/api/timezone_machine/", methods=["POST"])
@login_required
def timezone_machine_api():
    print("Machine Timestamp API endpoint hit")
    print(f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")
    data = json.loads(request.data.decode('utf-8'))
    uuid = data.get("uuid")
    utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]
    print(f"UUID: {uuid}")
    
    # Check basic conditions, if the user is not an employee or if no UUID is provided
    if current_user.role != "employee":
        flash("Only \"Employee\" accounts can create machine timestamps", "danger")
        return jsonify({ "success": False, "error": "Not permitted" }), 403
    elif not uuid:
        flash("No machine ID provided, please retry", "danger")
        return jsonify({ "success": False, "error": "Missing UUID" }), 400
    
    # Get a list of all valid UUIDs from the database
    try:
        conn = db_connect()
        uuid_list = conn.execute("SELECT uuid FROM machines ORDER BY id").fetchall()
        uuid_list = [str(uuid[0]) for uuid in uuid_list]
        print(uuid_list)
        conn.commit()
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database error', 'danger')
        return jsonify({ "success": False, "error": "Database error" }), 400
    finally:
        conn.close()
    
    # Check if the provided UUID is in the list of valid UUIDs
    if uuid not in uuid_list:
        flash("Invalid machine ID provided, please contact support", "danger")
        print(f"Invalid machine ID provided: {uuid}")
        return jsonify({ "success": False, "error": "Invalid UUID" }), 400

    # RECHECK LOGIC HERE SINCE THE ACTIVE COLUMN HAS BEEN ADDED TO THE TIMEENTRIES TABLE
    # Check if machine already has a start time today
    try:
        conn = db_connect()
        machine = conn.execute('SELECT name FROM machines WHERE uuid = ?', (uuid,)).fetchone()
        conn.commit()
        machine = str(machine[0])
        print(f"Machine name: {machine}")
        time_data = conn.execute('SELECT * FROM timeentries WHERE machine = ? AND DATE(start_time) = DATE(?) ORDER BY id DESC LIMIT 1', (machine, utc_dt)).fetchone()
        conn.commit()
        try:
            time_data = dict(time_data)
        except Exception as e:
            print(f"Error converting time_data to dict: {e}")
            print("Setting time_data to None")
            time_data = None
        print(f"Started? {time_data}")
        # If the machine has no start time today, create a new entry
        if not time_data:
            conn.execute('INSERT INTO timeentries (user, machine, start_time) VALUES (?, ?, ?)',
                         (current_user.username, machine, utc_dt))
            conn.commit()
            print(f"Start time created for machine: {machine} at {utc_dt}")
        else:
            # Check if the machine already has an end time today
            ended = time_data.get("end_time")
            print(f"Ended? {ended}")
            # If the machine has no end time today, update entry with end time
            if not ended:
                conn.execute('UPDATE timeentries SET end_time = ? WHERE machine = ? AND DATE(start_time) = DATE(?) AND id = ?',
                            (utc_dt, machine, utc_dt, time_data["id"]))
                print(f"End time created for machine: {machine} at {utc_dt}")
                conn.commit()
            # If the machine has an end time today, create a new entry
            else:
                conn.execute('INSERT INTO timeentries (user, machine, start_time) VALUES (?, ?, ?)',
                         (current_user.username, machine, utc_dt))
                conn.commit()
                print(f"Start time created for machine: {machine} at {utc_dt}")
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database error', 'danger')
        return jsonify({ "success": False, "error": "Database error" }), 400
    finally:
        conn.close()

    print("Reached the end of the function")
    return jsonify({ "success": True }), 200
    
    

# API Route for employee timestamp creation
@app.route("/api/timezone_user/", methods=["POST"])
@login_required
def timezone_user_api():
    print(f"User Timestamp API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")
    utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]
    user = current_user.username

    conn = db_connect()
    try:
        conn.execute('INSERT INTO timeentries (user, start_time) VALUES (?, ?)', (user, utc_dt))
        conn.commit()
        print(f"Timestamp created for user: {user} at {utc_dt}")
        flash(f"Start Time created for user: {user} at {utc_dt}", "success")
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database error', 'danger')
    finally:
        conn.close()

    return redirect(url_for('time_zone'))

#Route for an admin to create a new user.
#Data from the create user form, located in the admin.html template, is sent to this route.
@app.route("/api/create_user", methods=["POST"])
@login_required
@admin_required
def admin_create_user():
    print(f"Create user API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = generate_password_hash(request.form.get("password", ""))
        name     = request.form.get("name", "").strip()
        lastname = request.form.get("lastname", "").strip()
        email    = request.form.get("email", "").strip()
        role     = request.form.get("role")
        paytype  = request.form.get("paytype")
        pay      = request.form.get("pay", "").strip()

        utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]

        if not username or not password or not name or not email or not role:
            flash('All fields are required.', 'danger')
            return redirect(url_for('admin'))
        elif lastname == "root":
            print(f"An attempt has been made to create a user with the root lastname.")
            flash(f"You canot create a user with the lastname \"root\".", "danger")
            return redirect(url_for('admin'))
        elif current_user.role == "org_admin" and (role == "sysadmin" or role == "org_admin"):
            print(f"An attempt has been made to create a user with the role \"{role}\" by an org admin.")
            flash(f"You cannot create a user with the role \"{role}\".", "danger")
            return redirect(url_for('admin'))

        conn = db_connect()
        try:
            conn.execute('INSERT INTO users (username, password, name, lastname, email, role, paytype, pay, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                            (username, password, name, lastname, email, role, paytype, pay, utc_dt))
            conn.commit()
            print('User created successfully.', 'success')
            flash(f'User {username} created successfully.', 'success')
        except sqlite3.IntegrityError:
            print('Username or email already exists.')
            flash('Username or email already exists.', 'danger')
        finally:
            conn.close()
    return redirect(url_for('admin'))

#API endpoint to get user data for one specific user
#Only accessible by admins, both sysadmin and org admin
@app.route("/api/user/<int:user_id>", methods=["GET"])
@login_required
@admin_required
def get_user(user_id):
    print(f"User data API endpoint hit, requested user ID: {user_id}")
    print(f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")

    conn = db_connect()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if user:
        user = dict(user)
        return jsonify(user)
    else:
        return jsonify({"Status": "Error 404", "Message": "User not found"}), 404

# API endpoint to update a user
# Only accessible by admins, both sysadmin and org admin
# There's some logic to prevent certain users from being modified, needs updates
@app.route("/api/update/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def update(user_id):
    print(f"User update API endpoint hit, requested user ID to update: {user_id}")
    print(f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")

    utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]
    
    name        = request.form.get("name", "").strip()
    lastname    = request.form.get("lastname", "").strip()
    email       = request.form.get("email", "").strip()
    username    = request.form.get("username", "").strip()
    role        = request.form.get("role", "")
    paytype     = request.form.get("paytype", "")
    pay         = request.form.get("pay", "").strip()

    try:
        conn = db_connect()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        user = dict(user)
        print(f"User data: {user}")
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database error', 'danger')
        conn.close()
        return redirect(url_for('admin'))
    finally:
        conn.close()
    
    # Check if all fields are filled
    if not name or not lastname or not email or not username or not role:
        flash('All fields are required.', 'danger')
        return redirect(url_for('admin'))
    # Root users, don't allow modification
    elif user['lastname'] == "root":
        print(f"\nWARNING ({utc_dt}):")
        print(f"Attempt has been made to modify the root \"{username}\" user.")
        print(f"Attempt was made by user: [{current_user.username}] ({current_user.name} {current_user.lastname}).")
        print(f"The incident has been logged.\n")
        flash(f"Attempt to modify the root \"{username}\" user was made at {utc_dt}.", "danger")
        flash(f"Attempt was made by: [{current_user.username}] ({current_user.name} {current_user.lastname}). Attempt has been logged.", "danger")
        return redirect(url_for('admin'))
    # User 2, don't allow modification
    elif user_id == 2 and current_user.id != 2:
        print(f"\nWARNING ({utc_dt}):")
        print(f"Attempt has been made to modify the user: \"{username}\"")
        print(f"Attempt was made by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")
        print(f"The incident has been logged.\n")

        # If the active user is root, log them out
        if current_user.lastname == "root":
            logout_user()
            flash(f"DET MÅ DU IKKE! FY FY FY FY!", "danger")
            return redirect(url_for('login'))
        
        # If the active user is not root, teach them a lesson
        try:
            conn = db_connect()
            conn.execute("""UPDATE users SET name = ?, lastname = ? WHERE id = ?""", ("FJOLS", "FJOLS" ,current_user.id))
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            print("Stop making the databse sad!")
        finally:
            conn.close()
            logout_user()
            flash(f"DET MÅ DU IKKE! FY FY FY FY!", "danger")
        return redirect(url_for('login'))

    # Only root sysadmin can freely modify all sysadmin users, sysadmin users can only modify themselves
    ################## LOOK INTO THIS, LOGIC ISN'T SOUND ##################
    elif user["role"] == "sysadmin" and current_user.id != 1:
        if user["role"] == "sysadmin" and current_user.id != user_id:
            print(f"\nWARNING ({utc_dt}):")
            print(f"Attempt has been made to modify the sysadmin user: \"{username}\"")
            print(f"Attempt was made by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")
            print(f"The incident has been logged.\n")
            flash(f"SysAdmins users can only be modified by root, or by the account owner.", "warning")

            return redirect(url_for('admin'))
        pass

    else:
        try:
            conn = db_connect()
            conn.execute('UPDATE users SET name = ?, lastname = ?, email = ?, username = ?, role = ?, paytype = ?, pay = ? WHERE id = ?',
                            (name, lastname, email, username, role, paytype, pay, user_id))
            conn.commit()
        except sqlite3.IntegrityError:
            print('Username or email already exists.')
            flash('Username or email already exists.', 'danger')
        except Exception as e:
            print(f"Database error: {e}")
            flash('Database error', 'danger')
        finally:
            flash(f"User \"{username}\" updated successfully.", "success")
            conn.close()

    return redirect(url_for('admin'))

# API endpoint to delete a user (soft delete)
# Only accessible by admins, both sysadmin and org admin (org admin can only delete employees)
# Be careful with this one pls pls (don't do it Katrin)
@app.route("/api/delete/<int:user_id>")
@login_required
@admin_required
def delete(user_id):
    print(f"User delete API endpoint hit, requested user ID to delete: {user_id}")
    print(f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})")

    utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]

    try:
        conn = db_connect()
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        user = dict(user)
    except Exception as e:
        print(f"Database error: {e}")
        flash('Database error', 'danger')
        return redirect(url_for('admin'))
    finally:
        conn.close()

    # Do not allow deletion of root users
    if user["lastname"] == "root":
        flash(f"Attempt to delete the root \"{user["username"]}\" user was made at {utc_dt}.", "danger")
        flash(f"Attempt was made by: [{current_user.username}] ({current_user.name} {current_user.lastname}). Attempt has been logged.", "danger")
        return redirect(url_for('admin'))
    # Do not allow deletion of the user making the request
    elif user_id == current_user.id:
        flash(f"Don't delete yourself, you have so much to live for!", "danger")
        return redirect(url_for('admin'))
    # Do not allow deletion of sysadmin users, unless done by root sysadmin
    elif user["role"] == "sysadmin" and current_user.id != 1:
        flash(f"SysAdmin users can't be deleted.", "danger")
        return redirect(url_for('admin'))
    
    else:
        try:
            conn = db_connect()
            conn.execute('UPDATE users SET deleted_at = ? WHERE id = ?', (utc_dt, user_id))
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            flash('Database error', 'danger')
        finally:
            conn.close()
        flash(f"User \"{user["username"]}\" deleted successfully.", "success")
        return redirect(url_for('admin'))

@app.route("/api/contact", methods=["POST"])
def contactAPI():
    print(f"User contact API endpoint hit")
    email      = request.form.get("email", "").strip()
    message    = request.form.get("message", "").strip()
    ip         = request.remote_addr 

    utc_dt = str(datetime.now(timezone.utc)+timedelta(hours=2))[:-13]

    try:
        conn = db_connect() 
        try:
            row = conn.execute("""SELECT * FROM contact WHERE email = ? 
                               AND TIMEDIFF(?, timestamp) < "+0000-00-00 00:01:00" 
                               ORDER BY id DESC LIMIT 1""", (email, utc_dt)).fetchone()
            row = dict(row)
            conn.commit()
        except Exception as e:
            print(f"Error: {e}")
            row = None
        finally:
            conn.close()
            
    except Exception as e:
        flash("Database error", "danger") 
        print(f"Database error: {e}")
        conn.close() 
        return redirect(url_for("contact"))

    print(row)

    print(f"{email}, {message}")

    if not email or not message:
        print(f"Both fields are required!")
        flash("Both fields are required!", "danger")
        return redirect(url_for("contact"))
    elif len(message) > 150:
        print("Message is too long!")
        flash("Message is too long, please use less than 150 characters.", "warning")
        return redirect(url_for("contact"))
    elif  row != None:
        print(f"User {email} tried to spam the contact form!")
        flash("Gotta wait buddy hehe", "danger") 
        return redirect (url_for("contact"))
    
    try:
        print(f"User {email} sent a message: {message}")
        print("Updating database...")
        conn = db_connect()
        conn.execute("""INSERT INTO contact (email, message, ip, timestamp) VALUES (?,?,?,?)""", (email, message, ip, utc_dt))
        conn.commit()
        conn.close()
        flash("Message sent successfully!", "success")
    except Exception as e:
        flash("Database error", "danger")
        conn.close()
        return redirect(url_for("contact"))

    return redirect(url_for("contact"))
    


################################################### CONFIG #####################################################

# Config, app runs locally on port 5000. NGINX proxies outisde requests to this port, and sends the apps response back to the client.
if __name__ == '__main__':
    app.run(debug=True, port=5000, host="127.0.0.1", request_handler=ProxiedRequestHandler)