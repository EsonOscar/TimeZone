from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    jsonify,
    abort,
    send_from_directory,
)
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    login_required,
    logout_user,
    current_user,
)

from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.serving import WSGIRequestHandler
from cryptography.fernet import Fernet

from functools import wraps
from datetime import datetime, timezone, timedelta
import sqlite3
import json
import os


# Tell Flask to show the actual request IP in the log, instead of 127.0.0.1 (NGINX)
# The request handler is used in the app.run() method
class ProxiedRequestHandler(WSGIRequestHandler):
    """Proxy request handler class, makes sure we can access the real client IP"""

    def address_string(self):
        # trust the first entry in X-Forwarded-For
        forwarded = self.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return super().address_string()


# Initialise the flask app and CORS
app = Flask(
    __name__, static_folder="/home/eson/timezone_static", static_url_path="/static"
)
app.secret_key = "super_duper_secret_key"

# Tell flask to trust the third entry in X-Forwarded-For
# The app is behind cloudflare, and a reverse proxy, so the third entry is the real client IP
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=2, x_proto=1)
# socketio = SocketIO(app)

# CORS would be used to allow cross-origin requests, but it's not needed for this app,
# since all HTML rendering and API requests are done from the same domain
# CORS(app)

# Inistialize the login manager
login_manager = LoginManager()
# Set the login view for the login manager, this is used to redirect users to the login page if they are not logged in
login_manager.login_view = "login"
login_manager.init_app(app)

# Database path
database = "TimeZone.db"


# Create database connection
def db_connect():
    conn = sqlite3.connect(database)
    conn.row_factory = sqlite3.Row
    return conn


# User class for Flask-Login
class User(UserMixin):
    """Current User class, extracts all necessary information about the current user from the database,
    and saves it to object attributes.

    Also creates properties for quick checks to see what role the current user has."""

    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.password = row["password"]
        self.name = row["name"]
        self.lastname = row["lastname"]
        self.password = row["password"]
        self.email = row["email"]
        self.role = row["role"]
        self.paytype = row["paytype"]
        self.pay = row["pay"]

    # Check if user is sysadmin
    @property
    def is_sysadmin(self):
        return self.role == "sysadmin"

    # Check if user is org admin
    @property
    def is_org_admin(self):
        return self.role == "org_admin"

    # Check if user is employee
    @property
    def is_employee(self):
        return self.role == "employee"


# Load selected user from database
@login_manager.user_loader
def load_user(user_id):
    conn = db_connect()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None


# Send unauthorized response if user tries to connect to API endpoints, but is not logged in
# Survivor from before Kotlin app was disregarded
# Maybe useful in the future
@login_manager.unauthorized_handler
def unauthorized():
    if request.path.startswith("/api/"):
        return (
            jsonify(
                {
                    "Status": "Error 401",
                    "Message": "Unauthorized access attempted, please login",
                }
            ),
            401,
        )
    elif request.path.startswith("/"):
        return render_template("forbidden.html"), 403


# Decorator, only allow sysadmin access
def sysadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_sysadmin:
            abort(403)  # Forbidden
        return f(*args, **kwargs)

    return decorated_function


# Decorator, only allow admin access, both org admin and sysadmin
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (
            current_user.is_org_admin or current_user.is_sysadmin
        ):
            abort(403)
        return f(*args, **kwargs)

    return decorated_function


# Load the Fernet key from the environment variable (saved in .bashrc, don't tell anyone shhh)
FERNET_KEY = os.environ.get("FERNET_KEY")
if not FERNET_KEY:
    print("ooooh boi u in danger, the fernet key wasn't found")
    exit(1)
else:
    print("Fernet key found in environment variable, and loaded successfully")
    print("We lucky :D")
    # DON'T DO THIS PRINT IN PROD, U GET FIRED >:|
    print(f"Fernet key: {FERNET_KEY}")


############################################# WEBSITE ROUTES BELOW #############################################


# Index
@app.route("/")
@app.route("/index")
@app.route("/home")
def index():
    return render_template("indexV3.html")


# Meet the team
@app.route("/team")
def team():
    return render_template("team.html")


# Contact
@app.route("/contact")
def contact():
    return render_template("contactV3.html")


# Dashboard
@app.route("/dashboard")
@login_required
def dashboard():
    # REMOVE LOGIC ONCE API IS SET UP
    # IGNORE THAT KEEP LOGIC TIHI
    if current_user.is_authenticated and current_user.is_employee:
        user = current_user.username
        now = datetime.now(timezone.utc) + timedelta(hours=2)

        # Big extract, maybe move to API later to lighten the load on the dashboard route
        # LOGIC HERE WORKS

        try:
            conn = db_connect()
            times = conn.execute(
                """SELECT start_time, end_time, TIMEDIFF(end_time, start_time) AS duration,
                         CASE 
                            WHEN TIMEDIFF(end_time, start_time) > "+0000-00-00 00:01:00" 
                            THEN TIMEDIFF(end_time, datetime(start_time, "+1 minute")) 
                            ELSE "+0000-00-00 00:00:00"
                         END AS overtime,
                         ROUND(CASE
                                 WHEN (strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                 THEN 0
                                 ELSE
                                    (strftime("%s", end_time) - strftime("%s", start_time) - 60) 
                                    * 100.0 / (strftime("%s", end_time) - strftime("%s", start_time))
                                    END, 2)
                                 AS overtime_percentage
                         FROM timeentries
                         WHERE user = ?
                         AND start_time >= DATE("now", "start of month")
                         AND end_time IS NOT NULL
                         AND machine IS NULL
                         ORDER BY start_time ASC""",
                (user,),
            ).fetchall()

            total_times = conn.execute(
                """SELECT TIME(SUM(strftime("%s", end_time) - strftime("%s", start_time)), "unixepoch") AS total_worked,
                                        TIME(SUM(CASE
                                                WHEN (strftime("%s", end_time) - strftime("%s", start_time) > (60))
                                                THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                ELSE 0
                                            END), "unixepoch") AS total_overtime,
                                        ROUND(CASE
                                                WHEN SUM(strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                                THEN 0
                                                ELSE
                                                    SUM(CASE WHEN (strftime("%s", end_time) - strftime("%s", start_time)) > (60)
                                                             THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                             ELSE 0
                                                        END) * 100.0 / SUM(strftime("%s", end_time) - strftime("%s", start_time))
                                                END, 2)
                                        AS overtime_percentage
                                        FROM timeentries
                                        WHERE user = ?
                                        AND start_time >= DATE("now", "start of month")
                                        AND end_time IS NOT NULL
                                        AND machine IS NULL
                                        GROUP BY user""",
                (user,),
            ).fetchone()

            conn.commit()
            if times:
                times = [dict(time) for time in times]
            total_times = dict(total_times)

            for time in times:
                time["duration"] = time["duration"][:-4][12:]
                if len(time["overtime"]) > 20:
                    time["overtime"] = time["overtime"][:-4][12:]
                else:
                    time["overtime"] = time["overtime"][12:]

            print(f"Times fetched: {times}")
            print(f"Total times fetched: {total_times}")

        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("index"))
        finally:
            conn.close()

        return render_template(
            "dashboard.html",
            times=times,
            total_times=total_times,
            current_month=now.strftime("%B"),
            current_year=now.strftime("%Y"),
        )

    elif current_user.is_authenticated and current_user.is_org_admin:

        try:
            conn = db_connect()
            # Add back later: AND lastname != "root"
            # Currently using the root employee for testing
            users = conn.execute(
                """SELECT id, username, name, lastname FROM users 
                                WHERE role = "employee"                               
                                AND deleted_at IS NULL
                                ORDER BY name ASC"""
            ).fetchall()
            machines = conn.execute(
                """SELECT id, name, type, dom, dop, pp FROM machines 
                                    ORDER BY id ASC"""
            ).fetchall()
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("index"))
        finally:
            conn.close()
        print(users)
        users = [dict(user) for user in users]
        machines = [dict(machine) for machine in machines]

        return render_template(
            "orgadmin_dashboardV2.html", users=users, machines=machines
        )

    elif current_user.is_authenticated and current_user.is_sysadmin:
        try:
            conn = db_connect()
            messages = conn.execute(
                """SELECT * FROM contact
                                    WHERE is_read = 0
                                    ORDER BY timestamp ASC"""
            ).fetchall()
            conn.commit()
            messages = [dict(message) for message in messages]
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("index"))
        finally:
            conn.close()
        return render_template("sysadmin_dashboard.html", messages=messages)
    else:
        return render_template("forbidden.html")


# Administration panel
@app.route("/admin")
@login_required
@admin_required
def admin():
    if current_user.is_authenticated and current_user.is_org_admin:
        conn = db_connect()
        users = conn.execute(
            """SELECT * FROM users 
                             WHERE role = "employee" 
                             AND lastname != "root"
                             AND deleted_at IS NULL
                             ORDER BY role DESC"""
        ).fetchall()
        conn.close()
        return render_template("orgadmin_admin.html", users=users)
    elif current_user.is_authenticated and current_user.is_sysadmin:
        conn = db_connect()

        users = conn.execute(
            """SELECT * FROM users 
                             WHERE lastname != "root"
                             AND deleted_at IS NULL 
                             ORDER BY role DESC"""
        ).fetchall()

        deleted_users = conn.execute(
            """SELECT * FROM users 
                             WHERE lastname != "root"
                             AND deleted_at IS NOT NULL 
                             ORDER BY role DESC"""
        ).fetchall()

        if current_user.id == 1:
            root_users = conn.execute(
                """SELECT * FROM users 
                                      WHERE lastname = "root"
                                      AND deleted_at IS NULL
                                      ORDER BY role DESC"""
            ).fetchall()

            count = 0
            for account in root_users:
                count += 1

            count -= 1
            for account in root_users:
                users.insert(0, root_users[count])
                count -= 1

            conn.close()
            return render_template(
                "admin.html", users=users, deleted_users=deleted_users
            )

        conn.close()
        return render_template("admin.html", users=users)
    else:
        return render_template("forbidden.html")


# My profile
@app.route("/user")
@login_required
def user():
    if current_user.is_authenticated:
        conn = db_connect()
        user = conn.execute(
            "SELECT * FROM users WHERE id = ?", (current_user.id,)
        ).fetchone()
        conn.close()
        return render_template("user.html", user=user)
    else:
        return render_template("forbidden.html")


# TimeZone route
# Employee time tracking and BLE scanning
@app.route("/timezone")
@login_required
def time_zone():
    if current_user.is_authenticated and current_user.is_employee:
        try:
            conn = db_connect()
            # Get the list of machines from the database
            machines = conn.execute(
                """SELECT id, name, uuid FROM machines
                                    ORDER BY id"""
            ).fetchall()
            # Get the list of active machines from the database
            active_machines = conn.execute(
                """SELECT machine FROM timeentries
                                            WHERE active = 1
                                            AND MACHINE IS NOT NULL
                                            ORDER BY id"""
            ).fetchall()
            active_machines = [str(machine[0]) for machine in active_machines]
            if len(active_machines) == 0:
                active_machines = None
            print(f"Active machines: {active_machines}")
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("index"))
        finally:
            conn.close()
        # Convert the machine data to a list of dictionaries
        machines = [dict(machine) for machine in machines]
        for machine in machines:
            for entry in machine:
                print(f"{entry}:{machine[entry]}")

        print(f"Machines: {machines}")
        return render_template(
            "timezone.html", machines=machines, active_machines=active_machines
        )
    elif current_user.is_authenticated and current_user.is_org_admin:

        return render_template("admin_timezone.html")
    elif current_user.is_authenticated and current_user.is_sysadmin:

        return render_template("admin_timezone.html")
    else:
        return render_template("forbidden.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()

        try:
            conn = db_connect()
            row = conn.execute(
                """SELECT * FROM users 
                               WHERE username = ?
                               """,
                (username,),
            ).fetchone()
        except Exception as e:
            print(f"Database error: {e}")
            flash("Invalid username or password.", "danger")
            return redirect(url_for("login"))
        finally:
            conn.close()

        pass_check = check_password_hash(
            row["password"], request.form.get("password", "")
        )
        print(f"Password check: {pass_check}")

        if row["deleted_at"] is not None:
            flash("Your account has been deleted. Please contact support.", "danger")
            return redirect(url_for("login"))
        elif row and pass_check:
            user = User(row)
            login_user(user)
            next_page = url_for("index")
            return redirect(next_page)
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


# Logout
@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# Doesn't work, cloudflare doesn't allow you to serve a robots.txt file yourself, has to be set on the website. boooooo
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
# Happy lil whale for the app
@app.route("/favicon.ico")
def favicon():
    return send_from_directory(
        app.static_url_path, "happy_logo.png", mimetype="image/vnd.microsoft.icon"
    )


# Manifest
# This is used for PWA support, and is required for the app to be installable on mobile devices
@app.route("/manifest.json")
def serve_manifest():
    return send_from_directory(
        app.root_path, "manifest.json", mimetype="application/manifest+json"
    )


# Service Worker for PWA
# Bare minimum atm, but it works, maybe expand later for offline functionality
@app.route("/sw.js")
def serve_sw():
    return send_from_directory(
        app.root_path, "sw.js", mimetype="application/javascript"
    )


############################################# API ENDPOINTS BELOW ##############################################


# API route for marking a message as read
@app.route("/api/message", methods=["POST"])
@login_required
@sysadmin_required
def mark_message_read():
    print(
        f"Mark message read API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    message_id = request.args.get("msg_id")

    print(f"Message ID: {message_id}")

    try:
        conn = db_connect()
        conn.execute("UPDATE contact SET is_read = 1 WHERE id = ?", (message_id,))
        conn.commit()
        print(f"Message with ID {message_id} marked as read")
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error, please contact support", "danger")
        return jsonify({"Success": False, "Message": "Database error"}), 500
    finally:
        conn.close()

    return (
        jsonify(
            {"Success": True, "Message": "API endpoint hit, message marked as read"}
        ),
        200,
    )


# API route for marking a message as unread
@app.route("/api/message/unread", methods=["POST"])
@login_required
@sysadmin_required
def mark_message_unread():
    print(
        f"Mark message unread API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    message_id = request.args.get("msg_id")

    print(f"Message ID: {message_id}")

    try:
        conn = db_connect()
        conn.execute("UPDATE contact SET is_read = 0 WHERE id = ?", (message_id,))
        conn.commit()
        print(f"Message with ID {message_id} marked as unread")
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error, please contact support", "danger")
        return jsonify({"Success": False, "Message": "Database error"}), 500
    finally:
        conn.close()

    return (
        jsonify(
            {"Success": True, "Message": "API endpoint hit, message marked as unread"}
        ),
        200,
    )


# API route for fetching read messages
@app.route("/api/messages/read", methods=["GET"])
@login_required
@sysadmin_required
def get_read_messages():
    print(
        f"Get read messages API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    date_from = request.args.get("dateFrom")
    date_to = request.args.get("dateTo")
    fetch_all = request.args.get("fetchAll")

    print(f"Date from: {date_from}, Date to: {date_to}")
    print(f"Fetch all: {fetch_all}")

    if fetch_all:
        print("Fetching all read messages")
        try:
            conn = db_connect()
            messages = conn.execute(
                """SELECT * FROM contact 
                                    WHERE is_read = 1 
                                    ORDER BY timestamp DESC"""
            ).fetchall()
            conn.commit()
            messages = [dict(message) for message in messages]
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return jsonify({"Success": False, "Message": "Database error"}), 500
        finally:
            conn.close()

        if not messages:
            return jsonify([]), 200

        return jsonify(messages), 200
    elif not date_from or not date_to:
        print("Both from and to dates are required")
        return (
            jsonify(
                {"Success": False, "Message": "Both from and to dates are required"}
            ),
            400,
        )
    elif date_from > date_to:
        print("From date cannot be after to date")
        return (
            jsonify({"Success": False, "Message": "From date cannot be after to date"}),
            400,
        )
    else:
        try:
            conn = db_connect()
            messages = conn.execute(
                """SELECT * FROM contact 
                                    WHERE is_read = 1 
                                    AND timestamp BETWEEN ? AND ?
                                    ORDER BY timestamp DESC""",
                (date_from, date_to),
            ).fetchall()
            conn.commit()
            messages = [dict(message) for message in messages]
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return jsonify({"Success": False, "Message": "Database error"}), 500
        finally:
            conn.close()

        if not messages:
            return jsonify([]), 200
    print(f"Messages fetched: {messages}")
    return jsonify(messages), 200


# API route for fetching user work times for the employee dashboard
@app.route("/api/times/user", methods=["GET"])
@login_required
def get_user_times():
    print(
        f"User times API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    user = current_user.username
    from_date = request.args.get("dateFrom")
    to_date = request.args.get("dateTo")

    if not from_date or not to_date:
        flash("Both from and to dates are required.", "danger")
        print("Both from and to dates are required")
        return redirect(url_for("dashboard"))
    elif from_date > to_date:
        flash("From date cannot be after to date.", "danger")
        print("From date cannot be after to date")
        return redirect(url_for("dashboard"))
    elif not user:
        flash("User not found, please contact support.", "danger")
        print("User not found")
        return redirect(url_for("dashboard"))
    else:
        try:
            conn = db_connect()
            times = conn.execute(
                """SELECT start_time, end_time, TIMEDIFF(end_time, start_time) AS worked,
                         CASE 
                            WHEN TIMEDIFF(end_time, start_time) > "+0000-00-00 00:01:00" 
                            THEN TIMEDIFF(end_time, datetime(start_time, "+1 minute")) ELSE "+0000-00-00 00:00:00"
                         END AS overtime,
                         ROUND(CASE
                                 WHEN (strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                 THEN 0
                                 ELSE
                                    (strftime("%s", end_time) - strftime("%s", start_time) - 60) 
                                    * 100.0 / (strftime("%s", end_time) - strftime("%s", start_time))
                                    END, 2)
                                 AS overtime_percentage
                         FROM timeentries
                         WHERE user = ?
                         AND DATE(start_time) BETWEEN ? AND ?
                         AND end_time IS NOT NULL
                         AND machine IS NULL
                         ORDER BY start_time ASC""",
                (user, from_date, to_date),
            ).fetchall()

            total_times = conn.execute(
                """SELECT TIME(SUM(strftime("%s", end_time) - strftime("%s", start_time)), "unixepoch") AS total_worked,
                                        TIME(SUM(CASE
                                                WHEN (strftime("%s", end_time) - strftime("%s", start_time) > (60))
                                                THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                ELSE 0
                                            END), "unixepoch") AS total_overtime,
                                        ROUND(CASE
                                                WHEN SUM(strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                                THEN 0
                                                ELSE
                                                    SUM(CASE WHEN (strftime("%s", end_time) - strftime("%s", start_time)) > (60)
                                                             THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                             ELSE 0
                                                        END) * 100.0 / SUM(strftime("%s", end_time) - strftime("%s", start_time))
                                                END, 2) 
                                        AS overtime_percentage
                                        FROM timeentries
                                        WHERE user = ?
                                        AND DATE(start_time) BETWEEN ? AND ?
                                        AND end_time IS NOT NULL
                                        AND machine IS NULL
                                        GROUP BY user""",
                (user, from_date, to_date),
            ).fetchone()
            conn.commit()
            if times:
                times = [dict(time) for time in times]
            else:
                return jsonify([]), 200

            for time in times:
                time["worked"] = time["worked"][:-4][12:]
                time["overtime"] = time["overtime"][:-4][12:]
            total_times = dict(total_times)

        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("dashboard"))
        finally:
            conn.close()

        print(f"Sent data: {[times, [total_times]]}")

        return jsonify([times, [total_times]]), 200


# API route for fetching all user work times for the org admin dashboard
@app.route("/api/times", methods=["GET"])
@login_required
@admin_required
def get_times():
    print(
        f"Times API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    # Bonk 'em out if they're not an org admin
    if not current_user.is_org_admin:
        return render_template("forbidden.html")

    from_date_gen = request.args.get("dateFromGeneral")
    to_date_gen = request.args.get("dateToGeneral")

    from_date_emp = request.args.get("dateFromEmployee")
    to_date_emp = request.args.get("dateToEmployee")
    user = request.args.get("userId")

    print(f"From date: {from_date_gen}, To date: {to_date_gen}")
    print(f"From date employee: {from_date_emp}, To date employee: {to_date_emp}")
    print(f"User: {user}")

    # THIS WORKS FOR NOW, BUT IMPLEMENT LOGIC FOR CHECKING IF DATES ARE SUPPLIED AND VALID

    if from_date_gen and to_date_gen and not user:
        try:
            conn = db_connect()
            # Rewrite logic later to NOT include root accounts, currently using the root employee for testing
            # WHERE lastname != "root"
            users = conn.execute(
                """SELECT username, name, lastname FROM users 
                                WHERE role = "employee"                               
                                AND deleted_at IS NULL
                                ORDER BY name ASC"""
            ).fetchall()
            times = conn.execute(
                """SELECT user,
                                        TIME(SUM(strftime("%s", end_time) - strftime("%s", start_time)), "unixepoch") AS total_worked,
                                        TIME(SUM(CASE
                                                WHEN (strftime("%s", end_time) - strftime("%s", start_time) > (60))
                                                THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                ELSE 0
                                            END), "unixepoch") AS total_overtime,
                                        ROUND(CASE
                                                WHEN SUM(strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                                THEN 0
                                                ELSE
                                                    SUM(CASE WHEN (strftime("%s", end_time) - strftime("%s", start_time)) > (60)
                                                             THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                             ELSE 0
                                                        END) * 100.0 / SUM(strftime("%s", end_time) - strftime("%s", start_time))
                                                END, 2)
                                        AS overtime_percentage
                                        FROM timeentries
                                        WHERE DATE(start_time) BETWEEN ? AND ?
                                        AND end_time IS NOT NULL
                                        AND machine IS NULL
                                        GROUP BY user
                                        ORDER BY user""",
                (from_date_gen, to_date_gen),
            ).fetchall()
            conn.commit()
            times = [dict(time) for time in times]
            users = [dict(user) for user in users]
            print(f"Users fetched: {users}")
            for user in users:
                for time in times:
                    if user["username"] == time["user"]:
                        time["user"] = user["name"] + " " + user["lastname"]
                        break
            print(f"Times fetched: {times}")
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("dashboard"))
        finally:
            conn.close()

        return jsonify(times), 200
    elif user:
        try:
            conn = db_connect()
            user = conn.execute(
                "SELECT username, name, lastname FROM users WHERE id = ?", (user,)
            ).fetchone()
            user = dict(user)
            # Logic in these makes my head hurt, but it works, fricken finally
            times = conn.execute(
                """SELECT start_time, end_time, TIMEDIFF(end_time, start_time) AS worked,
                         CASE 
                            WHEN TIMEDIFF(end_time, start_time) > "+0000-00-00 00:01:00" 
                            THEN TIMEDIFF(end_time, datetime(start_time, "+1 minute")) ELSE "+0000-00-00 00:00:00"
                         END AS overtime,
                         ROUND(CASE
                                 WHEN (strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                 THEN 0
                                 ELSE
                                    (strftime("%s", end_time) - strftime("%s", start_time) - 60) 
                                    * 100.0 / (strftime("%s", end_time) - strftime("%s", start_time))
                                    END, 2)
                                 AS overtime_percentage
                         FROM timeentries
                         WHERE user = ?
                         AND DATE(start_time) BETWEEN ? AND ?
                         AND end_time IS NOT NULL
                         AND machine IS NULL
                         ORDER BY start_time ASC""",
                (user["username"], from_date_emp, to_date_emp),
            ).fetchall()

            total_times = conn.execute(
                """SELECT TIME(SUM(strftime("%s", end_time) - strftime("%s", start_time)), "unixepoch") AS total_worked,
                                        TIME(SUM(CASE
                                                WHEN (strftime("%s", end_time) - strftime("%s", start_time) > (60))
                                                THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                ELSE 0
                                            END), "unixepoch") AS total_overtime,
                                        ROUND(CASE
                                                WHEN SUM(strftime("%s", end_time) - strftime("%s", start_time)) <= 60
                                                THEN 0
                                                ELSE
                                                    SUM(CASE WHEN (strftime("%s", end_time) - strftime("%s", start_time)) > (60)
                                                             THEN (strftime("%s", end_time) - strftime("%s", start_time) - (60))
                                                             ELSE 0
                                                        END) * 100.0 / SUM(strftime("%s", end_time) - strftime("%s", start_time))
                                                END, 2) 
                                        AS overtime_percentage
                                        FROM timeentries
                                        WHERE user = ?
                                        AND DATE(start_time) BETWEEN ? AND ?
                                        AND end_time IS NOT NULL
                                        AND machine IS NULL
                                        GROUP BY user""",
                (user["username"], from_date_emp, to_date_emp),
            ).fetchone()

            conn.commit()

            if times:
                times = [dict(time) for time in times]
            else:
                return jsonify([]), 200
            total_times = dict(total_times)

            print(f"Times fetched for user {user['name']} {user['lastname']}: {times}")
            print(
                f"Total times for user {user['name']} {user['lastname']}: {total_times}"
            )
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error, please contact support", "danger")
            return redirect(url_for("dashboard"))
        finally:
            conn.close()
        if times:
            for time in times:
                time["worked"] = time["worked"][:-4][12:]
                time["overtime"] = time["overtime"][:-4][12:]
                time["user"] = user["name"] + " " + user["lastname"]

        print(f"Times fetched for user {user['name']} {user['lastname']}: {times}")
        print(f"Data sent: {[times, [total_times]]}")
        return jsonify([times, [total_times]]), 200
    else:
        flash("Invalid request, please contact support", "danger")
        print(
            "Invalid request in org admin API. If this prints, something is wrong, and your code is poop. Give up and live under a bridge :("
        )
        return redirect(url_for("dashboard"))


# FILL THIS OUT ASAP SO WE CAN LOOK AT THE SHINY MACHINES
# FILLED OUT, GOOD JOB OSCAR U CUTE
# API Route for getting machine usage times for the org admin dashboard
@app.route("/api/times/machine", methods=["GET"])
@login_required
@admin_required
def get_machine_times():
    print(
        f"Machine times API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    # Bonk 'em out if they're not an org admin
    if not current_user.is_org_admin:
        return render_template("forbidden.html")

    from_date_gen = request.args.get("dateFromGeneral")
    to_date_gen = request.args.get("dateToGeneral")

    from_date_machine = request.args.get("dateFromMachine")
    to_date_machine = request.args.get("dateToMachine")
    machineId = request.args.get("machineId")

    print(f"From date: {from_date_gen}, To date: {to_date_gen}")
    print(f"From date machine: {from_date_machine}, To date machine: {to_date_machine}")
    print(f"User: {machineId}")

    if from_date_gen and to_date_gen and not machineId:
        try:
            conn = db_connect()
            times = conn.execute(
                """SELECT machine, 
                                 TIME(SUM(strftime("%s", end_time) - strftime("%s", start_time)), "unixepoch") AS total_used
                                 FROM timeentries
                                 WHERE DATE(start_time) BETWEEN ? AND ?
                                 AND end_time IS NOT NULL
                                 AND machine IS NOT NULL
                                 GROUP BY machine
                                 ORDER BY machine""",
                (from_date_gen, to_date_gen),
            ).fetchall()
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

        try:
            times = [dict(time) for time in times]
        except Exception as e:
            print(e)
            times = dict(times)
        print(times)

        return jsonify(times), 200

    elif machineId:
        try:
            conn = db_connect()
            machine = conn.execute(
                """SELECT name FROM machines
                                   WHERE id = ?""",
                (machineId),
            ).fetchone()
            machine = dict(machine)
            print(machine)
            times = conn.execute(
                """SELECT start_time, end_time, TIMEDIFF(end_time, start_time) AS used
                                    FROM timeentries
                                    WHERE end_time IS NOT NULL
                                    AND DATE(start_time) BETWEEN ? AND ?
                                    AND machine IS NOT NULL
                                    AND machine = ?""",
                (from_date_machine, to_date_machine, machine["name"]),
            ).fetchall()
            total_times = conn.execute(
                """SELECT TIME(SUM(strftime("%s", end_time) - strftime("%s", start_time)), "unixepoch") AS total_used
                                 FROM timeentries
                                 WHERE machine = ?
                                 AND DATE(start_time) BETWEEN ? AND ?
                                 AND end_time IS NOT NULL
                                 AND machine IS NOT NULL
                                 GROUP BY machine""",
                (machine["name"], from_date_machine, to_date_machine),
            ).fetchone()
            print(total_times)
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
        finally:
            conn.close()

        try:
            times = [dict(time) for time in times]
        except Exception as e:
            print(e)
            times = dict(times)

        for time in times:
            time["used"] = time["used"][:-4][12:]
        print(times)

        total_times = dict(total_times)
        print(total_times)

        return jsonify([times, [total_times]]), 200


# API Route for changing the user password
@app.route("/api/change_password", methods=["POST"])
@login_required
def change_password():
    print(
        f"Change password API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    username = current_user.username
    lastname = current_user.lastname

    if lastname == "root":
        print(f"An attempt has been made to change the password for the root user.")
        flash(f"You cannot change the password for a root user.", "danger")
        return redirect(url_for("user"))

    try:
        conn = db_connect()
        old_password = conn.execute(
            """SELECT password FROM users 
                               WHERE username = ?
                               """,
            (username,),
        ).fetchone()
        old_password = str(old_password[0])
    except Exception as e:
        print(f"Database error: {e}")
        flash("Invalid username or password.", "danger")
        return redirect(url_for("user"))
    finally:
        conn.close()

    old_check = check_password_hash(old_password, request.form.get("oldPassword", ""))
    new_password = generate_password_hash(request.form.get("newPassword", ""))
    print(f"Old password check: {old_check}, Old password hash: {old_password}")

    if not new_password:
        flash("All fields are required.", "danger")
        print("All fields are required")
        return redirect(url_for("user"))

    if not old_check:
        flash("Your old password was incorrect, please try again", "warning")
        print("All fields are required")
        return redirect(url_for("user"))

    print(f"Old password check: {old_check}, New password hash: {new_password}")

    try:
        conn = db_connect()
        conn.execute(
            """UPDATE users SET password = ? WHERE username = ?""",
            (new_password, username),
        )
        conn.commit()
        flash("Password changed successfully.", "success")
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error", "danger")
        return redirect(url_for("user"))
    finally:
        conn.close()

    return redirect(url_for("user"))


# API Route for machine timestamp creation
@app.route("/api/timezone_machine/", methods=["POST"])
@login_required
def timezone_machine_api():
    print("Machine Timestamp API endpoint hit")
    print(
        f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )
    data = json.loads(request.data.decode("utf-8"))
    uuid = data.get("uuid")
    utc_dt = str(datetime.now(timezone.utc) + timedelta(hours=2))[:-13]
    print(f"UUID: {uuid}")

    # Check basic conditions, if the user is not an employee or if no UUID is provided
    if current_user.role != "employee":
        flash('Only "Employee" accounts can create machine timestamps', "danger")
        return jsonify({"success": False, "error": "Not permitted"}), 403
    elif not uuid:
        flash("No machine ID provided, please retry", "danger")
        return jsonify({"success": False, "error": "Missing UUID"}), 400

    # Get a list of all valid UUIDs from the database
    try:
        conn = db_connect()
        uuid_list = conn.execute("SELECT uuid FROM machines ORDER BY id").fetchall()
        uuid_list = [str(uuid[0]) for uuid in uuid_list]
        print(uuid_list)
        conn.commit()
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error", "danger")
        return jsonify({"success": False, "error": "Database error"}), 400
    finally:
        conn.close()

    # Check if the provided UUID is in the list of valid UUIDs
    if uuid not in uuid_list:
        flash("Invalid machine ID provided, please contact support", "danger")
        print(f"Invalid machine ID provided: {uuid}")
        return jsonify({"success": False, "error": "Invalid UUID"}), 400

    # RECHECK LOGIC HERE SINCE THE ACTIVE COLUMN HAS BEEN ADDED TO THE TIMEENTRIES TABLE
    # Check if machine already has a start time today
    try:
        conn = db_connect()
        machine = conn.execute(
            "SELECT name FROM machines WHERE uuid = ?", (uuid,)
        ).fetchone()
        conn.commit()
        machine = str(machine[0])
        print(f"Machine name: {machine}")
        time_data = conn.execute(
            "SELECT * FROM timeentries WHERE machine = ? AND DATE(start_time) = DATE(?) ORDER BY id DESC LIMIT 1",
            (machine, utc_dt),
        ).fetchone()
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
            conn.execute(
                "INSERT INTO timeentries (user, machine, start_time) VALUES (?, ?, ?)",
                (current_user.username, machine, utc_dt),
            )
            conn.commit()
            print(f"Start time created for machine: {machine} at {utc_dt}")
        else:
            # Check if the machine already has an end time today
            ended = time_data.get("end_time")
            print(f"Ended? {ended}")
            # If the machine has no end time today, update entry with end time
            if not ended:
                conn.execute(
                    "UPDATE timeentries SET end_time = ? WHERE machine = ? AND DATE(start_time) = DATE(?) AND id = ?",
                    (utc_dt, machine, utc_dt, time_data["id"]),
                )
                print(f"End time created for machine: {machine} at {utc_dt}")
                conn.commit()
            # If the machine has an end time today, create a new entry
            else:
                conn.execute(
                    "INSERT INTO timeentries (user, machine, start_time) VALUES (?, ?, ?)",
                    (current_user.username, machine, utc_dt),
                )
                conn.commit()
                print(f"Start time created for machine: {machine} at {utc_dt}")
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error", "danger")
        return jsonify({"success": False, "error": "Database error"}), 400
    finally:
        conn.close()

    print("Reached the end of the function")
    return jsonify({"success": True}), 200


# API Route for employee timestamp creation
@app.route("/api/timezone_user/", methods=["POST"])
@login_required
def timezone_user_api():
    print(
        f"User Timestamp API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )
    utc_dt = str(datetime.now(timezone.utc) + timedelta(hours=2))[:-13]
    user = current_user.username

    conn = db_connect()
    try:
        cursor = conn.execute(
            "SELECT id FROM timeentries WHERE user = ? AND end_time IS NULL ORDER BY start_time DESC LIMIT 1",
            (user,),
        )
        row = cursor.fetchone()

        if row:
            conn.execute(
                "UPDATE timeentries SET end_time = ? WHERE id = ?", (utc_dt, row["id"])
            )
            conn.commit()
            print(f" END time updated for user: {user} at {utc_dt}")
            return jsonify(
                {
                    "status": "success",
                    "message": f"DIN dag er slut og registreret {user} at {utc_dt} og hvis du vil starte den igen tryk start dagen igen",
                    "action": "stop",
                }
            )
        else:
            conn.execute(
                "INSERT INTO timeentries (user, start_time) VALUES (?, ?)",
                (user, utc_dt),
            )
            conn.commit()
            print(f"start time skabt for user: {user} kl. {utc_dt}")
            return jsonify(
                {
                    "status": "great success",
                    "message": f"din tid er startet {user} kl {utc_dt}",
                    "action": "start",
                }
            )
    except Exception as e:
        print(f"Database fejl: {e}")
        return jsonify({"status": "error", "message": f"Databasefejl: {str(e)}"}), 500
    finally:
        conn.close()


# Route for an admin to create a new user.
# Data from the create user form, located in the admin.html template, is sent to this route.
@app.route("/api/create_user", methods=["POST"])
@login_required
@admin_required
def admin_create_user():
    print(
        f"Create user API endpoint hit, requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = generate_password_hash(request.form.get("password", ""))
        name = request.form.get("name", "").strip()
        lastname = request.form.get("lastname", "").strip()
        email = request.form.get("email", "").strip()
        role = request.form.get("role")
        paytype = request.form.get("paytype")
        pay = request.form.get("pay", "").strip()

        utc_dt = str(datetime.now(timezone.utc) + timedelta(hours=2))[:-13]

        if not username or not password or not name or not email or not role:
            flash("All fields are required.", "danger")
            return redirect(url_for("admin"))
        elif lastname == "root":
            print(f"An attempt has been made to create a user with the root lastname.")
            flash(f'You canot create a user with the lastname "root".', "danger")
            return redirect(url_for("admin"))
        elif current_user.role == "org_admin" and (
            role == "sysadmin" or role == "org_admin"
        ):
            print(
                f'An attempt has been made to create a user with the role "{role}" by an org admin.'
            )
            flash(f'You cannot create a user with the role "{role}".', "danger")
            return redirect(url_for("admin"))

        conn = db_connect()
        try:
            conn.execute(
                "INSERT INTO users (username, password, name, lastname, email, role, paytype, pay, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (username, password, name, lastname, email, role, paytype, pay, utc_dt),
            )
            conn.commit()
            print("User created successfully.", "success")
            flash(f"User {username} created successfully.", "success")
        except sqlite3.IntegrityError:
            print("Username or email already exists.")
            flash("Username or email already exists.", "danger")
        finally:
            conn.close()
    return redirect(url_for("admin"))


# API endpoint to get user data for one specific user
# Only accessible by admins, both sysadmin and org admin
@app.route("/api/user/<int:user_id>", methods=["GET"])
@login_required
@admin_required
def get_user(user_id):
    print(f"User data API endpoint hit, requested user ID: {user_id}")
    print(
        f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    conn = db_connect()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
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
    print(
        f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    utc_dt = str(datetime.now(timezone.utc) + timedelta(hours=2))[:-13]

    name = request.form.get("name", "").strip()
    lastname = request.form.get("lastname", "").strip()
    email = request.form.get("email", "").strip()
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "")
    paytype = request.form.get("paytype", "")
    pay = request.form.get("pay", "").strip()

    try:
        conn = db_connect()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        user = dict(user)
        print(f"User data: {user}")
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error", "danger")
        conn.close()
        return redirect(url_for("admin"))
    finally:
        conn.close()

    # Check if all fields are filled
    if not name or not lastname or not email or not username or not role:
        flash("All fields are required.", "danger")
        return redirect(url_for("admin"))
    # Root users, don't allow modification
    elif user["lastname"] == "root":
        print(f"\nWARNING ({utc_dt}):")
        print(f'Attempt has been made to modify the root "{username}" user.')
        print(
            f"Attempt was made by user: [{current_user.username}] ({current_user.name} {current_user.lastname})."
        )
        print(f"The incident has been logged.\n")
        flash(
            f'Attempt to modify the root "{username}" user was made at {utc_dt}.',
            "danger",
        )
        flash(
            f"Attempt was made by: [{current_user.username}] ({current_user.name} {current_user.lastname}). Attempt has been logged.",
            "danger",
        )
        return redirect(url_for("admin"))
    # User 2, don't allow modification
    elif user_id == 2 and current_user.id != 2:
        print(f"\nWARNING ({utc_dt}):")
        print(f'Attempt has been made to modify the user: "{username}"')
        print(
            f"Attempt was made by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
        )
        print(f"The incident has been logged.\n")

        # If the active user is root, log them out
        if current_user.lastname == "root":
            logout_user()
            flash(f"DET MÅ DU IKKE! FY FY FY FY!", "danger")
            return redirect(url_for("login"))

        # If the active user is not root, teach them a lesson
        try:
            conn = db_connect()
            conn.execute(
                """UPDATE users SET name = ?, lastname = ? WHERE id = ?""",
                ("FJOLS", "FJOLS", current_user.id),
            )
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            print("Stop making the databse sad!")
        finally:
            conn.close()
            logout_user()
            flash(f"DET MÅ DU IKKE! FY FY FY FY!", "danger")
        return redirect(url_for("login"))

    # Only root sysadmin can freely modify all sysadmin users, sysadmin users can only modify themselves
    ################## LOOK INTO THIS, LOGIC ISN'T SOUND ##################
    elif user["role"] == "sysadmin" and current_user.id != 1:
        if user["role"] == "sysadmin" and current_user.id != user_id:
            print(f"\nWARNING ({utc_dt}):")
            print(f'Attempt has been made to modify the sysadmin user: "{username}"')
            print(
                f"Attempt was made by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
            )
            print(f"The incident has been logged.\n")
            flash(
                f"SysAdmins users can only be modified by root, or by the account owner.",
                "warning",
            )

            return redirect(url_for("admin"))
        pass

    else:
        try:
            conn = db_connect()
            conn.execute(
                "UPDATE users SET name = ?, lastname = ?, email = ?, username = ?, role = ?, paytype = ?, pay = ? WHERE id = ?",
                (name, lastname, email, username, role, paytype, pay, user_id),
            )
            conn.commit()
        except sqlite3.IntegrityError:
            print("Username or email already exists.")
            flash("Username or email already exists.", "danger")
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error", "danger")
        finally:
            flash(f'User "{username}" updated successfully.', "success")
            conn.close()

    return redirect(url_for("admin"))


# API endpoint to delete a user (soft delete)
# Only accessible by admins, both sysadmin and org admin (org admin can only delete employees)
# Be careful with this one pls pls (don't do it Katrin)
@app.route("/api/delete/<int:user_id>")
@login_required
@admin_required
def delete(user_id):
    print(f"User delete API endpoint hit, requested user ID to delete: {user_id}")
    print(
        f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    utc_dt = str(datetime.now(timezone.utc) + timedelta(hours=2))[:-13]

    try:
        conn = db_connect()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        user = dict(user)
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error", "danger")
        return redirect(url_for("admin"))
    finally:
        conn.close()

    # Do not allow deletion of root users
    if user["lastname"] == "root":
        flash(
            f'Attempt to delete the root "{user["username"]}" user was made at {utc_dt}.',
            "danger",
        )
        flash(
            f"Attempt was made by: [{current_user.username}] ({current_user.name} {current_user.lastname}). Attempt has been logged.",
            "danger",
        )
        return redirect(url_for("admin"))
    # Do not allow deletion of the user making the request
    elif user_id == current_user.id:
        flash(f"Don't delete yourself, you have so much to live for!", "danger")
        return redirect(url_for("admin"))
    # Do not allow deletion of sysadmin users, unless done by root sysadmin
    elif user["role"] == "sysadmin" and current_user.id != 1:
        flash(f"SysAdmin users can't be deleted.", "danger")
        return redirect(url_for("admin"))

    else:
        try:
            conn = db_connect()
            conn.execute(
                "UPDATE users SET deleted_at = ? WHERE id = ?", (utc_dt, user_id)
            )
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error", "danger")
        finally:
            conn.close()
        flash(f'User "{user["username"]}" deleted successfully.', "success")
        return redirect(url_for("admin"))


# API Route for restoring a  deleted user
@app.route("/api/restore/<int:user_id>")
@login_required
@admin_required
def restore(user_id):

    if not current_user.is_authenticated:
        flash("You must be logged in to perform this action.", "danger")
        return redirect(url_for("login"))

    print(f"User restore API endpoint hit, requested user ID to delete: {user_id}")
    print(
        f"Requested by user: [{current_user.username}] ({current_user.name} {current_user.lastname})"
    )

    try:
        conn = db_connect()
        user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        user = dict(user)
    except Exception as e:
        print(f"Database error: {e}")
        flash("Database error", "danger")
        return redirect(url_for("admin"))
    finally:
        conn.close()

    if current_user.role == "employee":
        flash("This action is not permitted for employee accounts.", "danger")
        flash("How did you even get here? Get out.", "danger")
        return redirect(url_for("index"))

    else:
        try:
            conn = db_connect()
            conn.execute(
                "UPDATE users SET deleted_at = ? WHERE id = ?", (None, user_id)
            )
            conn.commit()
        except Exception as e:
            print(f"Database error: {e}")
            flash("Database error", "danger")
        finally:
            conn.close()
        flash(f'User "{user["username"]}" restored successfully.', "success")
        return redirect(url_for("admin"))


# API Route for storing information from the contact form
@app.route("/api/contact", methods=["POST"])
def contactAPI():
    print(f"User contact API endpoint hit")
    email = request.form.get("email", "").strip()
    message = request.form.get("message", "").strip()
    ip = request.remote_addr

    utc_dt = str(datetime.now(timezone.utc) + timedelta(hours=2))[:-13]

    try:
        conn = db_connect()
        try:
            row = conn.execute(
                """SELECT * FROM contact WHERE email = ? 
                               AND TIMEDIFF(?, timestamp) < "+0000-00-00 00:01:00" 
                               ORDER BY id DESC LIMIT 1""",
                (email, utc_dt),
            ).fetchone()
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
    elif row != None:
        print(f"User {email} tried to spam the contact form!")
        flash("Gotta wait buddy hehe", "danger")
        return redirect(url_for("contact"))

    try:
        print(f"User {email} sent a message: {message}")
        print("Updating database...")
        conn = db_connect()
        conn.execute(
            """INSERT INTO contact (email, message, ip, timestamp) VALUES (?,?,?,?)""",
            (email, message, ip, utc_dt),
        )
        conn.commit()
        conn.close()
        flash("Message sent successfully!", "success")
    except Exception as e:
        flash("Database error", "danger")
        print(f"Database error: {e}")
        conn.close()
        return redirect(url_for("contact"))

    return redirect(url_for("contact"))


################################################### CONFIG #####################################################

# Config, app runs locally on port 5000. NGINX proxies outisde requests to this port, and sends the apps response back to the client.
if __name__ == "__main__":
    app.run(
        debug=True, port=5000, host="127.0.0.1", request_handler=ProxiedRequestHandler
    )
