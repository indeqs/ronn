from dotenv import load_dotenv
load_dotenv()

import os
from flask import Flask, render_template, request, redirect, url_for, flash, session, current_app
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps
import secrets
from utils.email_sender import generate_verification_code, send_verification_code

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blockinspect.db"  # SQLite database
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Email Configuration (Use Environment Variables in Production!) ---
app.config["EMAIL_USERNAME"] = os.environ.get("EMAIL_USER") # Replace or set env var
app.config["EMAIL_PASSWORD"] = os.environ.get("EMAIL_PASS") # Replace or set env var (Use App Password for Gmail)
app.config["SMTP_SERVER"] = os.environ.get("SMTP_SERV")
app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT")) # Ensure it's an int
app.config["OTP_EXPIRY_MINUTES"] = 10 # OTP validity duration

# Initialize the database
db = SQLAlchemy(app)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)
    # New fields for OTP verification
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    otp_code = db.Column(db.String(6), nullable=True) # Store the OTP
    otp_expiry = db.Column(db.DateTime, nullable=True) # Store OTP expiry time


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(200), nullable=False)
    start_date = db.Column(db.Date, nullable=False)
    end_date = db.Column(db.Date, nullable=True)
    status = db.Column(db.String(20), nullable=False, default="Active")
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)


class Inspection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    inspector_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default="Completed")
    notes = db.Column(db.Text, nullable=True)
    blockchain_tx_hash = db.Column(db.String(200), nullable=True)


# Create database tables
with app.app_context():
    db.create_all()


# Decorators
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page", "warning")
            return redirect(url_for("login"))
        # Optional: Check if user still exists and is verified
        user = User.query.get(session.get("user_id"))
        if not user or not user.email_verified:
             flash("Please complete email verification or login again.", "warning")
             session.clear() # Log them out if not verified
             return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to access this page", "warning")
                return redirect(url_for("login"))

            user = User.query.get(session["user_id"])
             # Check if user exists, is verified, and has the role
            if not user or not user.email_verified or user.role not in roles:
                flash("You do not have permission to access this page or need to verify your email.", "danger")
                # Decide where to redirect - dashboard or login?
                # If they are logged in but wrong role, dashboard is fine.
                # If not verified, maybe login is better. Let's stick to dashboard for simplicity now.
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role") # Ensure role is selected in the form

        # Input validation (basic)
        if not all([username, email, password, role]):
             flash("All fields are required.", "danger")
             return render_template("register.html")
        if role not in ['engineer', 'inspector', 'admin']: # Validate role
             flash("Invalid role selected.", "danger")
             return render_template("register.html")

        # Check if username or email already exists
        existing_user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        if existing_user:
            if existing_user.username == username:
                flash("Username already exists", "danger")
            if existing_user.email == email:
                flash("Email already registered", "danger")
            return render_template("register.html")

        # Generate OTP and expiry
        otp = generate_verification_code()
        otp_expiry = datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])

        # Create new user (but don't mark as verified yet)
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role,
            email_verified=False, # Important: Start as unverified
            otp_code=otp,
            otp_expiry=otp_expiry
        )

        # Try sending the verification email *before* saving the user
        try:
            # Need app context for email sending
            with app.app_context():
                email_sent = send_verification_code(email, otp)

            if not email_sent:
                # Log the error internally if possible (already done in send_email)
                flash("Could not send verification email. Please check the email address or contact support.", "danger")
                # Don't save the user if email fails critically
                return render_template("register.html")

            # Email sent successfully, now save the user
            db.session.add(new_user)
            db.session.commit()

            # Store email in session to know who is verifying
            session['verification_email'] = email

            flash(f"Registration successful! Please check your email ({email}) for a verification code.", "info")
            return redirect(url_for("verify_otp")) # Redirect to OTP verification page

        except Exception as e:
            db.session.rollback() # Rollback DB changes if any error occurs
            current_app.logger.error(f"Error during registration for {email}: {e}")
            flash("An unexpected error occurred during registration. Please try again.", "danger")
            return render_template("register.html")


    return render_template("register.html")

@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    # Check if we know which email to verify
    email_to_verify = session.get('verification_email')
    if not email_to_verify:
        flash("Verification session expired or invalid. Please register or login again.", "warning")
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email_to_verify, email_verified=False).first()

    if not user:
        flash("User not found or already verified. Try logging in.", "warning")
        session.pop('verification_email', None) # Clean up session
        return redirect(url_for('login'))

    if request.method == "POST":
        submitted_otp = request.form.get("otp")

        if not submitted_otp:
            flash("Please enter the OTP code.", "warning")
            return render_template("verify_otp.html", email=email_to_verify)

        # Check OTP correctness and expiry
        if user.otp_code == submitted_otp and user.otp_expiry > datetime.utcnow():
            # OTP is correct and not expired
            user.email_verified = True
            user.otp_code = None # Clear OTP fields after successful verification
            user.otp_expiry = None
            db.session.commit()

            session.pop('verification_email', None) # Clean up session
            flash("Email verified successfully! You can now login.", "success")
            return redirect(url_for("login"))
        elif user.otp_expiry <= datetime.utcnow():
            flash("OTP has expired. Please request a new one.", "danger")
            # Optionally redirect to a resend route or show resend button
            return render_template("verify_otp.html", email=email_to_verify, show_resend=True) # Add show_resend flag
        else:
            flash("Invalid OTP code. Please try again.", "danger")
            return render_template("verify_otp.html", email=email_to_verify)

    # GET request
    return render_template("verify_otp.html", email=email_to_verify)


@app.route("/resend_otp", methods=["POST"])
def resend_otp():
    email_to_verify = session.get('verification_email')
    if not email_to_verify:
        flash("Verification session expired. Please register or login again.", "warning")
        return redirect(url_for('register'))

    user = User.query.filter_by(email=email_to_verify, email_verified=False).first()

    if not user:
        flash("User not found or already verified.", "warning")
        session.pop('verification_email', None)
        return redirect(url_for('login'))

    # Generate new OTP and update expiry
    otp = generate_verification_code()
    otp_expiry = datetime.utcnow() + timedelta(minutes=app.config['OTP_EXPIRY_MINUTES'])
    user.otp_code = otp
    user.otp_expiry = otp_expiry

    try:
         # Need app context for email sending
        with app.app_context():
            email_sent = send_verification_code(user.email, otp)

        if not email_sent:
            flash("Could not resend verification email. Please contact support.", "danger")
            # Don't commit the new OTP if sending failed
            return redirect(url_for('verify_otp')) # Stay on verify page

        # Commit the new OTP details only if email sent successfully
        db.session.commit()
        flash(f"A new verification code has been sent to {user.email}.", "info")

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error resending OTP for {user.email}: {e}")
        flash("An error occurred while resending the OTP.", "danger")

    return redirect(url_for('verify_otp'))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
             flash("Username and password are required.", "warning")
             return render_template("login.html")

        # Find user by username
        user = User.query.filter_by(username=username).first()

        if user:
             # Check if email is verified FIRST
             if not user.email_verified:
                 flash("Your email is not verified. Please check your inbox for the verification code or request a new one.", "warning")
                 # Store email in session so verify_otp page knows who it is
                 session['verification_email'] = user.email
                 return redirect(url_for('verify_otp')) # Send them to verify

             # Now check password
             if check_password_hash(user.password, password):
                 # Password correct, log them in
                 session["user_id"] = user.id
                 session["username"] = user.username
                 session["role"] = user.role
                 # Clear any lingering verification email from session
                 session.pop('verification_email', None)
                 flash("Login successful!", "success")
                 return redirect(url_for("dashboard"))
             else:
                 # Incorrect password
                 flash("Invalid username or password", "danger")
        else:
             # User not found
             flash("Invalid username or password", "danger")

    # GET request
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = User.query.get(session["user_id"])
    projects = (
        Project.query.filter_by(owner_id=user.id).all()
        if user.role == "engineer"
        else Project.query.all()
    )
    inspections = Inspection.query.all()

    # Add the related project and inspector to each inspection
    for inspection in inspections:
        inspection.project = Project.query.get(inspection.project_id)
        inspection.inspector = User.query.get(inspection.inspector_id)

    return render_template(
        "dashboard.html", user=user, projects=projects, inspections=inspections
    )

@app.route("/projects")
@login_required
def projects_list():
    user = User.query.get(session["user_id"])
    projects = (
        Project.query.all()
        if user.role == "admin"
        else Project.query.filter_by(owner_id=user.id).all()
    )
    return render_template("projects.html", projects=projects)


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    inspections = Inspection.query.filter_by(project_id=project.id).all()
    users = {user.id: user for user in User.query.all()}  # Fetch all users and map them by their IDs

    # Add the inspector object to each inspection
    for inspection in inspections:
        inspection.inspector = users.get(inspection.inspector_id)

    return render_template(
        "project_detail.html", project=project, inspections=inspections, users=users
    )


@app.route("/create_project", methods=["GET", "POST"])
@login_required
@role_required("admin", "engineer")
def create_project():
    if request.method == "POST":
        name = request.form.get("name")
        description = request.form.get("description")
        location = request.form.get("location")
        start_date = datetime.strptime(request.form.get("start_date"), "%Y-%m-%d")
        end_date = request.form.get("end_date")
        end_date = datetime.strptime(end_date, "%Y-%m-%d") if end_date else None

        new_project = Project(
            name=name,
            description=description,
            location=location,
            start_date=start_date,
            end_date=end_date,
            owner_id=session["user_id"],
        )
        db.session.add(new_project)
        db.session.commit()

        flash("Project created successfully", "success")
        return redirect(url_for("project_detail", project_id=new_project.id))

    return render_template("create_project.html")


@app.route("/inspections/<int:inspection_id>")
@login_required
def inspection_detail(inspection_id):
    inspection = Inspection.query.get_or_404(inspection_id)
    project = Project.query.get(inspection.project_id)
    inspector = User.query.get(inspection.inspector_id)

    return render_template(
        "inspection_detail.html",
        inspection=inspection,
        project=project,
        inspector=inspector,
    )


@app.route("/create_inspection/<int:project_id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "inspector", "engineer")
def create_inspection(project_id):
    project = Project.query.get_or_404(project_id)

    if request.method == "POST":
        notes = request.form.get("notes")
        categories = {
            "structural": request.form.get("structural"),
            "electrical": request.form.get("electrical"),
            "plumbing": request.form.get("plumbing"),
            "safety": request.form.get("safety"),
        }

        new_inspection = Inspection(
            project_id=project.id,
            inspector_id=session["user_id"],
            notes=notes,
            blockchain_tx_hash=None,  # Placeholder for blockchain integration
        )
        db.session.add(new_inspection)
        db.session.commit()

        flash("Inspection created successfully", "success")
        return redirect(url_for("project_detail", project_id=project.id))

    return render_template("create_inspection.html", project=project)


if __name__ == "__main__":
    app.run(debug=True)
