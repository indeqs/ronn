from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

import os
import uuid
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    current_app,
    jsonify,  # Added for potential future AJAX
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, date  # Import date
from functools import wraps
import secrets
from utils.email_sender import (
    generate_verification_code,
    send_verification_code,
    send_email,
)

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# --- Database Configuration ---
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
    "DATABASE_URL", "sqlite:///blockinspect.db"
)  # Use DATABASE_URL env var if set
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- Email Configuration ---
app.config["EMAIL_USERNAME"] = os.environ.get("EMAIL_USER")
app.config["EMAIL_PASSWORD"] = os.environ.get("EMAIL_PASS")
app.config["SMTP_SERVER"] = os.environ.get(
    "SMTP_SERV", "smtp.gmail.com"
)  # Default SMTP server
app.config["SMTP_PORT"] = int(os.environ.get("SMTP_PORT", 587))  # Default SMTP port
app.config["OTP_EXPIRY_MINUTES"] = 10

# --- Application Specific Config ---
app.config["PROJECT_TYPES"] = [
    "Residential House",
    "Commercial Building",
    "Road Construction",
    "Renovation",
    "Infrastructure",
]
app.config["PROJECT_LOCATIONS"] = [
    "City Center",
    "Suburb North",
    "Suburb South",
    "Industrial Zone",
    "Rural Area West",
    "Coastal Region",
]
app.config["PROJECT_PHASES"] = [
    "Planning",
    "Design",
    "Foundation",
    "Framing",
    "Exterior",
    "Interior",
    "MEP",
    "Finishing",
    "Testing",
    "Completed",
    "On Hold",
]

# Initialize the database
db = SQLAlchemy(app)


# --- Models ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # engineer, client, admin
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    otp_code = db.Column(db.String(6), nullable=True)
    otp_expiry = db.Column(db.DateTime, nullable=True)
    is_banned = db.Column(db.Boolean, default=False, nullable=False)

    # Relationships
    # Projects owned by this user (engineer/admin)
    projects_owned = db.relationship(
        "Project", backref="owner", lazy=True, foreign_keys="Project.owner_id"
    )
    # Inspections conducted by this user (engineer/admin)
    inspections_conducted = db.relationship(
        "Inspection",
        backref="inspector",
        lazy=True,
        foreign_keys="Inspection.inspector_id",
    )


class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    project_type = db.Column(db.String(50), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100), nullable=False)
    start_date = db.Column(db.Date, nullable=False, default=date.today)
    end_date = db.Column(db.Date, nullable=True)
    phase = db.Column(db.String(50), nullable=False, default="Planning")
    status = db.Column(
        db.String(20), nullable=False, default="Active"
    )  # Active, On Hold, Completed
    # Foreign Keys
    owner_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )  # Engineer/Admin who created it
    client_name = db.Column(db.String(150), nullable=False)

    # Relationship
    inspections = db.relationship(
        "Inspection", backref="project", lazy=True, cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<Project {self.name}>"


# Model for Password Reset Tokens
class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expiry = db.Column(db.DateTime, nullable=False)

    def is_expired(self):
        return datetime.utcnow() > self.expiry

    def __repr__(self):
        return f"<PasswordResetToken for User {self.user_id}>"


class Inspection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey("project.id"), nullable=False)
    inspector_id = db.Column(
        db.Integer, db.ForeignKey("user.id"), nullable=False
    )  # Engineer/Admin who created it
    date = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    structural_completion = db.Column(db.Integer, nullable=True)  # Percentage 0-100
    electrical_completion = db.Column(db.Integer, nullable=True)  # Percentage 0-100
    plumbing_completion = db.Column(db.Integer, nullable=True)  # Percentage 0-100
    safety_compliance = db.Column(db.Integer, nullable=True)  # Percentage 0-100
    status = db.Column(
        db.String(20), nullable=False, default="Recorded"
    )  # e.g., Recorded, Needs Review, Passed
    blockchain_tx_hash = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<Inspection {self.id} for Project {self.project_id}>"


# --- Database Creation ---
# IMPORTANT: Schema changed (Project.client_id added). Delete blockinspect.db OR use migrations.
with app.app_context():
    db.create_all()
    print("Database tables checked/created.")

# --- Context Processors ---


# Make the current user available globally in templates
@app.context_processor
def inject_user():
    if "user_id" in session:
        return dict(current_user=User.query.get(session["user_id"]))
    return dict(current_user=None)


# Inject the 'now' function (datetime.utcnow) into templates for the year
@app.context_processor
def inject_now():
    return {"now": datetime.utcnow}  # Use utcnow for consistency


# --- Decorators ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page.", "warning")
            return redirect(url_for("login"))
        user = User.query.get(session.get("user_id"))
        if not user:
            flash("User not found. Please login again.", "warning")
            session.clear()
            return redirect(url_for("login"))
        # --- Check if banned ---
        if user.is_banned:
            flash("Your account has been suspended. Please contact support.", "danger")
            session.clear()  # Log them out
            return redirect(url_for("login"))
        # --- End Banned Check ---
        if not user.email_verified:
            flash("Please complete email verification first.", "warning")
            if "verification_email" not in session:
                session["verification_email"] = user.email
            return redirect(url_for("verify_otp"))
        return f(*args, **kwargs)

    return decorated_function


def role_required(*roles):  # Outer function takes arguments
    # This function ('decorator') IS the actual decorator returned by the factory
    def decorator(f):  # 'f' is defined here; 'decorator' is defined here
        @wraps(f)  # This MUST be indented under 'decorator'
        def decorated_function(
            *args, **kwargs
        ):  # This MUST be indented under 'decorator'
            # --- Start of decorated_function's block ---
            user = User.query.get(
                session.get("user_id")
            )  # Assumes login_required runs first
            if not user or user.role not in roles:
                flash("You do not have permission to access this page.", "danger")
                return redirect(url_for("dashboard"))
            # Call the original function 'f'
            return f(*args, **kwargs)
            # --- End of decorated_function's block ---

        # This MUST be indented under 'decorator', aligned with @wraps and def decorated_function
        return decorated_function

    # This MUST be indented under 'role_required', aligned with def decorator
    return decorator  # Returns the 'decorator' function


# --- Helper Function ---
def get_current_user():
    if "user_id" in session:
        return User.query.get(session["user_id"])
    return None


@app.context_processor
def inject_user():
    return dict(current_user=get_current_user())


# --- Routes ---
@app.route("/")
def index():
    return render_template("index.html")


# (register, verify_otp, resend_otp, login, logout routes remain the same as previous version)
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")  # Get confirm password
        role = request.form.get("role")

        # --- Backend Validation ---
        errors = {}
        if (
            not username
            or not (3 <= len(username) <= 20)
            or not username.replace("_", "").isalnum()
        ):
            errors["username"] = (
                "Username must be 3-20 chars (letters, numbers, underscore)."
            )
        if not email:  # Basic check, more robust email validation could be added
            errors["email"] = "Email is required."
        if not password or len(password) < 8:
            errors["password"] = "Password must be at least 8 characters."
        if password != confirm_password:  # Check password match
            errors["confirm_password"] = "Passwords do not match."
        if role not in ["engineer", "client", "admin"]:
            errors["role"] = "Invalid role selected."

        # Check existence (only if basic validation passes for username/email)
        if "username" not in errors and User.query.filter_by(username=username).first():
            errors["username"] = "Username already exists."
        if "email" not in errors and User.query.filter_by(email=email).first():
            # Handle existing but unverified user
            existing_user = User.query.filter_by(email=email).first()
            if existing_user and not existing_user.email_verified:
                flash(
                    "This email is registered but not verified. Check your email or resend OTP.",
                    "warning",
                )
                session["verification_email"] = email
                return redirect(url_for("verify_otp"))
            elif existing_user:
                errors["email"] = "Email already registered."

        if errors:
            for field, msg in errors.items():
                flash(f"{msg}", "danger")  # Flash each error
            # Return form with user's input (except passwords)
            return render_template("register.html", request_form=request.form)
        # --- End Backend Validation ---

        # Generate OTP & Hash Password (only if validation passed)
        otp = generate_verification_code()
        otp_expiry = datetime.utcnow() + timedelta(
            minutes=app.config["OTP_EXPIRY_MINUTES"]
        )
        hashed_password = generate_password_hash(password)

        new_user = User(
            username=username,
            email=email,
            password=hashed_password,
            role=role,
            email_verified=False,
            otp_code=otp,
            otp_expiry=otp_expiry,
        )

        try:
            with app.app_context():
                email_sent = send_verification_code(email, otp)

            if not email_sent:
                flash("Could not send verification email.", "danger")
                return render_template("register.html", request_form=request.form)

            db.session.add(new_user)
            db.session.commit()

            session["verification_email"] = email
            flash(
                f"Registration successful! Check {email} for a verification code.",
                "info",
            )
            return redirect(url_for("verify_otp"))

        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Registration Error for {email}: {e}")
            flash("An unexpected error occurred.", "danger")
            return render_template("register.html", request_form=request.form)

    # GET request
    return render_template("register.html", request_form={})  # Pass empty dict on GET


# --- OTP Verification Routes ---
@app.route("/verify_otp", methods=["GET", "POST"])
def verify_otp():
    email_to_verify = session.get("verification_email")
    if not email_to_verify:
        flash(
            "Verification session expired or invalid. Please register or login.",
            "warning",
        )
        return redirect(url_for("register"))

    user = User.query.filter_by(
        email=email_to_verify
    ).first()  # Find user regardless of verified status initially

    if not user:
        # Should not happen if registration worked, but handle defensively
        flash("User associated with this verification request not found.", "danger")
        session.pop("verification_email", None)
        return redirect(url_for("register"))

    if user.email_verified:
        flash("Email already verified. Please login.", "info")
        session.pop("verification_email", None)
        return redirect(url_for("login"))

    if request.method == "POST":
        submitted_otp = request.form.get("otp")
        if not submitted_otp:
            flash("Please enter the OTP code.", "warning")
            return render_template("verify_otp.html", email=email_to_verify)

        # Check OTP
        now = datetime.utcnow()
        if user.otp_code == submitted_otp and user.otp_expiry and user.otp_expiry > now:
            user.email_verified = True
            user.otp_code = None  # Clear OTP info
            user.otp_expiry = None
            db.session.commit()

            session.pop("verification_email", None)
            flash("Email verified successfully! You can now login.", "success")
            return redirect(url_for("login"))
        elif user.otp_expiry and user.otp_expiry <= now:
            flash("OTP has expired. Please request a new one.", "danger")
            return render_template(
                "verify_otp.html", email=email_to_verify, show_resend=True
            )
        else:
            flash("Invalid OTP code.", "danger")
            return render_template("verify_otp.html", email=email_to_verify)

    # GET request
    return render_template("verify_otp.html", email=email_to_verify)


@app.route("/resend_otp", methods=["POST"])
def resend_otp():
    email_to_verify = session.get("verification_email")
    if not email_to_verify:
        flash("Verification session expired. Please register or login.", "warning")
        return redirect(url_for("register"))

    user = User.query.filter_by(email=email_to_verify, email_verified=False).first()
    if not user:
        flash("User not found or already verified.", "warning")
        session.pop("verification_email", None)
        return redirect(url_for("login"))

    # Generate new OTP
    otp = generate_verification_code()
    otp_expiry = datetime.utcnow() + timedelta(minutes=app.config["OTP_EXPIRY_MINUTES"])
    user.otp_code = otp
    user.otp_expiry = otp_expiry

    try:
        with app.app_context():  # Ensure app context
            email_sent = send_verification_code(user.email, otp)
        if not email_sent:
            flash("Could not resend verification email. Contact support.", "danger")
            # Don't commit the new OTP if sending failed
            return redirect(url_for("verify_otp"))

        # Commit new OTP details
        db.session.commit()
        flash(f"A new verification code sent to {user.email}.", "info")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Resend OTP Error for {user.email}: {e}")
        flash("An error occurred resending OTP.", "danger")

    return redirect(url_for("verify_otp"))


# --- Login/Logout ---
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            flash("Username and password required.", "warning")
            return render_template("login.html")

        user = User.query.filter_by(username=username).first()

        if user:
            # --- Check if banned BEFORE checking password ---
            if user.is_banned:
                flash(
                    "Your account has been suspended. Please contact support.", "danger"
                )
                return render_template("login.html")
            # --- End Banned Check ---

            if not user.email_verified:
                flash("Email not verified. Check your inbox or resend OTP.", "warning")
                session["verification_email"] = user.email
                return redirect(url_for("verify_otp"))

            if check_password_hash(user.password, password):
                session.clear()  # Clear old session data
                session["user_id"] = user.id
                session["username"] = user.username
                session["role"] = user.role
                flash("Login successful!", "success")
                # Redirect admin to admin dashboard, others to regular dashboard
                if user.role == "admin":
                    return redirect(url_for("admin_dashboard"))
                else:
                    return redirect(url_for("dashboard"))
            else:
                flash("Invalid username or password.", "danger")
        else:
            flash("Invalid username or password.", "danger")

    return render_template("login.html")


# --- Admin Routes ---
@app.route("/admin")
@login_required
@role_required("admin")
def admin_dashboard():
    # Fetch some stats for admin dashboard
    user_count = User.query.count()
    project_count = Project.query.count()
    inspection_count = Inspection.query.count()
    banned_count = User.query.filter_by(is_banned=True).count()
    return render_template(
        "admin/admin_dashboard.html",
        user_count=user_count,
        project_count=project_count,
        inspection_count=inspection_count,
        banned_count=banned_count,
    )


@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    page = request.args.get("page", 1, type=int)
    users = User.query.order_by(User.username).paginate(
        page=page, per_page=15
    )  # Paginate users
    return render_template("admin/admin_users.html", users=users)


@app.route("/admin/projects")
@login_required
@role_required("admin")
def admin_projects():
    page = request.args.get("page", 1, type=int)
    # Paginate projects, eager load owner and client for efficiency
    projects = (
        Project.query.options(
            db.joinedload(Project.owner), db.joinedload(Project.client)
        )
        .order_by(Project.start_date.desc())
        .paginate(page=page, per_page=15)
    )
    return render_template("admin/admin_projects.html", projects=projects)


# Ban/Unban User Routes (Use POST for actions that change state)
@app.route("/admin/users/<int:user_id>/ban", methods=["POST"])
@login_required
@role_required("admin")
def ban_user(user_id):
    user_to_ban = User.query.get_or_404(user_id)
    admin_user = get_current_user()

    # Prevent admin from banning themselves or another admin (optional rule)
    if user_to_ban.id == admin_user.id:
        flash("You cannot ban yourself.", "danger")
    elif user_to_ban.role == "admin":
        flash("Administrators cannot be banned through this interface.", "warning")
    else:
        user_to_ban.is_banned = True
        db.session.commit()
        flash(f"User '{user_to_ban.username}' has been banned.", "success")

    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:user_id>/unban", methods=["POST"])
@login_required
@role_required("admin")
def unban_user(user_id):
    user_to_unban = User.query.get_or_404(user_id)
    user_to_unban.is_banned = False
    db.session.commit()
    flash(f"User '{user_to_unban.username}' has been unbanned.", "success")
    return redirect(url_for("admin_users"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


# Helper function to generate a unique token
def generate_reset_token():
    return str(uuid.uuid4())


@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email")
        user = User.query.filter_by(
            email=email, email_verified=True, is_banned=False
        ).first()  # Ensure user exists, verified, and not banned

        if user:
            # Generate token and expiry
            token_str = generate_reset_token()
            expiry_time = datetime.utcnow() + timedelta(
                hours=1
            )  # Token valid for 1 hour

            # Delete any existing tokens for this user
            PasswordResetToken.query.filter_by(user_id=user.id).delete()

            # Create new token
            new_token = PasswordResetToken(
                user_id=user.id, token=token_str, expiry=expiry_time
            )
            db.session.add(new_token)
            db.session.commit()

            # Send reset email
            reset_url = url_for(
                "reset_password", token=token_str, _external=True
            )  # _external=True gives full URL
            subject = "Password Reset Request for BlockInspect"
            # Consider using render_template for email body for better formatting
            body = f"""Hello {user.username},

You requested a password reset for your BlockInspect account.
Click the link below to set a new password. This link is valid for 1 hour:

{reset_url}

If you did not request this, please ignore this email.

Regards,
BlockInspect Team
"""
            try:
                with app.app_context():  # Ensure context for send_email
                    email_sent = send_email(user.email, subject, body)
                if not email_sent:
                    flash(
                        "Could not send password reset email. Please try again later or contact support.",
                        "danger",
                    )
                else:
                    flash(
                        "Password reset instructions have been sent to your email address.",
                        "info",
                    )
            except Exception as e:
                current_app.logger.error(
                    f"Error sending password reset email to {user.email}: {e}"
                )
                flash("An error occurred while sending the reset email.", "danger")

            # Always redirect to login page after attempt, regardless of success, to prevent email enumeration
            return redirect(url_for("login"))
        else:
            # User not found or not eligible, show generic message
            flash(
                "If an account with that email exists and is verified, reset instructions have been sent.",
                "info",
            )
            return redirect(url_for("login"))  # Redirect to login

    # GET request
    return render_template("forgot_password.html")


@app.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password(token):
    token_entry = PasswordResetToken.query.filter_by(token=token).first()

    # Validate token existence and expiry
    if not token_entry or token_entry.is_expired():
        flash(
            "Invalid or expired password reset link. Please request a new one.",
            "danger",
        )
        return redirect(url_for("forgot_password"))

    user = User.query.get(token_entry.user_id)
    if not user or user.is_banned:  # Also check if user still exists and is not banned
        flash("Associated user account not found or inactive.", "danger")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        errors = {}
        if not password or len(password) < 8:
            errors["password"] = "Password must be at least 8 characters."
        if password != confirm_password:
            errors["confirm_password"] = "Passwords do not match."

        if errors:
            for field, msg in errors.items():
                flash(msg, "danger")
            # Pass token back to template for the form action URL
            return render_template("reset_password.html", token=token)

        # Update user's password
        user.password = generate_password_hash(password)

        # Delete the used token
        db.session.delete(token_entry)
        db.session.commit()

        flash(
            "Your password has been successfully reset! You can now login.", "success"
        )
        return redirect(url_for("login"))

    # GET request
    return render_template("reset_password.html", token=token)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        # Process contact form data (e.g., send email)
        name = request.form.get("name")
        email = request.form.get("email")
        subject = request.form.get("subject")
        message = request.form.get("message")

        # Basic validation
        if not all([name, email, subject, message]):
            flash("Please fill out all fields.", "danger")
            return render_template("contact.html", form_data=request.form)

        # Placeholder: Send email or save to DB
        print(
            f"Contact Form Submission:\nName: {name}\nEmail: {email}\nSubject: {subject}\nMessage: {message}"
        )
        flash("Thank you for your message! We will get back to you soon.", "success")
        return redirect(
            url_for("contact")
        )  # Redirect after POST to prevent re-submission

    # GET request
    return render_template("contact.html", form_data={})


# --- Core Application Routes ---
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_current_user()
    projects = []
    inspections = []

    if user.role == "admin":
        projects = Project.query.order_by(Project.start_date.desc()).all()
        inspections = Inspection.query.order_by(Inspection.date.desc()).limit(10).all()
    elif user.role == "engineer":
        projects = (
            Project.query.filter_by(owner_id=user.id)
            .order_by(Project.start_date.desc())
            .all()
        )
        project_ids = [p.id for p in projects]
        # Show inspections owned by engineer OR for projects owned by engineer
        inspections = (
            Inspection.query.filter(
                (Inspection.inspector_id == user.id)
                | (Inspection.project_id.in_(project_ids))
            )
            .order_by(Inspection.date.desc())
            .limit(10)
            .all()
        )
    # elif user.role == "client":
    #     # Clients see projects where they are the client_id
    #     projects = (
    #         Project.query.filter_by(client_id=user.id)
    #         .order_by(Project.start_date.desc())
    #         .all()
    #     )
    #     project_ids = [p.id for p in projects]
    #     # Clients see inspections only for their projects
    #     if project_ids:
    #         inspections = (
    #             Inspection.query.filter(Inspection.project_id.in_(project_ids))
    #             .order_by(Inspection.date.desc())
    #             .limit(10)
    #             .all()
    #         )
    #     else:
    #         inspections = []

    return render_template(
        "dashboard.html", user=user, projects=projects, inspections=inspections
    )


@app.route("/projects")
@login_required
def projects_list():
    user = get_current_user()
    projects = []
    if user.role == "admin":
        projects = Project.query.order_by(Project.start_date.desc()).all()
    elif user.role == "engineer":
        projects = (
            Project.query.filter_by(owner_id=user.id)
            .order_by(Project.start_date.desc())
            .all()
        )
    elif user.role == "client":
        projects = (
            Project.query.filter_by(client_id=user.id)
            .order_by(Project.start_date.desc())
            .all()
        )

    return render_template("projects.html", projects=projects)


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    project = Project.query.get_or_404(project_id)
    user = get_current_user()

    # Authorization Check
    can_view = False
    if user.role == "admin":
        can_view = True
    elif user.role == "engineer" and project.owner_id == user.id:
        can_view = True
    # elif user.role == "client" and project.client_id == user.id:  # Client access check
    #     can_view = True

    if not can_view:
        flash("You do not have permission to view this project.", "danger")
        return redirect(url_for("projects_list"))

    inspections = (
        Inspection.query.filter_by(project_id=project.id)
        .order_by(Inspection.date.desc())
        .all()
    )

    return render_template(
        "project_detail.html",
        project=project,
        inspections=inspections,
    )


@app.route("/create_project", methods=["GET", "POST"])
@login_required
@role_required("admin", "engineer")
def create_project():
    user = get_current_user()
    # No need to query clients anymore
    # clients = User.query.filter_by(role='client', email_verified=True, is_banned=False).order_by(User.username).all()

    if request.method == "POST":
        name = request.form.get("name")
        project_type = request.form.get("project_type")
        description = request.form.get("description")
        location = request.form.get("location")
        start_date_str = request.form.get("start_date")
        end_date_str = request.form.get("end_date")
        phase = request.form.get("phase", "Planning")
        client_name = request.form.get("client_name")  # Get client_name input

        # --- Backend Validation ---
        errors = {}
        if not name:
            errors["name"] = "Project Name is required."
        if not project_type or project_type not in app.config["PROJECT_TYPES"]:
            errors["project_type"] = "Valid Project Type is required."
        if not description:
            errors["description"] = "Description is required."
        if not location or location not in app.config["PROJECT_LOCATIONS"]:
            errors["location"] = "Valid Location is required."
        if not client_name:
            errors["client_name"] = "Client Name is required."  # Now required
        # ... (keep date and phase validation as before) ...
        if not start_date_str:
            errors["start_date"] = "Start Date is required."
        else:
            try:
                start_date = date.fromisoformat(start_date_str)
            except ValueError:
                errors["start_date"] = "Invalid Start Date format."
        # Validate end date only if provided
        end_date = None
        if end_date_str:
            try:
                end_date = date.fromisoformat(end_date_str)
                if (
                    "start_date" not in errors
                    and "start_date" in locals()
                    and end_date < start_date
                ):
                    errors["end_date"] = "End Date cannot be before Start Date."
            except ValueError:
                errors["end_date"] = "Invalid End Date format."

        if not phase or phase not in app.config["PROJECT_PHASES"]:
            errors["phase"] = "Valid Phase is required."

        if errors:
            for field, msg in errors.items():
                flash(msg, "danger")
            return render_template(
                "create_project.html",
                project_types=app.config["PROJECT_TYPES"],
                locations=app.config["PROJECT_LOCATIONS"],
                phases=app.config["PROJECT_PHASES"],
                # Don't pass clients anymore
                request_form=request.form,
            )  # Pass form back
        # --- End Validation ---

        # Proceed if no errors
        new_project = Project(
            name=name,
            project_type=project_type,
            description=description,
            location=location,
            start_date=start_date,
            end_date=end_date,
            phase=phase,
            owner_id=user.id,
            client_name=client_name,  # Save the client_name string
            status="Active",
        )
        db.session.add(new_project)
        db.session.commit()

        flash("Project created successfully!", "success")
        return redirect(url_for("project_detail", project_id=new_project.id))

    # GET request
    return render_template(
        "create_project.html",
        project_types=app.config["PROJECT_TYPES"],
        locations=app.config["PROJECT_LOCATIONS"],
        phases=app.config["PROJECT_PHASES"],
        # Don't pass clients anymore
        request_form={},
    )  # Pass empty dict on GET


@app.route("/inspections/<int:inspection_id>")
@login_required
def inspection_detail(inspection_id):
    inspection = Inspection.query.get_or_404(inspection_id)
    user = get_current_user()
    project = inspection.project

    # Authorization: Admin, Engineer (owner/inspector), or Client of the project
    can_view = False
    if user.role == "admin":
        can_view = True
    elif user.role == "engineer" and (
        project.owner_id == user.id or inspection.inspector_id == user.id
    ):
        can_view = True
    # elif user.role == "client" and project.client_id == user.id:  # Client access check
    #     can_view = True

    if not can_view:
        flash("You do not have permission to view this inspection.", "danger")
        # Redirect based on role? Maybe just back to their dashboard.
        if user.role == "client":
            return redirect(
                url_for("project_detail", project_id=project.id)
            )  # Client likely came from project detail
        else:
            return redirect(url_for("dashboard"))

    return render_template(
        "inspection_detail.html",
        inspection=inspection,
    )


@app.route("/create_inspection/<int:project_id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "engineer")
def create_inspection(project_id):
    project = Project.query.get_or_404(project_id)
    user = get_current_user()

    # Authorization check (Admin or Engineer owner)
    if not (
        user.role == "admin"
        or (user.role == "engineer" and project.owner_id == user.id)
    ):
        flash(
            "You do not have permission to create inspections for this project.",
            "danger",
        )
        return redirect(url_for("project_detail", project_id=project.id))

    if request.method == "POST":
        notes = request.form.get("notes")
        # Attempt to get percentages as integers, default to None if empty/invalid format
        structural = request.form.get("structural_completion")
        electrical = request.form.get("electrical_completion")
        plumbing = request.form.get("plumbing_completion")
        safety = request.form.get("safety_compliance")
        status = request.form.get("status", "Recorded")

        # --- Percentage Validation ---
        perc_fields = {
            "Structural": structural,
            "Electrical": electrical,
            "Plumbing": plumbing,
            "Safety": safety,
        }
        validated_percentages = {}
        validation_passed = True

        for name, val_str in perc_fields.items():
            if not val_str:  # Treat empty string as None (not entered)
                validated_percentages[name.lower()] = None
                continue
            try:
                val_int = int(val_str)
                if not (0 <= val_int <= 100):  # Check range 0-100 inclusive
                    flash(f"{name} percentage must be between 0 and 100.", "danger")
                    validation_passed = False
                else:
                    validated_percentages[name.lower()] = val_int
            except ValueError:  # Handle non-integer input
                flash(
                    f"Invalid input for {name} percentage. Please enter a whole number.",
                    "danger",
                )
                validation_passed = False

        if not notes:
            flash("Inspection Notes are required.", "warning")
            validation_passed = False

        if not validation_passed:
            # Re-render form with entered values and flash messages
            return render_template(
                "create_inspection.html", project=project, request_form=request.form
            )

        # --- End Percentage Validation ---

        new_inspection = Inspection(
            project_id=project.id,
            inspector_id=user.id,
            notes=notes,
            structural_completion=validated_percentages.get("structural"),
            electrical_completion=validated_percentages.get("electrical"),
            plumbing_completion=validated_percentages.get("plumbing"),
            safety_compliance=validated_percentages.get("safety"),
            status=status,
            blockchain_tx_hash=None,  # Placeholder
        )
        db.session.add(new_inspection)
        db.session.commit()

        # --- TODO: Blockchain Integration ---
        # 1. Prepare data to be stored (e.g., inspection ID, hash of notes/data, project ID, timestamp)
        # inspection_data_hash = generate_hash(f"{new_inspection.id}-{new_inspection.notes}-{new_inspection.date}")
        # 2. Connect to blockchain network (e.g., using Web3.py and RPC endpoint)
        # 3. Load your smart contract ABI and address
        # 4. Call the smart contract function to record the inspection hash
        #    (Requires signing the transaction with the engineer's/server's private key)
        # try:
        #     tx_receipt = contract.functions.recordInspection(new_inspection.id, inspection_data_hash).transact({'from': YOUR_ACCOUNT_ADDRESS})
        #     tx_hash = tx_receipt['transactionHash'].hex()
        #     # 5. Update the inspection record in *our* DB with the transaction hash
        #     new_inspection.blockchain_tx_hash = tx_hash
        #     db.session.commit()
        #     current_app.logger.info(f"Inspection {new_inspection.id} recorded on blockchain. Tx: {tx_hash}")
        # except Exception as e:
        #     current_app.logger.error(f"Blockchain transaction failed for inspection {new_inspection.id}: {e}")
        #     # Decide how to handle failure: maybe flash a warning, retry later?
        #     flash("Inspection saved, but failed to record on blockchain. Please contact support.", "warning")
        # --- End Blockchain Integration ---

        flash("Inspection recorded successfully!", "success")
        return redirect(url_for("project_detail", project_id=project.id))

    # GET request
    # Pass an empty dict for request_form on GET to avoid errors in template
    return render_template("create_inspection.html", project=project, request_form={})


# --- Main Execution ---
if __name__ == "__main__":
    app.run(debug=True)
    # app.run(debug=os.environ.get("FLASK_DEBUG", "False").lower() == "true")
