from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
from functools import wraps
import secrets

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# Database configuration
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///blockinspect.db"  # SQLite database
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Initialize the database
db = SQLAlchemy(app)


# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    role = db.Column(db.String(20), nullable=False)


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
            if not user or user.role not in roles:
                flash("You do not have permission to access this page", "danger")
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
        role = request.form.get("role")

        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash("Username already exists", "danger")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already exists", "danger")
            return render_template("register.html")

        # Create new user
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username, email=email, password=hashed_password, role=role
        )
        db.session.add(new_user)
        db.session.commit()

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Find user by username
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            session["username"] = user.username
            session["role"] = user.role
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")

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
    users = {
        user.id: user for user in User.query.all()
    }  # Fetch all users and map them by their IDs
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
