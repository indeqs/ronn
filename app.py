from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import os
from functools import wraps
import hashlib
import json

app = Flask(__name__)
app.secret_key = secrets.token_hex(16)

# For demonstration purposes, we'll use simple dictionaries to store data
# In a production app, you would use a proper database
users = {}
projects = {}
inspections = {}


# Sample data for demonstration
def load_sample_data():
    # Create sample users
    users.update(
        {
            1: {
                "id": 1,
                "username": "admin",
                "password": generate_password_hash("admin123"),
                "email": "admin@blockinspect.com",
                "role": "admin",
            },
            2: {
                "id": 2,
                "username": "engineer1",
                "password": generate_password_hash("engineer123"),
                "email": "engineer@blockinspect.com",
                "role": "engineer",
            },
            3: {
                "id": 3,
                "username": "inspector1",
                "password": generate_password_hash("inspector123"),
                "email": "inspector@blockinspect.com",
                "role": "inspector",
            },
        }
    )

    # Create sample projects
    projects.update(
        {
            1: {
                "id": 1,
                "name": "City Center Complex",
                "description": "Multi-story commercial complex with retail and office spaces",
                "location": "Downtown Nairobi",
                "start_date": datetime.now() - timedelta(days=60),
                "end_date": datetime.now() + timedelta(days=300),
                "status": "Active",
                "owner_id": 1,
                "inspections": [],
            },
            2: {
                "id": 2,
                "name": "Green Heights Apartments",
                "description": "Eco-friendly residential complex with solar integration",
                "location": "Westlands, Nairobi",
                "start_date": datetime.now() - timedelta(days=120),
                "end_date": datetime.now() + timedelta(days=180),
                "status": "Active",
                "owner_id": 2,
                "inspections": [],
            },
            3: {
                "id": 3,
                "name": "Riverside Bridge Renovation",
                "description": "Structural repairs and upgrade of existing bridge",
                "location": "Riverside Drive",
                "start_date": datetime.now() - timedelta(days=30),
                "end_date": datetime.now() + timedelta(days=90),
                "status": "On Hold",
                "owner_id": 1,
                "inspections": [],
            },
        }
    )

    # Create sample inspections
    inspections.update(
        {
            1: {
                "id": 1,
                "project_id": 1,
                "inspector_id": 3,
                "date": datetime.now() - timedelta(days=15),
                "status": "Completed",
                "notes": "Foundation work completed according to specifications. All structural elements pass inspection.",
                "blockchain_tx_hash": "0x7d8f5e21c4a9e96bf5eb5de85c46d8a2f701587e9943e5e9ab92b3c1b7c3cb4a",
                "categories": {
                    "structural": "Pass",
                    "electrical": "Not Applicable",
                    "plumbing": "Not Applicable",
                    "safety": "Pass",
                },
            },
            2: {
                "id": 2,
                "project_id": 1,
                "inspector_id": 3,
                "date": datetime.now() - timedelta(days=5),
                "status": "Completed",
                "notes": "Structural framework for floors 1-3 inspected. Minor adjustments needed in section B4.",
                "blockchain_tx_hash": "0x3a2c2e25a7f1b98c7bf3a25d3f9e43b15ab3c2d6e5f8a9b1c4d7e10f2a3b5c8d",
                "categories": {
                    "structural": "Pass with Comments",
                    "electrical": "Not Started",
                    "plumbing": "Not Started",
                    "safety": "Pass",
                },
            },
            3: {
                "id": 3,
                "project_id": 2,
                "inspector_id": 3,
                "date": datetime.now() - timedelta(days=10),
                "status": "Completed",
                "notes": "Foundation and initial framing inspection completed. All elements meet specifications.",
                "blockchain_tx_hash": None,  # Pending blockchain verification
                "categories": {
                    "structural": "Pass",
                    "electrical": "Not Started",
                    "plumbing": "Not Started",
                    "safety": "Pass",
                },
            },
        }
    )

    # Update project inspections lists
    for inspection_id, inspection in inspections.items():
        project_id = inspection["project_id"]
        if project_id in projects:
            projects[project_id]["inspections"].append(inspection_id)


# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to access this page", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


# Role required decorator
def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                flash("Please login to access this page", "warning")
                return redirect(url_for("login"))

            user = users.get(session["user_id"])
            if not user or user["role"] not in roles:
                flash("You do not have permission to access this page", "danger")
                return redirect(url_for("dashboard"))
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# Simulate blockchain transaction
def create_blockchain_record(data):
    # In a real implementation, this would interact with a blockchain network
    # For demo purposes, we just create a hash of the data
    data_string = json.dumps(data, default=str)
    hash_object = hashlib.sha256(data_string.encode())
    return "0x" + hash_object.hexdigest()


# Routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Find user by username
        user_id = None
        for uid, user in users.items():
            if user["username"] == username:
                user_id = uid
                break

        if user_id and check_password_hash(users[user_id]["password"], password):
            session["user_id"] = user_id
            session["username"] = username
            session["role"] = users[user_id]["role"]
            flash("Login successful!", "success")
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", "danger")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        role = request.form.get("role")

        # Check if username or email already exists
        if any(user["username"] == username for user in users.values()):
            flash("Username already exists", "danger")
            return render_template("register.html")

        if any(user["email"] == email for user in users.values()):
            flash("Email already exists", "danger")
            return render_template("register.html")

        # Create new user
        new_id = max(users.keys(), default=0) + 1
        users[new_id] = {
            "id": new_id,
            "username": username,
            "password": generate_password_hash(password),
            "email": email,
            "role": role,
        }

        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    user = users.get(session["user_id"])
    user_projects = []
    user_inspections = []

    # Get projects based on user role
    if user["role"] == "admin":
        # Admin sees all projects
        user_projects = list(projects.values())
        user_inspections = list(inspections.values())
    else:
        # Other roles see specific projects
        for project in projects.values():
            # Engineers see their projects, inspectors and stakeholders see all
            if user["role"] == "engineer" and project["owner_id"] == user["id"]:
                user_projects.append(project)
            elif user["role"] in ["inspector", "stakeholder"]:
                user_projects.append(project)

        # Get inspections for these projects
        for inspection in inspections.values():
            if inspection["project_id"] in [p["id"] for p in user_projects]:
                user_inspections.append(inspection)

    # Add project and inspector objects to inspections for template access
    for inspection in user_inspections:
        inspection["project"] = projects.get(inspection["project_id"])
        inspection["inspector"] = users.get(inspection["inspector_id"])

    return render_template(
        "dashboard.html",
        user=user,
        projects=user_projects,
        inspections=user_inspections,
    )


@app.route("/projects")
@login_required
def projects_list():
    user = users.get(session["user_id"])
    user_projects = []

    if user["role"] == "admin":
        user_projects = list(projects.values())
    else:
        for project in projects.values():
            if user["role"] == "engineer" and project["owner_id"] == user["id"]:
                user_projects.append(project)
            elif user["role"] in ["inspector", "stakeholder"]:
                user_projects.append(project)

    return render_template("projects.html", projects=user_projects)


@app.route("/projects/<int:project_id>")
@login_required
def project_detail(project_id):
    project = projects.get(project_id)
    if not project:
        flash("Project not found", "danger")
        return redirect(url_for("projects_list"))

    # Get project inspections
    project_inspections = []
    for inspection_id in project["inspections"]:
        inspection = inspections.get(inspection_id)
        if inspection:
            inspection["inspector"] = users.get(inspection["inspector_id"])
            project_inspections.append(inspection)

    return render_template(
        "project_detail.html", project=project, inspections=project_inspections
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
        end_date = None
        if request.form.get("end_date"):
            end_date = datetime.strptime(request.form.get("end_date"), "%Y-%m-%d")

        # Create new project
        new_id = max(projects.keys(), default=0) + 1
        projects[new_id] = {
            "id": new_id,
            "name": name,
            "description": description,
            "location": location,
            "start_date": start_date,
            "end_date": end_date,
            "status": "Active",
            "owner_id": session["user_id"],
            "inspections": [],
        }

        flash("Project created successfully", "success")
        return redirect(url_for("project_detail", project_id=new_id))

    return render_template("create_project.html")


@app.route("/create_inspection/<int:project_id>", methods=["GET", "POST"])
@login_required
@role_required("admin", "inspector", "engineer")
def create_inspection(project_id):
    project = projects.get(project_id)
    if not project:
        flash("Project not found", "danger")
        return redirect(url_for("projects_list"))

    if project["status"] != "Active":
        flash("Inspections can only be created for active projects", "warning")
        return redirect(url_for("project_detail", project_id=project_id))

    if request.method == "POST":
        notes = request.form.get("notes")
        categories = {
            "structural": request.form.get("structural"),
            "electrical": request.form.get("electrical"),
            "plumbing": request.form.get("plumbing"),
            "safety": request.form.get("safety"),
        }

        # Create new inspection
        new_id = max(inspections.keys(), default=0) + 1
        new_inspection = {
            "id": new_id,
            "project_id": project_id,
            "inspector_id": session["user_id"],
            "date": datetime.now(),
            "status": "Completed",
            "notes": notes,
            "blockchain_tx_hash": None,  # Will be generated after submission
            "categories": categories,
        }

        # Generate blockchain record (this would communicate with a blockchain in production)
        tx_hash = create_blockchain_record(new_inspection)
        new_inspection["blockchain_tx_hash"] = tx_hash

        # Save inspection
        inspections[new_id] = new_inspection

        # Update project inspections list
        projects[project_id]["inspections"].append(new_id)

        flash("Inspection created and secured on blockchain", "success")
        return redirect(url_for("inspection_detail", inspection_id=new_id))

    return render_template("create_inspection.html", project=project)


@app.route("/inspection/<int:inspection_id>")
@login_required
def inspection_detail(inspection_id):
    inspection = inspections.get(inspection_id)
    if not inspection:
        flash("Inspection not found", "danger")
        return redirect(url_for("dashboard"))

    # Add related objects
    inspection["project"] = projects.get(inspection["project_id"])
    inspection["inspector"] = users.get(inspection["inspector_id"])

    return render_template("inspection_detail.html", inspection=inspection)


if __name__ == "__main__":
    # Load sample data
    load_sample_data()

    # Run app
    app.run(debug=True)
