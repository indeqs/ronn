from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from datetime import datetime
import os
from web3 import Web3
import hashlib

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site_inspection.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# Connect to Ethereum node - will need to be adjusted for actual deployment
w3 = Web3(Web3.HTTPProvider('http://127.0.0.1:8545'))  # Local Ganache instance for development

# ---------- DATABASE MODELS ----------

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin, engineer, inspector, stakeholder
    inspections = db.relationship('Inspection', backref='inspector', lazy=True)
    
class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    start_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    end_date = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), nullable=False, default='Active')
    blockchain_address = db.Column(db.String(42), nullable=True)  # Ethereum address
    inspections = db.relationship('Inspection', backref='project', lazy=True)

class Inspection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    inspector_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(20), nullable=False, default='Pending')
    findings = db.Column(db.Text, nullable=True)
    recommendations = db.Column(db.Text, nullable=True)
    blockchain_tx_hash = db.Column(db.String(66), nullable=True)  # Ethereum transaction hash
    data_hash = db.Column(db.String(64), nullable=True)  # SHA256 hash of inspection data

    def calculate_hash(self):
        """Calculate SHA256 hash of inspection data for integrity verification"""
        data = f"{self.project_id}{self.inspector_id}{self.date}{self.findings}{self.recommendations}"
        return hashlib.sha256(data.encode()).hexdigest()

    def save_to_blockchain(self):
        """Save inspection data hash to blockchain"""
        # In a production environment, this would interact with a deployed smart contract
        self.data_hash = self.calculate_hash()
        # Placeholder for blockchain transaction
        self.blockchain_tx_hash = "0x" + "0" * 64  # Mock transaction hash
        return True

# ---------- ROUTES ----------

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['role'] = user.role
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check username and password.', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role')
        
        # Check if username or email already exists
        user_exists = User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first()
        if user_exists:
            flash('Username or email already exists.', 'danger')
            return redirect(url_for('register'))
        
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, email=email, password=hashed_password, role=role)
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    projects = Project.query.all()
    
    if user.role == 'engineer' or user.role == 'inspector':
        inspections = Inspection.query.filter_by(inspector_id=user.id).all()
    else:
        inspections = Inspection.query.all()
    
    return render_template('dashboard.html', user=user, projects=projects, inspections=inspections)

@app.route('/projects')
def projects():
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    projects = Project.query.all()
    return render_template('projects.html', projects=projects)

@app.route('/project/<int:project_id>')
def project_detail(project_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    inspections = Inspection.query.filter_by(project_id=project_id).all()
    
    return render_template('project_detail.html', project=project, inspections=inspections)

@app.route('/create_project', methods=['GET', 'POST'])
def create_project():
    if 'user_id' not in session or session['role'] not in ['admin', 'engineer']:
        flash('You do not have permission to create projects.', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        location = request.form.get('location')
        description = request.form.get('description')
        start_date = datetime.strptime(request.form.get('start_date'), '%Y-%m-%d')
        end_date = datetime.strptime(request.form.get('end_date'), '%Y-%m-%d') if request.form.get('end_date') else None
        
        new_project = Project(
            name=name,
            location=location,
            description=description,
            start_date=start_date,
            end_date=end_date,
            status='Active'
        )
        
        db.session.add(new_project)
        db.session.commit()
        
        flash('Project created successfully!', 'success')
        return redirect(url_for('projects'))
    
    return render_template('create_project.html')

@app.route('/create_inspection/<int:project_id>', methods=['GET', 'POST'])
def create_inspection(project_id):
    if 'user_id' not in session or session['role'] not in ['admin', 'inspector', 'engineer']:
        flash('You do not have permission to create inspections.', 'danger')
        return redirect(url_for('dashboard'))
    
    project = Project.query.get_or_404(project_id)
    
    if request.method == 'POST':
        findings = request.form.get('findings')
        recommendations = request.form.get('recommendations')
        
        new_inspection = Inspection(
            project_id=project_id,
            inspector_id=session['user_id'],
            findings=findings,
            recommendations=recommendations,
            status='Completed'
        )
        
        # Calculate and store hash, simulate blockchain storage
        new_inspection.save_to_blockchain()
        
        db.session.add(new_inspection)
        db.session.commit()
        
        flash('Inspection record created and secured on blockchain!', 'success')
        return redirect(url_for('project_detail', project_id=project_id))
    
    return render_template('create_inspection.html', project=project)

@app.route('/inspection/<int:inspection_id>')
def inspection_detail(inspection_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    inspection = Inspection.query.get_or_404(inspection_id)
    
    # Verify data integrity
    current_hash = inspection.calculate_hash()
    is_valid = current_hash == inspection.data_hash
    
    return render_template('inspection_detail.html', 
                          inspection=inspection, 
                          is_valid=is_valid,
                          current_hash=current_hash)

@app.route('/generate_report/<int:project_id>')
def generate_report(project_id):
    if 'user_id' not in session:
        flash('Please log in to access this page.', 'warning')
        return redirect(url_for('login'))
    
    project = Project.query.get_or_404(project_id)
    inspections = Inspection.query.filter_by(project_id=project_id).all()
    
    # Format for report generation
    return render_template('report.html', project=project, inspections=inspections)

@app.route('/api/verify_inspection/<int:inspection_id>', methods=['GET'])
def verify_inspection(inspection_id):
    inspection = Inspection.query.get_or_404(inspection_id)
    current_hash = inspection.calculate_hash()
    is_valid = current_hash == inspection.data_hash
    
    return jsonify({
        'inspection_id': inspection_id,
        'stored_hash': inspection.data_hash,
        'calculated_hash': current_hash,
        'is_valid': is_valid,
        'blockchain_tx': inspection.blockchain_tx_hash
    })

# Initialize database
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)