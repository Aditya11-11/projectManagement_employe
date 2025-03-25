import os
import random
import string
from datetime import datetime, timedelta
from flask import Flask, request, jsonify,send_from_directory, abort
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash 
from werkzeug.utils import secure_filename
import json
from flask_migrate import Migrate  
from flask_cors import CORS

# JWT imports
from flask_jwt_extended import (
    JWTManager, create_access_token,
    jwt_required, get_jwt_identity, get_jwt
)

####################################################
# FLASK & DATABASE CONFIGURATION
####################################################
app = Flask(__name__)

# Local MySQL Database Configuration (fallback to SQLite for development)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///test.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# Set a secret key for JWT (change this in production)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'

app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=1)



# Define and set the upload folder
UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize SQLAlchemy, JWTManager, and SocketIO
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # For development only
migrate = Migrate(app, db)  
CORS(app,cors_allowed_origins="*")

####################################################
# MODELS
####################################################
class Employee(db.Model):  # employeeData
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name  = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    employee_geo_id = db.Column(db.String(16), unique=True, nullable=False)  # Public employee ID
    department = db.Column(db.String(100))
    is_active  = db.Column(db.Boolean, default=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='')
    phone= db.Column(db.Integer,nullable=False)
    department = db.Column(db.String(100), default='')
    position = db.Column(db.String(100), default='')
    emergency_contact_name = db.Column(db.String(100), default='')
    emergency_contact_phone = db.Column(db.String(50), default='')
    professional_skills = db.Column(db.String(255), default='')

class Admin(db.Model):  # admin data 
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name  = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    phone=db.Column(db.Integer(),nullable=False)

class Task(db.Model): # Task Data
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default='')
    due_date = db.Column(db.String(10), default='')  # "dd-mm-yyyy"
    priority = db.Column(db.String(10), default='Medium')  # "Low", "Medium", or "High"
    project=db.Column(db.String(100),nullable=False)
    assigned_to = db.Column(db.String(100), default='')
    status = db.Column(db.String(20), default="Pending")  # New field: Pending, In Progress, Completed
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    employee = db.relationship('Employee', backref='tasks')


class PolicyDocument(db.Model): # Policy Document tab
    __tablename__ = 'policy_documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), default='')
    status = db.Column(db.String(50), default='Active')  # e.g. Active, Archived
    doc_url = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PolicyAcknowledgement(db.Model): #acknowledge_policy_document
    __tablename__ = 'policy_acknowledgements'
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy_documents.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # references some user/employee ID
    ack_status = db.Column(db.String(50), default='Acknowledged')
    ack_date = db.Column(db.DateTime, default=datetime.utcnow)

class LeaveRequest(db.Model): #leverequest table
    __tablename__ = 'leave_requests'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, nullable=False)
    leave_type = db.Column(db.String(20), default='Annual')  # "Annual", "Sick", "Other"
    start_date = db.Column(db.String(10), nullable=False)    # "YYYY-MM-DD"
    end_date = db.Column(db.String(10), nullable=False)      # "YYYY-MM-DD"
    days = db.Column(db.Float, default=1.0)
    status = db.Column(db.String(20), default='Pending')     # "Pending", "Approved", "Rejected"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    reason = db.Column(db.String(255), default='', nullable=True)


class EmployeeLeaveBalance(db.Model): #EMPLOYE LEAVE BALANCE DATA 
    """
    Tracks how many annual leave days an employee has left for a given year.
    Default is 50.0 days per year.
    """
    __tablename__ = 'employee_leave_balance'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    annual_remaining = db.Column(db.Float, default=50.0)

class Shift(db.Model): #SHIFT DATA
    __tablename__ = 'shifts'
    id = db.Column(db.Integer, primary_key=True)
    staff_member = db.Column(db.String(100), nullable=False)  # e.g. "Ryan - Cloud System Engineer"
    shift_name   = db.Column(db.String(50), nullable=False)   # e.g. "Morning (07:00 - 13:00)"
    date         = db.Column(db.String(10), nullable=False)   # "dd-mm-yyyy"
    notes        = db.Column(db.String(200), default='') 
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    employee = db.relationship('Employee', backref='shifts')


# Define the ShiftTime model
class ShiftTime(db.Model):
    __tablename__ = 'shift_times'
    id = db.Column(db.Integer, primary_key=True)
    shift_type = db.Column(db.String(20), nullable=False)  # e.g., Morning, Afternoon, Evening, Night
    start_time = db.Column(db.String(10), nullable=False)    # e.g., "07:00 AM"
    end_time = db.Column(db.String(10), nullable=False) 

# class PersonalInfo(db.Model):
#     __tablename__ = 'personal_info'
#     id = db.Column(db.Integer, primary_key=True)
#     first_name = db.Column(db.String(50), nullable=False)
#     last_name  = db.Column(db.String(50), nullable=False)
#     email = db.Column(db.String(100), unique=True, nullable=False)
#     phone = db.Column(db.String(50), default='')
#     department = db.Column(db.String(100), default='')
#     position = db.Column(db.String(100), default='')
#     emergency_contact_name = db.Column(db.String(100), default='')
#     emergency_contact_phone = db.Column(db.String(50), default='')
#     professional_skills = db.Column(db.String(255), default='')

class Document(db.Model):
    __tablename__ = 'documents'
    id = db.Column(db.Integer, primary_key=True)
    original_filename = db.Column(db.String(255), nullable=False)
    stored_filename   = db.Column(db.String(255), nullable=False)  # Name used on disk
    upload_time       = db.Column(db.DateTime, default=datetime.utcnow)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    employee = db.relationship('Employee', backref='documents')


# class Project(db.Model):
#     __tablename__ = 'projects'
    
#     id = db.Column(db.Integer, primary_key=True)
#     project_name = db.Column(db.String(100), nullable=False)
#     description = db.Column(db.String(500), default='')
#     project_lead = db.Column(db.String(100), default='')
#     start_date = db.Column(db.String(10), default='')  # "dd-mm-yyyy"
#     due_date = db.Column(db.String(10), default='')    # "dd-mm-yyyy"
#     team_members = db.Column(db.Text(255), default='[]')  # could store JSON or comma-separated
#     project_status = db.Column(db.String(50), default='Not Started')
#     lead_id=db.Column(db.Integer,nullable=False)

class Project(db.Model):
    __tablename__ = 'projects'
    
    id = db.Column(db.Integer, primary_key=True)
    project_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default='')
    project_lead = db.Column(db.String(100), default='')
    # lead_id = db.Column(db.Integer, nullable=False)  # NEW column
    start_date = db.Column(db.String(10), default='')  # "dd-mm-yyyy"
    due_date = db.Column(db.String(10), default='')    # "dd-mm-yyyy"
    team_members = db.Column(db.JSON, default=[])
    project_status = db.Column(db.String(50), default='Not Started')

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, nullable=False)
    receiver_id = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    # timestamp = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.String, nullable=False)

class Communication(db.Model):
    __tablename__ = 'communications'
    
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(200), nullable=False)
    channel = db.Column(db.String(100), default='')
    priority = db.Column(db.String(20), default='Medium')   # e.g. High, Medium, Low
    project = db.Column(db.String(100), default='')
    date = db.Column(db.String(20), default='')
    participants = db.Column(db.Text, default='[]')         # store as JSON string

class CommunicationMessage(db.Model):
    __tablename__ = 'communication_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    communication_id = db.Column(db.Integer, db.ForeignKey('communications.id'), nullable=False)
    sender_id = db.Column(db.Integer, nullable=False)  # or store a string if needed
    content = db.Column(db.String(1000), nullable=False)
    # timestamp = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.String, nullable=False)

    # Relationship to access parent Communication if needed
    communication = db.relationship('Communication', backref='messages')


class Compliences(db.Model):
    __tablename__ = 'compliences'
    id = db.Column(db.Integer, primary_key=True)
    subjects = db.Column(db.String(200), nullable=False)
    Discription = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(10), nullable=False)  # e.g., "YYYY-MM-DD"
    posted_by = db.Column(db.String(100), nullable=False)
####################################################
# ENDPOINTS
####################################################

# Create all tables if they do not exist
# with app.app_context():
#     db.create_all()

# -------------------------
# EMPLOYEE AUTH & CRUD ENDPOINTS
# -------------------------

def generate_employee_code(length=8):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# Employee Registration (Public)
@app.route('/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")
    phone = data.get("phone")
    role=data.get("role")
    
    if not all([first_name, last_name, email, password, phone,role]):
        return jsonify({"message": "Missing required fields"}), 400

    if Employee.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400

    # Generate a unique random employee code
    code = generate_employee_code()
    while Employee.query.filter_by(employee_geo_id=code).first() is not None:
        code = generate_employee_code()

    hashed_password = generate_password_hash(password)
    new_employee = Employee(
        employee_geo_id=code,
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        phone=phone,
        role=role
    )
    db.session.add(new_employee)
    db.session.commit()

    return jsonify({"message": "Registration successful", "employee_geo_code": new_employee.employee_geo_id,"employee_id":new_employee.id}), 201


# Unified Login Endpoint (Public)
@app.route('/auth/login', methods=['POST'])
def unified_login():
    """
    Unified login endpoint for both employees and admins.
    Expects JSON:
    {
      "email": "user@example.com",
      "password": "secretpassword"
    }
    The function first checks if the email exists in the Admin table.
    If yes and the password matches, it returns a JWT with role "admin".
    Otherwise, it checks the Employee table and returns a JWT with role "employee".
    If no match is found, it returns an error.
    """
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400

    email = data.get("email")
    password = data.get("password")
    if not email or not password:
        return jsonify({"message": "Missing email or password"}), 400

    # First check Admin table
    admin = Admin.query.filter_by(email=email).first()
    if admin and check_password_hash(admin.password, password):
        access_token = create_access_token(identity=str(admin.id), additional_claims={"role": "admin"})
        return jsonify({
            "message": "Admin login successful",
            "access_token": access_token,
            "user_id": admin.id,
            "first_name" : admin.first_name,
            "last_name":admin.last_name,
            "email":admin.email,
            "role": "admin"
        }), 200

    # Check Employee table
    employee = Employee.query.filter_by(email=email).first()
    if employee and check_password_hash(employee.password, password):
        access_token = create_access_token(identity=str(employee.id), additional_claims={"role": "employee"})
        return jsonify({
            "message": "Employee login successful",
            "access_token": access_token,
            "user_id": employee.id,
            "first_name": employee.first_name,
            "last_name": employee.last_name,
            "email": employee.email,
            "role": employee.role
        }), 200

    return jsonify({"message": "Invalid credentials"}), 401

# Get all employees (Public)
@app.route('/RegisterEmployees', methods=['GET'])
def get_employees():
    employees = Employee.query.all()
    result = []
    for emp in employees:
        result.append({
            "id": emp.id,
            "first_name": emp.first_name,
            "last_name": emp.last_name,
            "email": emp.email,
            "department": emp.department,
            "is_active": emp.is_active,
            "role": emp.role,
            "phone": emp.phone,
            "position": emp.position,
            "emergency_contact_name": emp.emergency_contact_name,
            "emergency_contact_phone": emp.emergency_contact_phone,
            "professional_skills": emp.professional_skills,
            "employee_geo_id":emp.employee_geo_id
        })
    return jsonify(result), 200

# Get a single employee (Public)
@app.route('/Employees/<int:employee_id>', methods=['GET'])
def get_employee(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    result = {
       "id": emp.id,
        "first_name": emp.first_name,
        "last_name": emp.last_name,
        "email": emp.email,
        "department": emp.department,
        "is_active": emp.is_active,
        "role": emp.role,
        "phone": emp.phone,
        "position": emp.position,
        "emergency_contact_name": emp.emergency_contact_name,
        "emergency_contact_phone": emp.emergency_contact_phone,
        "professional_skills": emp.professional_skills,
        "employee_geo_id":emp.employee_geo_id
    }
    return jsonify(result), 200

# Delete an employee (Protected)
@app.route('/employees/<int:employee_id>', methods=['DELETE'])
# @jwt_required()
def delete_employee(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    db.session.delete(emp)
    db.session.commit()
    return jsonify({"message": "Employee deleted"}), 200

# Update employee email (Protected)
@app.route('/employees/<int:employee_id>', methods=['PUT'])
# @jwt_required()  # Uncomment if you want to protect this endpoint with JWT
def update_employee(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    data = request.get_json() or {}

    # Update first name if provided
    if "first_name" in data:
        emp.first_name = data["first_name"]
    
    # Update last name if provided
    if "last_name" in data:
        emp.last_name = data["last_name"]
    
    # Update email if provided (check for uniqueness if it's changed)
    if "email" in data:
        new_email = data["email"]
        if new_email != emp.email and Employee.query.filter_by(email=new_email).first():
            return jsonify({"message": "Email already in use"}), 400
        emp.email = new_email
    
    # Update password if provided (hash it)
    if "password" in data:
        emp.password = generate_password_hash(data["password"])
    
    # Update department if provided
    if "department" in data:
        emp.department = data["department"]
    
    # Update is_active if provided
    if "is_active" in data:
        emp.is_active = data["is_active"]
    
    # Update two_factor_enabled if provided
    if "two_factor_enabled" in data:
        emp.two_factor_enabled = data["two_factor_enabled"]
    
    # Update role if provided
    if "role" in data:
        emp.role = data["role"]
    
    # Update phone if provided
    if "phone" in data:
        emp.phone = data["phone"]
    
    # Update position if provided
    if "position" in data:
        emp.position = data["position"]
    
    # Update emergency contact name if provided
    if "emergency_contact_name" in data:
        emp.emergency_contact_name = data["emergency_contact_name"]
    
    # Update emergency contact phone if provided
    if "emergency_contact_phone" in data:
        emp.emergency_contact_phone = data["emergency_contact_phone"]
    
    # Update professional skills if provided
    if "professional_skills" in data:
        emp.professional_skills = data["professional_skills"]
    
    db.session.commit()
    return jsonify({"message": "Employee updated successfully"}), 200

# Change employee password (Protected)
@app.route('/employees/<int:employee_id>/change_password', methods=['PUT'])
# @jwt_required()
def change_password(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    data = request.get_json()
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    confirm_password = data.get("confirm_password")

    # Check all fields are present
    if not old_password or not new_password or not confirm_password:
        return jsonify({"message": "old_password, new_password, and confirm_password are required"}), 400

    # Verify the old password matches what's stored
    if not check_password_hash(emp.password, old_password):
        return jsonify({"message": "Old password is incorrect"}), 401

    # Ensure new_password and confirm_password match
    if new_password != confirm_password:
        return jsonify({"message": "New password and confirm password do not match"}), 400

    # Everything checks out, update the password
    emp.password = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({"message": "Password changed successfully"}), 200

# Update employee status by ID (Protected)
@app.route('/employees/<int:employee_id>/update_status', methods=['PUT'])
# @jwt_required()
def update_status_by_id(employee_id):
    data = request.get_json()
    if not data or "is_active" not in data:
        return jsonify({"message": "is_active field is required"}), 400

    is_active = data.get("is_active")
    emp = Employee.query.get_or_404(employee_id)
    emp.is_active = is_active
    db.session.commit()
    status_str = "active" if is_active else "inactive"
    return jsonify({"message": f"Employee ID {employee_id}'s status updated to {status_str}."}), 200

# -------------------------
# ADMIN AUTH & ENDPOINTS
# -------------------------

# Admin Registration (Public)
@app.route('/admin/auth/register', methods=['POST'])
def admin_register():
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data provided"}), 400
    first_name = data.get("first_name")
    last_name = data.get("last_name")
    email = data.get("email")
    password = data.get("password")
    phone=data.get("phone")
    # Optionally, you can include a parameter like "user_type": "admin" here if needed.
    if not all([first_name, last_name, email, password]):
        return jsonify({"message": "Missing required fields"}), 400
    if Admin.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400
    hashed_password = generate_password_hash(password)
    new_admin = Admin(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password,
        phone=phone
    )
    db.session.add(new_admin)
    db.session.commit()
    return jsonify({"message": "Admin registration successful", "admin_id": new_admin.id}), 201

# Note: The unified login endpoint (/auth/login) already checks for admin or employee.

# Get All Admins (Public)
@app.route('/admin/admins', methods=['GET'])
def get_admins():
    admins = Admin.query.all()
    result = []
    for adm in admins:
        result.append({
            "id": adm.id,
            "first_name": adm.first_name,
            "last_name": adm.last_name,
            "email": adm.email
        })
    return jsonify(result), 200

# Get Single Admin (Public)
@app.route('/admin/admins/<int:admin_id>', methods=['GET'])
def get_admin(admin_id):
    adm = Admin.query.get_or_404(admin_id)
    result = {
        "id": adm.id,
        "first_name": adm.first_name,
        "last_name": adm.last_name,
        "email": adm.email
    }
    return jsonify(result), 200

# Delete Admin (Protected, Admin-only)
@app.route('/admin/admins/<int:admin_id>', methods=['DELETE'])
# @jwt_required()
def delete_admin(admin_id):
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    adm = Admin.query.get_or_404(admin_id)
    db.session.delete(adm)
    db.session.commit()
    return jsonify({"message": "Admin deleted"}), 200

# Update Admin Email (Protected, Admin-only)
@app.route('/admin/admins/update_email/<int:admin_id>', methods=['PUT'])
# @jwt_required()
def update_admin_email(admin_id):
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    adm = Admin.query.get_or_404(admin_id)
    data = request.get_json()
    new_email = data.get("email")
    if not new_email:
        return jsonify({"message": "New email is required"}), 400
    if Admin.query.filter_by(email=new_email).first():
        return jsonify({"message": "Email already in use"}), 400
    adm.email = new_email
    db.session.commit()
    return jsonify({"message": "Admin email updated successfully"}), 200

# Change Admin Password (Protected, Admin-only)
@app.route('/admin/admins/change_password/<int:admin_id>', methods=['PUT'])
# @jwt_required()
def change_admin_password(admin_id):
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    adm = Admin.query.get_or_404(admin_id)
    data = request.get_json()
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    if not old_password or not new_password:
        return jsonify({"message": "Both old and new passwords are required"}), 400
    if not check_password_hash(adm.password, old_password):
        return jsonify({"message": "Old password is incorrect"}), 401
    adm.password = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({"message": "Admin password changed successfully"}), 200
# Add Task 
@app.route('/tasks', methods=['POST'])
# @jwt_required()  # Add this decorator to require authentication
def add_task():
    """
    Expects JSON:
    {
        "title": "Enter task title",
        "description": "Enter task description",
        "due_date": "dd-mm-yyyy",
        "priority": "High",
        "assigned_to": "John Doe"
    }
    # """
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403
    data = request.get_json()
    if not data or "title" not in data or "employee_id" not in data:
        return jsonify({"message": "Task title and employee_id are required"}), 400
    
    employee = Employee.query.get(data["employee_id"])
    if not employee:
        return jsonify({"message": "Employee not found"}), 404
    
    title = data["title"]
    description = data.get("description", "")
    due_date = data.get("due_date", "")
    priority = data.get("priority", "Medium")
    assigned_to = data.get("assigned_to", "")
    project=data.get("project")
    employee_id=data["employee_id"]


    new_task = Task(
        title=title,
        description=description,
        due_date=due_date,
        priority=priority,
        assigned_to=assigned_to,
        project=project,
        employee_id=employee_id,

    )
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "Task created", "task_id": new_task.id}), 201

@app.route('/tasks/get_tasks', methods=['GET'])
# @jwt_required() 
def get_tasks():
    """
    Optional query parameters:
      - title (string)
      - priority (Low/Medium/High)
    Example: /tasks?title=Fix&priority=High
    """
    title_filter = request.args.get('title')      # e.g. ?title=Fix
    priority_filter = request.args.get('priority')  # e.g. ?priority=High
    id_filter=request.args.get('id')
    assingn_filter=request.args.get("assigned_to")
    project_filter=request.args.get("project")
    employee_id_filter=request.args.get("employee_id")

    query = Task.query
    
    # Filter by title (case-insensitive "contains" search)
    if title_filter:
        query = query.filter(Task.title.ilike(f"%{title_filter}%"))
    
    # Filter by priority (exact match)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)

    if id_filter:
        query = query.filter_by(id=id_filter)

    if assingn_filter:
        query=query.filter_by(assigned_to=assingn_filter)

    if project_filter:
        query=query.filter_by(project=project_filter)

    if employee_id_filter :
        query=query.filter_by(employee_id=employee_id_filter)
        
    tasks = query.all()
    results = []
    for t in tasks:
        results.append({
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "due_date": t.due_date,
            "priority": t.priority,
            "assigned_to": t.assigned_to,
            "project":t.project,
            "status" :t.status,
            "employee_id":t.employee_id
        })
    return jsonify(results), 200

#update
@app.route('/tasks/<int:task_id>', methods=['PUT'])
# @jwt_required()  # Uncomment this if you need authentication
def update_task(task_id):
    """
    Update an existing task by ID. Only the fields provided in the request will be updated.
    Expects JSON payload with any of the following fields:
    {
        "title": "New task title",
        "description": "Updated description",
        "due_date": "dd-mm-yyyy",
        "priority": "High",
        "assigned_to": "John Doe",
        "project": "Project Name"
    }
    """
    
    task = Task.query.get_or_404(task_id)
    data = request.get_json() or {}

    if "title" in data:
        task.title = data["title"]
    if "description" in data:
        task.description = data["description"]
    if "due_date" in data:
        task.due_date = data["due_date"]
    if "priority" in data:
        task.priority = data["priority"]
    if "assigned_to" in data:
        task.assigned_to = data["assigned_to"]
    if "project" in data:
        task.project = data["project"]

    if "status" in data:
    # Optionally validate new status before updating
        new_status = data["status"]
    if new_status not in ["Pending", "In Progress", "Completed"]:
        return jsonify({"message": "Invalid status value"}), 400
    task.status = new_status

    db.session.commit()
    return jsonify({"message": "Task updated", "task_id": task.id}), 200

#  Delete Task by title (DELETE) 
@app.route('/tasks/<string:id>', methods=['DELETE'])
# @jwt_required() 
def delete_task_by_title(id):
    """
    Delete the first task matching the given title.
    If multiple tasks have the same title, only the first match is deleted.
    """
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403 
    task_id= Task.query.filter_by(id=id).first()
    if not task_id:
        return jsonify({"message": f"No task found with title '{id}'"}), 404
    
    db.session.delete(task_id)
    db.session.commit()
    return jsonify({"message": f"Task with title '{id}' deleted"}), 200


# Create (POST) a new policy document
@app.route('/policy/documents', methods=['POST'])
# @jwt_required()
def create_policy_document():
    """
    Expects JSON:
    {
      "title": "Employee Handbook",
      "description": "Company policies, procedures, and guidelines",
      "status": "Active",
      "doc_url": "http://example.com/docs/handbook.pdf"
    }
    # """
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403
    data = request.get_json() or {}
    if 'title' not in data:
        return jsonify({"message": "title is required"}), 400

    new_doc = PolicyDocument(
        title=data['title'],
        description=data.get('description', ''),
        status=data.get('status', 'Active'),
        doc_url=data.get('doc_url', '')
    )
    db.session.add(new_doc)
    db.session.commit()
    return jsonify({
        "message": "Policy document created",
        "doc_id": new_doc.id
    }), 201

# Delete (DELETE) a policy document by ID
@app.route('/policy/documents/<int:doc_id>', methods=['DELETE'])
# @jwt_required()
def delete_policy_document(doc_id):
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403
    doc = PolicyDocument.query.get_or_404(doc_id)
    db.session.delete(doc)
    db.session.commit()
    return jsonify({"message": f"Policy document {doc_id} deleted"}), 200

# Retrieve (GET) all policy documents
@app.route('/policy/documents', methods=['GET'])
def get_all_policy_documents():
    docs = PolicyDocument.query.order_by(PolicyDocument.created_at.desc()).all()
    results = []
    for d in docs:
        results.append({
            "id": d.id,
            "title": d.title,
            "description": d.description,
            "status": d.status,
            "doc_url": d.doc_url,
            "created_at": d.created_at.isoformat()
        })
    return jsonify(results), 200

# Retrieve (GET) a single policy document by ID
@app.route('/policy/documents/<int:doc_id>', methods=['GET'])
def get_policy_document(doc_id):
    doc = PolicyDocument.query.get_or_404(doc_id)
    return jsonify({
        "id": doc.id,
        "title": doc.title,
        "description": doc.description,
        "status": doc.status,
        "doc_url": doc.doc_url,
        "created_at": doc.created_at.isoformat()
    }), 200

# Acknowledge (POST) that a user has read a policy document
@app.route('/policy/documents/acknowledge/<int:doc_id>', methods=['POST'])
# @jwt_required()
def acknowledge_policy_document(doc_id):
    """
    Expects JSON:
    {
      "user_id": 123
    }
    """
    # claims = get_jwt()
    # if claims.get("role") != "employee":
    #     return jsonify({"message": "Employees only"}), 403
    
    data = request.get_json() or {}
    if 'user_id' not in data:
        return jsonify({"message": "user_id is required"}), 400

    # Ensure the document exists
    doc = PolicyDocument.query.get_or_404(doc_id)

    # Check if there's already an acknowledgement record for this user/doc
    existing_ack = PolicyAcknowledgement.query.filter_by(policy_id=doc_id, user_id=data['user_id']).first()
    if existing_ack:
        return jsonify({"message": "Already acknowledged"}), 200

    new_ack = PolicyAcknowledgement(
        policy_id=doc_id,
        user_id=data['user_id'],
        ack_status="Acknowledged"
    )
    db.session.add(new_ack)
    db.session.commit()
    return jsonify({"message": "Policy acknowledged"}), 201

# List which documents a user has acknowledged
@app.route('/policy/acknowledgements', methods=['GET'])
def get_acknowledgements():
    """
    Query param: ?user_id=123
    Returns a list of documents the user has acknowledged
    """
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"message": "user_id query param is required"}), 400

    # Join policy_docs + acknowledgements to return doc info
    acks = db.session.query(PolicyAcknowledgement, PolicyDocument)\
        .join(PolicyDocument, PolicyAcknowledgement.policy_id == PolicyDocument.id)\
        .filter(PolicyAcknowledgement.user_id == user_id)\
        .order_by(PolicyAcknowledgement.ack_date.desc())\
        .all()

    results = []
    for ack, doc in acks:
        results.append({
            "policy_id": doc.id,
            "title": doc.title,
            "ack_status": ack.ack_status,
            "ack_date": ack.ack_date.isoformat()
        })

    return jsonify(results), 200

#leave P
# Set or update the annual leave balance for a given employee and year
@app.route('/leave/balance', methods=['POST'])
# @jwt_required()
def set_annual_balance():

    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    data = request.get_json() or {}
    employee_id = data.get("employee_id")
    year = data.get("year")
    new_balance = data.get("new_balance")

    # Validate inputs
    if employee_id is None or year is None or new_balance is None:
        return jsonify({"message": "employee_id, year, and new_balance are required"}), 400

    # Try to find an existing balance record
    balance = EmployeeLeaveBalance.query.filter_by(employee_id=employee_id, year=year).first()
    if not balance:
        # Create a new record if none exists
        balance = EmployeeLeaveBalance(
            employee_id=employee_id,
            year=year,
            annual_remaining=new_balance
        )
        db.session.add(balance)
        db.session.commit()
        return jsonify({
            "message": f"Leave balance created for employee {employee_id}, year {year}",
            "annual_remaining": balance.annual_remaining
        }), 201
    else:
        # Update existing record
        balance.annual_remaining = new_balance
        db.session.commit()
        return jsonify({
            "message": f"Leave balance updated for employee {employee_id}, year {year}",
            "annual_remaining": balance.annual_remaining
        }), 200
# Apply for Leave (POST)
@app.route('/leave/requests', methods=['POST'])
# @jwt_required()
def apply_new_leave():
    """
    Expects JSON:
    {
      "employee_id": 123,
      "leave_type": "Annual",
      "start_date": "YYYY-MM-DD",
      "end_date": "YYYY-MM-DD",
      "days": 4,
      "reason": "Explanation of the leave"  (optional)
    }
    # """
    # claims = get_jwt()
    # if claims.get("role") != "employee":
    #     return jsonify({"message": "Employees only"}), 403

    data = request.get_json() or {}
    required = ["employee_id", "start_date", "end_date", "days"]
    if not all(field in data for field in required):
        return jsonify({"message": "Missing required fields"}), 400

    new_req = LeaveRequest(
        employee_id=data["employee_id"],
        leave_type=data.get("leave_type", "Annual"),
        start_date=data["start_date"],
        end_date=data["end_date"],
        days=data["days"],
        status="Pending",
        reason=data.get("reason", "")  # store the reason if provided
    )
    db.session.add(new_req)
    db.session.commit()

    return jsonify({"message": "Leave request created", "request_id": new_req.id}), 201

# Get Leave Requests (GET)
@app.route('/leave/requests', methods=['GET'])
def get_leave_requests():
    """
    Optional query param: employee_id
    e.g. /leave/requests?employee_id=123
    If provided, returns requests only for that employee.
    Otherwise returns all requests.
    """
    employee_id = request.args.get("employee_id", type=int)
    request_id = request.args.get("id", type=int)
    query = LeaveRequest.query

    if employee_id:
        query = query.filter_by(employee_id=employee_id)

    if request_id:
        query = query.filter_by(id=request_id)

    requests = query.order_by(LeaveRequest.created_at.desc()).all()

    data = []
    for r in requests:
        data.append({
            "id": r.id,
            "employee_id": r.employee_id,
            "leave_type": r.leave_type,
            "start_date": r.start_date,
            "end_date": r.end_date,
            "days": r.days,
            "status": r.status,
            "created_at": r.created_at.isoformat(),
            "reason": r.reason  # include the reason in the response

        })
    return jsonify(data), 200

# Approve/Reject a Leave Request (PUT)
@app.route('/leave/requests/decision/<int:req_id>', methods=['PUT'])
# @jwt_required()
def decide_leave_request(req_id):
    """
    Expects JSON:
    {
      "status": "Approved" or "Rejected"
    }
    If approving for the first time, subtract from user's annual balance.
    """
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403
    
    req = LeaveRequest.query.get_or_404(req_id)
    data = request.get_json() or {}
    new_status = data.get("status")
    if new_status not in ["Approved", "Rejected"]:
        return jsonify({"message": "Invalid status. Must be 'Approved' or 'Rejected'."}), 400

    old_status = req.status

    # Only if we're changing from something else to "Approved"
    # do we subtract from the user's annual remaining.
    if old_status != "Approved" and new_status == "Approved":
        # parse the year from the start_date
        try:
            req_year = datetime.strptime(req.start_date, "%Y-%m-%d").year
        except ValueError:
            # if invalid date, fallback to current year
            req_year = datetime.now().year

        # find or create an EmployeeLeaveBalance row
        balance = EmployeeLeaveBalance.query.filter_by(
            employee_id=req.employee_id, 
            year=req_year
        ).first()
        if not balance:
            balance = EmployeeLeaveBalance(
                employee_id=req.employee_id, 
                year=req_year
            )
            db.session.add(balance)
            db.session.commit()

        # subtract the requested days from annual_remaining
        if balance.annual_remaining < req.days:
            return jsonify({"message": "Not enough leave balance"}), 400

        balance.annual_remaining -= req.days
        db.session.commit()

    req.status = new_status
    db.session.commit()

    if new_status == "Approved":
        
        # Return updated balance
        return jsonify({
            "message": f"Leave request {req_id} approved.",
            "new_balance": balance.annual_remaining
        }), 200
    else:
        return jsonify({"message": f"Leave request {req_id} rejected."}), 200

# Get a Single Leave Request (GET)
@app.route('/leave/requests/<int:req_id>', methods=['GET'])
def get_leave_request_detail(req_id):
    req = LeaveRequest.query.get_or_404(req_id)
    return jsonify({
        "id": req.id,
        "employee_id": req.employee_id,
        "leave_type": req.leave_type,
        "start_date": req.start_date,
        "end_date": req.end_date,
        "days": req.days,
        "status": req.status,
        "created_at": req.created_at.isoformat(),
        "reason": req.reason  # include the reason in the response

    }), 200

# Get Total Leave of an Employee in a Given Month (GET)
@app.route('/leave/stats', methods=['GET'])
def get_leave_stats():
    """
    Query params: employee_id (required), year (optional), month (optional)
    e.g. /leave/stats?employee_id=123&year=2024&month=2
    If year/month not provided, defaults to current year/month.
    Returns total days of approved leave for that month.
    """
    employee_id = request.args.get("employee_id", type=int)
    if not employee_id:
        return jsonify({"message": "employee_id is required"}), 400

    year = request.args.get("year", type=int, default=datetime.now().year)
    month = request.args.get("month", type=int, default=datetime.now().month)

    # We'll parse the start_date from the request as "YYYY-MM-DD"
    # and check if the year/month matches, and if status == "Approved"
    all_requests = LeaveRequest.query.filter_by(employee_id=employee_id).all()

    total_days = 0.0
    for req in all_requests:
        if req.status == "Approved":
            try:
                start_dt = datetime.strptime(req.start_date, "%Y-%m-%d")
                if start_dt.year == year and start_dt.month == month:
                    total_days += req.days
            except ValueError:
                pass

    return jsonify({
        "employee_id": employee_id,
        "year": year,
        "month": month,
        "total_leave_days": total_days
    }), 200

# Check Current Annual Balance (opt)
@app.route('/leave/balance', methods=['GET'])
def get_annual_balance():
    """
    Query params: employee_id (required), year (optional)
    e.g. /leave/balance?employee_id=123&year=2024
    Returns the employee's current annual_remaining.
    """
    employee_id = request.args.get("employee_id", type=int)
    if not employee_id:
        return jsonify({"message": "employee_id is required"}), 400

    year = request.args.get("year", type=int, default=datetime.now().year)

    balance = EmployeeLeaveBalance.query.filter_by(
        employee_id=employee_id, 
        year=year
    ).first()

    if not balance:
        # If no row found, it means they still have the default 50
        return jsonify({
            "employee_id": employee_id,
            "year": year,
            "annual_remaining": 50.0
        }), 200

    return jsonify({
        "employee_id": employee_id,
        "year": year,
        "annual_remaining": balance.annual_remaining
    }), 200

#schedule
@app.route('/shifts', methods=['POST'])
# @jwt_required()
def create_shift():
    """
    Expects JSON:
    {
      "staff_member": "Ryan - Cloud System Engineer",
      "shift_name": "Morning (07:00 - 13:00)",
      "date": "15-03-2025",
      "notes": "Some optional note"
    }
    # """
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403
    data = request.get_json() or {}
    required_fields = ["staff_member", "shift_name", "date","employee_id"]
    if not all(f in data for f in required_fields):
        return jsonify({"message": "Missing required fields"}), 400
    
    new_shift = Shift(
        staff_member=data["staff_member"],
        shift_name=data["shift_name"],
        date=data["date"],
        notes=data.get("notes", ""),
        employee_id=data["employee_id"],

    )
    db.session.add(new_shift)
    db.session.commit()
    return jsonify({"message": "Shift created", "shift_id": new_shift.id}), 201

# Get all shifts (GET), with optional filtering by staff_member
@app.route('/shifts', methods=['GET'])
def get_shifts():
    """
    Optional query param: ?staff=Ryan
    If provided, returns only shifts for that staff_member (case-insensitive 'contains' search).
    Otherwise returns all shifts.
    """
    staff_filter = request.args.get("staff", type=str)
    id_filter = request.args.get("employee_id")
    query = Shift.query

    if staff_filter:
        # case-insensitive substring match
        query = query.filter(Shift.staff_member.ilike(f"%{staff_filter}%"))
    if id_filter :
        query = query.filter_by(employee_id=id_filter)
    
    shifts = query.all()
    results = []
    for s in shifts:
        results.append({
            "id": s.id,
            "staff_member": s.staff_member,
            "shift_name": s.shift_name,
            "date": s.date,
            "notes": s.notes,
            "employee_id":s.employee_id
        })
    return jsonify(results), 200

# Get a single shift by ID (GET)
@app.route('/shifts/<int:shift_id>', methods=['GET'])
def get_shift_by_id(shift_id):
    s = Shift.query.get_or_404(shift_id)
    return jsonify({
        "id": s.id,
        "staff_member": s.staff_member,
        "shift_name": s.shift_name,
        "date": s.date,
        "notes": s.notes
    }), 200

#  Update a shift by ID (PUT)
@app.route('/shifts/<int:shift_id>', methods=['PUT'])
# @jwt_required()
def update_shift(shift_id):
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403
    
    s = Shift.query.get_or_404(shift_id)
    data = request.get_json() or {}
    
    # Update fields if present
    s.staff_member = data.get("staff_member", s.staff_member)
    s.shift_name   = data.get("shift_name", s.shift_name)
    s.date         = data.get("date", s.date)
    s.notes        = data.get("notes", s.notes)

    db.session.commit()
    return jsonify({"message": f"Shift {shift_id} updated"}), 200

# Delete a shift by ID (DELETE)
@app.route('/shifts/<int:shift_id>', methods=['DELETE'])
# @jwt_required()
def delete_shift(shift_id):
        
        
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    s = Shift.query.get_or_404(shift_id)
    db.session.delete(s)
    db.session.commit()
    return jsonify({"message": f"Shift {shift_id} deleted"}), 200


##################################################################################### ALOT_SHIF_TTIME
# POST: Create a new shift time
@app.route('/api/shifttime', methods=['POST'])
def create_shift_time():
    data = request.get_json() or {}
    required_fields = ['shift_type', 'start_time', 'end_time']
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields: shift_type, start_time, and end_time are required"}), 400

    new_shift = ShiftTime(
        shift_type=data['shift_type'],
        start_time=data['start_time'],
        end_time=data['end_time']
    )
    db.session.add(new_shift)
    db.session.commit()

    return jsonify({
        "message": "Shift time created successfully",
        "shift_time_id": new_shift.id
    }), 201

# GET: Retrieve all shift times
@app.route('/api/shifttime', methods=['GET'])
def get_shift_times():
    shifts = ShiftTime.query.all()
    results = []
    for shift in shifts:
        results.append({
            "id": shift.id,
            "shift_type": shift.shift_type,
            "start_time": shift.start_time,
            "end_time": shift.end_time
        })
    return jsonify({
        "status": "success",
        "data": results
    }), 200

# DELETE: Delete a shift time by its ID
@app.route('/api/shifttime/<int:shift_id>', methods=['DELETE'])
def delete_shift_time(shift_id):
    shift = ShiftTime.query.get_or_404(shift_id)
    db.session.delete(shift)
    db.session.commit()
    return jsonify({"message": f"Shift time with id {shift_id} deleted successfully"}), 200

# personal info
# @app.route('/personal_info', methods=['POST'])
# # @jwt_required()
# def create_personal_info():
#     """
#     Expects JSON:
#     {
#       "first_name": "John",
#       "last_name": "Smith",
#       "email": "john.smith@company.com",
#       "phone": "+1 (555) 123-4567",
#       "department": "Engineering",
#       "position": "Senior Developer",
#       "emergency_contact_name": "Jane Smith",
#       "emergency_contact_phone": "+1 (555) 987-6543",
#       "professional_skills": "JavaScript, React, NodeJS, Python, AWS, Docker"
#     }
#     """
#     # claims = get_jwt()
#     # if claims.get("role") != "employee":
#     #     return jsonify({"message": "Employees only"}), 403

#     data = request.get_json() or {}
#     required_fields = ["first_name", "last_name", "email"]
#     if not all(f in data for f in required_fields):
#         return jsonify({"message": "Missing required fields"}), 400

#     # Check if email is already used
#     if PersonalInfo.query.filter_by(email=data["email"]).first():
#         return jsonify({"message": "Email already registered"}), 400

#     new_record = PersonalInfo(
#         first_name=data["first_name"],
#         last_name=data["last_name"],
#         email=data["email"],
#         phone=data.get("phone", ""),
#         department=data.get("department", ""),
#         position=data.get("position", ""),
#         emergency_contact_name=data.get("emergency_contact_name", ""),
#         emergency_contact_phone=data.get("emergency_contact_phone", ""),
#         professional_skills=data.get("professional_skills", "")
#     )
#     db.session.add(new_record)
#     db.session.commit()
#     return jsonify({"message": "Personal info created", "id": new_record.id}), 201

# @app.route('/personal_info', methods=['GET'])
# def get_personal_info():
#     """
#     If ?name=<someName> is provided, searches for records where first_name or last_name
#     contains <someName> (case-insensitive).
#     Otherwise, returns all personal info records.
#     Example:
#       GET /personal_info           -> fetches all
#       GET /personal_info?name=John -> fetches those matching 'John'
#     """
#     name_filter = request.args.get("name", type=str)
#     id_filter=request.args.get('id')

#     query = PersonalInfo.query

#     if name_filter:
#         # Filter where first_name or last_name contains the name_filter (case-insensitive)
#         query = PersonalInfo.query.filter(
#             (PersonalInfo.first_name.ilike(f"%{name_filter}%")) |
#             (PersonalInfo.last_name.ilike(f"%{name_filter}%"))
#         )
#     if id_filter:
#         query = query.filter_by(id=id_filter)


#     records = query.all()

#     results = []
#     for r in records:
#         results.append({
#             "id": r.id,
#             "first_name": r.first_name,
#             "last_name": r.last_name,
#             "email": r.email,
#             "phone": r.phone,
#             "department": r.department,
#             "position": r.position,
#             "emergency_contact_name": r.emergency_contact_name,
#             "emergency_contact_phone": r.emergency_contact_phone,
#             "professional_skills": r.professional_skills
#         })

#     return jsonify(results), 200

# # Update personal info by ID (PUT)
# @app.route('/personal_info/<int:info_id>', methods=['PUT'])
# # @jwt_required()
# def update_personal_info(info_id):

#     # claims = get_jwt()
#     # if claims.get("role") != "employee":
#     #     return jsonify({"message": "Employees only"}), 403

#     record = PersonalInfo.query.get_or_404(info_id)
#     data = request.get_json() or {}

#     # Update fields if provided
#     record.first_name = data.get("first_name", record.first_name)
#     record.last_name  = data.get("last_name", record.last_name)
#     record.email      = data.get("email", record.email)
#     record.phone      = data.get("phone", record.phone)
#     record.department = data.get("department", record.department)
#     record.position   = data.get("position", record.position)
#     record.emergency_contact_name = data.get("emergency_contact_name", record.emergency_contact_name)
#     record.emergency_contact_phone = data.get("emergency_contact_phone", record.emergency_contact_phone)
#     record.professional_skills = data.get("professional_skills", record.professional_skills)

#     db.session.commit()
#     return jsonify({"message": f"Personal info {info_id} updated"}), 200

# # Delete personal info by ID (DELETE)
# @app.route('/personal_info/<int:info_id>', methods=['DELETE'])
# # @jwt_required()
# def delete_personal_info(info_id):

#     # claims = get_jwt()
#     # if claims.get("role") != "employee":
#     #     return jsonify({"message": "Employees only"}), 403

#     record = PersonalInfo.query.get_or_404(info_id)
#     db.session.delete(record)
#     db.session.commit()
#     return jsonify({"message": f"Personal info {info_id} deleted"}), 200


@app.route('/documents', methods=['POST'])
# @jwt_required()
def upload_document():
    """
    Expects a multipart/form-data request with:
      - A file under key "file"
      - An "employee_id" field to associate the document with an employee.
    
    Example with cURL:
      curl -X POST -F file=@/path/to/file.pdf -F employee_id=1 http://localhost:5000/documents
    # """
    # claims = get_jwt()
    # if claims.get("role") != "employee":
    #     return jsonify({"message": "Employees only"}), 403

    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    # Get employee_id from form data.
    employee_id = request.form.get("employee_id")
    if not employee_id:
        return jsonify({"message": "Missing employee_id in the form data"}), 400
    try:
        employee_id = int(employee_id)
    except ValueError:
        return jsonify({"message": "Invalid employee_id"}), 400

    # Verify that the employee exists.
    employee = Employee.query.get(employee_id)
    if not employee:
        return jsonify({"message": "Employee not found"}), 404

    # Sanitize the filename.
    original_filename = secure_filename(file.filename)
    if not original_filename:
        return jsonify({"message": "Invalid file name"}), 400

    # Create a unique stored filename.
    stored_filename = f"{datetime.utcnow().timestamp()}_{original_filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
    
    # Save the file to disk.
    file.save(file_path)


    # Create a new Document record in the database.
    new_doc = Document(
        original_filename=original_filename,
        stored_filename=stored_filename,
        employee_id=employee_id
    )
    db.session.add(new_doc)
    db.session.commit()

    return jsonify({
        "message": "Document uploaded",
        "document_id": new_doc.id,
        "original_filename": original_filename
    }), 201

# Download a Document (GET)
@app.route('/documents/download/<int:doc_id>', methods=['GET'])
def download_document(doc_id):
    """
    Returns the file for download.
    Example: GET /documents/download/1
    """
    doc = Document.query.get_or_404(doc_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.stored_filename)
    if not os.path.exists(file_path):
        abort(404, description="File not found on disk")

    return send_from_directory(
        directory=app.config['UPLOAD_FOLDER'],
        path=doc.stored_filename,
        as_attachment=True,
        download_name=doc.original_filename
    )

# Delete a Document (DELETE)
@app.route('/documents/<int:doc_id>', methods=['DELETE'])
# @jwt_required()
def delete_document(doc_id):
    """
    Removes the document record from the DB and deletes the file from disk.
    Example: DELETE /documents/1
    # """
    # claims = get_jwt()
    # if claims.get("role") != "employee":
    #     return jsonify({"message": "Employees only"}), 403
    
    doc = Document.query.get_or_404(doc_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc.stored_filename)

    # Remove document record from the database.
    db.session.delete(doc)
    db.session.commit()

    # Remove file from disk if it exists.
    if os.path.exists(file_path):
        os.remove(file_path)

    return jsonify({"message": f"Document {doc_id} deleted"}), 200

# List all Documents (GET)
@app.route('/documents', methods=['GET'])
def list_documents():
    """
    Returns all documents metadata along with associated employee details.
    Employee details include: name, position, and department.
    """
    # Join Document with PersonalInfo.
    docs = db.session.query(Document, Employee)\
        .join(Employee, Document.employee_id == Employee.id)\
        .order_by(Document.upload_time.desc()).all()

    results = []
    for doc, emp in docs:
        results.append({
            "document_id": doc.id,
            "original_filename": doc.original_filename,
            "upload_time": doc.upload_time.isoformat(),
            "employee_id": emp.id,
            "employee_name": f"{emp.first_name} {emp.last_name}",
            "department": emp.department,
            "position": emp.position
        })
    return jsonify(results), 200

# PROJECT # 
@app.route('/projects', methods=['POST'])
# @jwt_required()
def create_project():
    """
    Expects JSON:
    {
      "project_name": "Project color coding and Geo Fencing",
      "description": "Some description of the project",
      "project_lead": "John Smith",
      "start_date": "01-04-2025",
      "due_date": "15-04-2025",
      "team_members": "John Smith, Jane Doe", 
      "project_status": "Not Started"
    }
    """

    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    data = request.get_json() or {}
    required_fields = ["project_name"]
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields: project_name are required"}), 400

    # Get project lead id and verify it is an integer
    # try:
    #     project_lead_id = int(data.get("lead_id"))
    # except ValueError:
    #     return jsonify({"message": "Invalid project_lead_id"}), 400

    # Lookup the employee using project_lead_id
    # project_lead_employee = Employee.query.get(project_lead_id)
    # if not project_lead_employee:
    #     return jsonify({"message": f"Employee with id {project_lead_id} not found"}), 404

    
    team_members = data.get("team_members", [])
    if isinstance(team_members, list):
        team_members_str = json.dumps(team_members)
    else:
        team_members_str = json.dumps(team_members.split(','))

    new_project = Project(
        project_name=data["project_name"],
        description=data.get("description", ""),
        project_lead=data.get("project_lead", ""),
        # lead_id=project_lead_employee.id,  # Correct: pass the employee's ID
        start_date=data.get("start_date", ""),
        due_date=data.get("due_date", ""),
        team_members=team_members_str,
        project_status=data.get("project_status", "Not Started")
    )


    db.session.add(new_project)
    db.session.commit()
    return jsonify({"message": "Project created", "project_id": new_project.id}), 201

# Get all projects (GET)
@app.route('/projects', methods=['GET'])
def get_all_projects():
    """
    Returns a list of all projects.
    """
    records = Project.query.all()
    results = []
    for r in records:
        results.append({
            "id": r.id,
            "project_name": r.project_name,
            "description": r.description,
            "project_lead": r.project_lead,
            "start_date": r.start_date,
            "due_date": r.due_date,
            "team_members": r.team_members,
            "project_status": r.project_status
        })
    return jsonify(results), 200

# Get project by ID (GET)
@app.route('/projects/<int:project_id>', methods=['GET'])
def get_project_by_id(project_id):
    """
    Retrieve a single project by its ID.
    """
    project = Project.query.get_or_404(project_id)
    return jsonify({
        "id": project.id,
        "project_name": project.project_name,
        "description": project.description,
        "project_lead": project.project_lead,
        "start_date": project.start_date,
        "due_date": project.due_date,
        "team_members": project.team_members,
        "project_status": project.project_status
    }), 200

# Delete a project by ID (DELETE)
@app.route('/projects/<int:project_id>', methods=['DELETE'])
# @jwt_required()
def delete_project(project_id):
   
    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    project = Project.query.get_or_404(project_id)
    db.session.delete(project)
    db.session.commit()
    return jsonify({"message": f"Project {project_id} deleted"}), 200

# Update project status by ID (PUT)
@app.route('/projects/<int:project_id>/status', methods=['PUT'])
# @jwt_required()
def update_project_status(project_id):
    """
    Expects JSON:
    {
      "project_status": "In Progress"
    }
    """

    # claims = get_jwt()
    # if claims.get("role") != "admin":
    #     return jsonify({"message": "Admins only"}), 403

    project = Project.query.get_or_404(project_id)
    data = request.get_json() or {}
    new_status = data.get("project_status")
    if not new_status:
        return jsonify({"message": "Missing project_status"}), 400

    project.project_status = new_status
    db.session.commit()
    return jsonify({"message": f"Project {project_id} status updated to {new_status}."}), 200


#employe chat 

@app.route('/chats', methods=['POST'])
# @jwt_required()
def create_chat_message():
    """
    Expects JSON:
    {
      "sender_id": 1,
      "receiver_id": 2,
      "content": "Hello, how are you?"
    }
    """
    # claims = get_jwt()
    # if claims.get("role") != "employee":
    #     return jsonify({"message": "Employees only"}), 403
    
    data = request.get_json() or {}
    required = ["sender_id", "receiver_id", "content","timestamp"]
    if not all(field in data for field in required):
        return jsonify({"message": "Missing required fields"}), 400

    new_msg = ChatMessage(
        sender_id=data["sender_id"],
        receiver_id=data["receiver_id"],
        content=data["content"],
        timestamp=data["timestamp"]
    )
    db.session.add(new_msg)
    db.session.commit()

    return jsonify({
        "message": "Chat message created",
        "chat_id": new_msg.id,
        # "timestamp": datetime.fromtimestamp(new_msg.timestamp).isoformat()
        "timpestamp":new_msg.timestamp
    }), 201

# 2. Get all messages between two employees (GET)
@app.route('/chats', methods=['GET'])
def get_chat_messages():
    """
    Query params:
      ?user1=<id>&user2=<id>
    Example: /chats?user1=1&user2=2

    Returns all messages where (sender_id, receiver_id) match either (user1, user2) or (user2, user1).
    Sorted by timestamp ascending.
    """
    user1 = request.args.get("user1", type=int)
    user2 = request.args.get("user2", type=int)
    if not user1 or not user2:
        return jsonify({"message": "Query params user1 and user2 are required"}), 400

    # Filter messages where (sender_id, receiver_id) = (user1, user2) OR (user2, user1)
    messages = ChatMessage.query.filter(
        db.or_(
            db.and_(ChatMessage.sender_id == user1, ChatMessage.receiver_id == user2),
            db.and_(ChatMessage.sender_id == user2, ChatMessage.receiver_id == user1)
        )
    ).order_by(ChatMessage.timestamp.asc()).all()

    results = []
    for msg in messages:
        results.append({
            "id": msg.id,
            "sender_id": msg.sender_id,
            "receiver_id": msg.receiver_id,
            "content": msg.content,
            # "timestamp": datetime.fromtimestamp(msg.timestamp).isoformat() #"timestamp": datetime.fromtimestamp(new_msg.timestamp).isoformat()  
            "timpestamp":msg.timestamp
        })

    return jsonify(results), 200

# 3. Delete all messages between two employees (DELETE)
@app.route('/chats', methods=['DELETE'])
# @jwt_required()
def delete_chat_messages():
    """
    Query params:
      ?user1=<id>&user2=<id>
    Example: /chats?user1=1&user2=2

    Deletes all messages between user1 and user2.
    """
    # claims = get_jwt()
    # if claims.get("role") != "employee":
    #     return jsonify({"message": "Employees only"}), 403

    user1 = request.args.get("user1", type=int)
    user2 = request.args.get("user2", type=int)
    if not user1 or not user2:
        return jsonify({"message": "Query params user1 and user2 are required"}), 400

    # Find all messages between user1 and user2
    messages = ChatMessage.query.filter(
        db.or_(
            db.and_(ChatMessage.sender_id == user1, ChatMessage.receiver_id == user2),
            db.and_(ChatMessage.sender_id == user2, ChatMessage.receiver_id == user1)
        )
    ).all()

    if not messages:
        return jsonify({"message": "No chat messages found between these users"}), 404

    for msg in messages:
        db.session.delete(msg)
    db.session.commit()

    return jsonify({"message": f"Deleted all messages between user {user1} and user {user2}"}), 200



@app.route('/communications', methods=['POST'])
def create_communication():
    """
    Expects JSON:
    {
      "subject": "Team Meeting",
      "channel": "General",
      "priority": "High",
      "project": "Website Redesign",
      "date": "Jan 15, 2023",
      "participants": ["Sarah Johnson", "Mike Peters"]
    }
    """
    data = request.get_json() or {}
    if "subject" not in data:
        return jsonify({"message": "subject is required"}), 400

    # Convert participants to JSON string if it's a list
    participants_data = data.get("participants", [])
    if isinstance(participants_data, list):
        participants_str = json.dumps(participants_data)
    else:
        participants_str = str(participants_data)

    new_comm = Communication(
        subject=data["subject"],
        channel=data.get("channel", ""),
        priority=data.get("priority", "Medium"),
        project=data.get("project", ""),
        date=data.get("date", ""),
        participants=participants_str
    )
    db.session.add(new_comm)
    db.session.commit()
    return jsonify({"message": "Communication created", "id": new_comm.id}), 201

@app.route('/communications', methods=['GET'])
def get_all_communications():
    comms = Communication.query.all()
    results = []
    for c in comms:
        try:
            part_list = json.loads(c.participants)
        except:
            part_list = []
        results.append({
            "id": c.id,
            "subject": c.subject,
            "channel": c.channel,
            "priority": c.priority,
            "project": c.project,
            "date": c.date,
            "participants": part_list
        })
    return jsonify(results), 200

@app.route('/communications/<int:comm_id>', methods=['GET'])
def get_communication_by_id(comm_id):
    comm = Communication.query.get_or_404(comm_id)
    try:
        part_list = json.loads(comm.participants)
    except:
        part_list = []
    return jsonify({
        "id": comm.id,
        "subject": comm.subject,
        "channel": comm.channel,
        "priority": comm.priority,
        "project": comm.project,
        "date": comm.date,
        "participants": part_list
    }), 200

@app.route('/communications/<int:comm_id>', methods=['PUT'])
def update_communication(comm_id):
    comm = Communication.query.get_or_404(comm_id)
    data = request.get_json() or {}

    comm.subject = data.get("subject", comm.subject)
    comm.channel = data.get("channel", comm.channel)
    comm.priority = data.get("priority", comm.priority)
    comm.project = data.get("project", comm.project)
    comm.date = data.get("date", comm.date)

    if "participants" in data:
        p_data = data["participants"]
        if isinstance(p_data, list):
            comm.participants = json.dumps(p_data)
        else:
            comm.participants = str(p_data)

    db.session.commit()
    return jsonify({"message": f"Communication {comm_id} updated"}), 200

@app.route('/communications/<int:comm_id>', methods=['DELETE'])
def delete_communication(comm_id):
    comm = Communication.query.get_or_404(comm_id)
    db.session.delete(comm)
    db.session.commit()
    return jsonify({"message": f"Communication {comm_id} deleted"}), 200

# -------------------------------------------------------
# COMMUNICATION MESSAGES (Chats) ENDPOINTS
# -------------------------------------------------------
# 1. Create a message in a communication
@app.route('/communications/<int:comm_id>/messages', methods=['POST'])
def create_communication_message(comm_id):
    """
    Expects JSON:
    {
      "sender_id": 101,
      "content": "Hello team, any updates?"
    }
    """
    data = request.get_json() or {}
    if "sender_id" not in data or "content" not in data:
        return jsonify({"message": "sender_id and content are required"}), 400

    # Ensure the communication exists
    comm = Communication.query.get_or_404(comm_id)

    new_msg = CommunicationMessage(
        communication_id=comm.id,
        sender_id=data["sender_id"],
        content=data["content"],
        timestamp=data["timestamp"]
    )
    db.session.add(new_msg)
    db.session.commit()
    return jsonify({
        "message": "Message created",
        "msg_id": new_msg.id,
        # "timestamp": datetime.fromtimestamp(new_msg.timestamp).isoformat()
        "timpestamp":new_msg.timestamp
    }), 201

# 2. Get all messages for a communication
@app.route('/communications/<int:comm_id>/messages', methods=['GET'])
def get_communication_messages(comm_id):
    """
    Returns all messages for the given communication_id, sorted by timestamp ascending.
    """
    # Ensure the communication exists
    comm = Communication.query.get_or_404(comm_id)

    msgs = CommunicationMessage.query.filter_by(communication_id=comm).order_by(CommunicationMessage.timestamp.asc()).all()
    results = []
    for m in msgs:
        results.append({
            "id": m.id,
            "sender_id": m.sender_id,
            "content": m.content,
            # "timestamp": datetime.fromtimestamp(m.timestamp).isoformat()
            "timpestamp":m.timestamp
        })
    return jsonify(results), 200

# 3. Delete all messages for a communication
@app.route('/communications/<int:comm_id>/messages', methods=['DELETE'])
def delete_communication_messages(comm_id):
    """
    Deletes all messages under a given communication.
    """
    # Ensure the communication exists
    comm = Communication.query.get_or_404(comm_id)

    msgs = CommunicationMessage.query.filter_by(communication_id=comm_id).all()
    if not msgs:
        return jsonify({"message": "No messages found for this communication"}), 404

    for m in msgs:
        db.session.delete(m)
    db.session.commit()

    return jsonify({"message": f"Deleted all messages for communication {comm_id}"}), 200

#compliences
@app.route('/api/compliences', methods=['POST'])
def add_complience():
    """
    Create a new compliance record.
    Expects a JSON payload with:
      - subjects: string
      - Discription: string
      - date: string in format "YYYY-MM-DD"
      - posted_by: string
    """
    data = request.get_json()
    required_fields = ['subjects', 'Discription', 'date', 'posted_by']
    if not data or not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields"}), 400

    new_complience = Compliences(
        subjects=data['subjects'],
        Discription=data['Discription'],
        date=data['date'],
        posted_by=data['posted_by']
    )
    db.session.add(new_complience)
    db.session.commit()

    return jsonify({
        "message": "Complience record created",
        "id": new_complience.id
    }), 201

@app.route('/api/compliences', methods=['GET'])
def get_compliences():
    """
    Retrieve all compliance records.
    """
    records = Compliences.query.all()
    output = []
    for record in records:
        output.append({
            "id": record.id,
            "subjects": record.subjects,
            "Discription": record.Discription,
            "date": record.date,
            "posted_by": record.posted_by
        })
    return jsonify({
        "status": "success",
        "data": output
    }), 200


#dashboard
@app.route('/dashboardemployee/<int:employee_id>', methods=['GET'])
def get_employee_dashboard(employee_id):
    """
    Returns a summarized 'dashboard' view for a specific employee:
      - Tasks assigned to them (e.g., tasks due today, total tasks, etc.)
      - Today's shift (if any)
      - Example placeholders for hours worked, attendance status, weekly time data, etc.
      - You can expand or modify the logic to include real calculations or additional data.
    """

    # 1. Fetch the employee or return 404 if not found
    employee = Employee.query.get_or_404(employee_id)
    employee_full_name = f"{employee.first_name} {employee.last_name}"

    # 2. Retrieve all tasks assigned to this employee by name
    #    (assuming `Task.assigned_to` stores the full name)
    assigned_tasks = Task.query.filter_by(employee_id=employee_id).all()

    # 3. Identify which tasks are due today
    today_str = datetime.now().strftime("%d-%m-%Y")  # Matches your Task.due_date format "dd-mm-yyyy"
    tasks_due_today = [t for t in assigned_tasks if t.due_date == today_str]

    # 4. Check if there's a shift scheduled for this employee today
    #    (assuming Shift.staff_member also uses the employee's full name)
    shift_today = Shift.query.filter_by(employee_id=employee_id, date=today_str).first()
    current_shift = shift_today.shift_name if shift_today else "No shift scheduled"

    # 5. Example placeholders: hours today, attendance, weekly time tracking, etc.
    #    Replace these with real calculations if you track time logs or attendance data.
    hours_today = 8
    attendance_status = "Present"
    # weekly_time_tracking = [0, 2, 3, 4, 6, 2, 0]  # Example placeholder array

    records = Compliences.query.all()
    output = []
    for record in records:
        output.append({
            "id": record.id,
            "subjects": record.subjects,
            "Discription": record.Discription,
            "date": record.date,
            "posted_by": record.posted_by
        })

 # 6. Retrieve 'team chat' communications in which this employee is a participant
    #    We parse the 'participants' field (JSON) and check if it contains 'employee_id'.
    all_communications = Communication.query.all()
    relevant_communications = []
    for comm in all_communications:
        try:
            participant_list = json.loads(comm.participants)  # e.g. [1, 2, 3]
        except:
            participant_list = []
        # Check if this employee is in the participant list
        if employee_id in participant_list:
            # Retrieve messages for this communication
            messages_data = []
            # comm.messages is available because of the backref
            # sorted by timestamp ascending if you like:
            sorted_msgs = sorted(comm.messages, key=lambda m: m.timestamp)
            for msg in sorted_msgs:
                messages_data.append({
                    "id": msg.id,
                    "sender_id": msg.sender_id,
                    "content": msg.content,
                    "timestamp": msg.timestamp.isoformat()
                })
            relevant_communications.append({
                "communication_id": comm.id,
                "subject": comm.subject,
                "channel": comm.channel,
                "priority": comm.priority,
                "project": comm.project,
                "date": comm.date,
                "messages": messages_data
            })
    # 6. Build a response object with whatever data you want to show on the dashboard
    dashboard_data = {
        "employee_id": employee.id,
        "employee_name": employee_full_name,
        "current_shift": current_shift,
        "hours_today": hours_today,
        "attendance": attendance_status,
        # "weekly_time_tracking": weekly_time_tracking,
        "tasks_due_today": len(tasks_due_today),
        "todays_tasks": [
            {
                "task_id": t.id,
                "title": t.title,
                "due_date": t.due_date,
                "priority": t.priority,
                "status": t.status
            }
            for t in tasks_due_today
        ],
        # You could also show all assigned tasks, not just today's:
        "total_assigned_tasks": len(assigned_tasks),
        "all_tasks": [
            {
                "task_id": t.id,
                "title": t.title,
                "due_date": t.due_date,
                "priority": t.priority,
                "status": t.status
            }
            for t in assigned_tasks
        ],
        # Example placeholders for chat messages or announcements
        "team_chat": relevant_communications,
        "announcements": output
    }

    return jsonify(dashboard_data), 200

#Admin Dashboard 

@app.route("/admindashboard", methods=["GET"])
def get_admin_dashboard():
    # 1. Count total employees and active employees
    total_employee = Employee.query.count()
    active_employees = Employee.query.filter_by(is_active=True).count()

    # 2. Use today's date to retrieve tasks and shift information
    today_str = datetime.now().strftime("%d-%m-%Y")
    # Use due_date since Task model uses 'due_date'
    assigned_tasks = Task.query.filter_by(due_date=today_str).all()
    tasks_due_today = [t for t in assigned_tasks if t.due_date == today_str]

    # For shifts, use the correct column 'date'
    shift_today = Shift.query.filter_by(date=today_str).first()
    current_shift = shift_today.shift_name if shift_today else "No shift scheduled"

    # 3. Get all compliance records (unchanged)
    records = Compliences.query.all()
    announcements = []
    for record in records:
        announcements.append({
            "id": record.id,
            "subjects": record.subjects,
            "Discription": record.Discription,
            "date": record.date,
            "posted_by": record.posted_by
        })

    # 4. Get all communications (team chat) information (unchanged)
    all_comms = Communication.query.all()
    team_chat = []
    for comm in all_comms:
        team_chat.append({
            "communication_id": comm.id,
            "subject": comm.subject,
            "channel": comm.channel,
            "priority": comm.priority,
            "project": comm.project,
            "date": comm.date,
        })

    # 5. Build the dashboard response
    dashboard_data = {
        "employee_all": [{
            "total_employee": total_employee,
            "active_employee": active_employees
        }],
        "current_shift": current_shift,
        "tasks_due_today": len(tasks_due_today),
        "todays_tasks": [{
            "task_id": t.id,
            "title": t.title,
            "due_date": t.due_date,
            "priority": t.priority,
            "status": t.status
        } for t in tasks_due_today],
        "total_assigned_tasks": len(assigned_tasks),
        "all_tasks": [{
            "task_id": t.id,
            "title": t.title,
            "due_date": t.due_date,
            "priority": t.priority,
            "status": t.status
        } for t in assigned_tasks],
        "team_chat": team_chat,
        "announcements": announcements
    }

    return jsonify(dashboard_data), 200


# MAIN
if __name__ == '__main__': 
    with app.app_context():
        db.create_all()
        print("Tables created (if not already present).")
    socketio.run(app, debug=True, port=5000)
