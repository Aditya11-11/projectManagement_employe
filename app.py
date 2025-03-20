import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash

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
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Set a secret key for JWT (change this in production)
app.config['JWT_SECRET_KEY'] = 'super-secret-key'

# Initialize SQLAlchemy, JWTManager, and SocketIO
db = SQLAlchemy(app)
jwt = JWTManager(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # For development only

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
    department = db.Column(db.String(100))
    is_active  = db.Column(db.Boolean, default=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='Employee')

class Admin(db.Model):  # admin data 
    __tablename__ = 'admins'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name  = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default='')
    due_date = db.Column(db.String(10), default='')  # "dd-mm-yyyy"
    priority = db.Column(db.String(10), default='Medium')  # "Low", "Medium", or "High"
    assigned_to = db.Column(db.String(100), default='')

class PolicyDocument(db.Model):
    __tablename__ = 'policy_documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), default='')
    status = db.Column(db.String(50), default='Active')  # e.g. Active, Archived
    doc_url = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PolicyAcknowledgement(db.Model):
    __tablename__ = 'policy_acknowledgements'
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy_documents.id'), nullable=False)
    user_id = db.Column(db.Integer, nullable=False)  # references some user/employee ID
    ack_status = db.Column(db.String(50), default='Acknowledged')
    ack_date = db.Column(db.DateTime, default=datetime.utcnow)

class LeaveRequest(db.Model):
    __tablename__ = 'leave_requests'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, nullable=False)
    leave_type = db.Column(db.String(20), default='Annual')  # "Annual", "Sick", "Other"
    start_date = db.Column(db.String(10), nullable=False)    # "YYYY-MM-DD"
    end_date = db.Column(db.String(10), nullable=False)      # "YYYY-MM-DD"
    days = db.Column(db.Float, default=1.0)
    status = db.Column(db.String(20), default='Pending')     # "Pending", "Approved", "Rejected"
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class EmployeeLeaveBalance(db.Model):
    """
    Tracks how many annual leave days an employee has left for a given year.
    Default is 50.0 days per year.
    """
    __tablename__ = 'employee_leave_balance'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    annual_remaining = db.Column(db.Float, default=50.0)

####################################################
# ENDPOINTS
####################################################
# -------------------------
# EMPLOYEE AUTH & CRUD ENDPOINTS
# -------------------------

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
    
    if not all([first_name, last_name, email, password]):
        return jsonify({"message": "Missing required fields"}), 400

    if Employee.query.filter_by(email=email).first():
        return jsonify({"message": "Email already registered"}), 400

    hashed_password = generate_password_hash(password)
    new_employee = Employee(
        first_name=first_name,
        last_name=last_name,
        email=email,
        password=hashed_password
    )
    db.session.add(new_employee)
    db.session.commit()

    return jsonify({"message": "Registration successful", "employee_id": new_employee.id}), 201

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
            "role": "employee"
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
            "role": emp.role
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
        "role": emp.role
    }
    return jsonify(result), 200

# Delete an employee (Protected)
@app.route('/employees/<int:employee_id>', methods=['DELETE'])
@jwt_required()
def delete_employee(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    db.session.delete(emp)
    db.session.commit()
    return jsonify({"message": "Employee deleted"}), 200

# Update employee email (Protected)
@app.route('/employees/<int:employee_id>/update_email', methods=['PUT'])
@jwt_required()
def update_email(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    data = request.get_json()
    new_email = data.get("email")
    if not new_email:
        return jsonify({"message": "New email is required"}), 400

    if Employee.query.filter_by(email=new_email).first():
        return jsonify({"message": "Email already in use"}), 400

    emp.email = new_email
    db.session.commit()
    return jsonify({"message": "Email updated successfully"}), 200

# Change employee password (Protected)
@app.route('/employees/<int:employee_id>/change_password', methods=['PUT'])
@jwt_required()
def change_password(employee_id):
    emp = Employee.query.get_or_404(employee_id)
    data = request.get_json()
    old_password = data.get("old_password")
    new_password = data.get("new_password")
    
    if not old_password or not new_password:
        return jsonify({"message": "Both old and new passwords are required"}), 400

    if not check_password_hash(emp.password, old_password):
        return jsonify({"message": "Old password is incorrect"}), 401

    emp.password = generate_password_hash(new_password)
    db.session.commit()
    return jsonify({"message": "Password changed successfully"}), 200

# Update employee status by ID (Protected)
@app.route('/employees/<int:employee_id>/update_status', methods=['PUT'])
@jwt_required()
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
        password=hashed_password
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
@jwt_required()
def delete_admin(admin_id):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403

    adm = Admin.query.get_or_404(admin_id)
    db.session.delete(adm)
    db.session.commit()
    return jsonify({"message": "Admin deleted"}), 200

# Update Admin Email (Protected, Admin-only)
@app.route('/admin/admins/update_email/<int:admin_id>', methods=['PUT'])
@jwt_required()
def update_admin_email(admin_id):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403

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
@jwt_required()
def change_admin_password(admin_id):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403

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
@jwt_required()  # Add this decorator to require authentication
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
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403
    data = request.get_json()
    if not data or "title" not in data:
        return jsonify({"message": "Task title is required"}), 400
    
    title = data["title"]
    description = data.get("description", "")
    due_date = data.get("due_date", "")
    priority = data.get("priority", "Medium")
    assigned_to = data.get("assigned_to", "")

    new_task = Task(
        title=title,
        description=description,
        due_date=due_date,
        priority=priority,
        assigned_to=assigned_to
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

    query = Task.query
    
    # Filter by title (case-insensitive "contains" search)
    if title_filter:
        query = query.filter(Task.title.ilike(f"%{title_filter}%"))
    
    # Filter by priority (exact match)
    if priority_filter:
        query = query.filter_by(priority=priority_filter)

    tasks = query.all()
    results = []
    for t in tasks:
        results.append({
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "due_date": t.due_date,
            "priority": t.priority,
            "assigned_to": t.assigned_to
        })
    return jsonify(results), 200

#  Delete Task by title (DELETE) 
@app.route('/tasks/<string:task_title>', methods=['DELETE'])
@jwt_required() 
def delete_task_by_title(task_title):
    """
    Delete the first task matching the given title.
    If multiple tasks have the same title, only the first match is deleted.
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403 
    task = Task.query.filter_by(title=task_title).first()
    if not task:
        return jsonify({"message": f"No task found with title '{task_title}'"}), 404
    
    db.session.delete(task)
    db.session.commit()
    return jsonify({"message": f"Task with title '{task_title}' deleted"}), 200


# Create (POST) a new policy document
@app.route('/policy/documents', methods=['POST'])
@jwt_required()
def create_policy_document():
    """
    Expects JSON:
    {
      "title": "Employee Handbook",
      "description": "Company policies, procedures, and guidelines",
      "status": "Active",
      "doc_url": "http://example.com/docs/handbook.pdf"
    }
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403
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
@jwt_required()
def delete_policy_document(doc_id):
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403
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
@jwt_required()
def acknowledge_policy_document(doc_id):
    """
    Expects JSON:
    {
      "user_id": 123
    }
    """
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
@jwt_required()
def set_annual_balance():

    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403

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
@jwt_required()
def apply_new_leave():
    """
    Expects JSON:
    {
      "employee_id": 123,
      "leave_type": "Annual",
      "start_date": "2024-02-15",
      "end_date": "2024-02-18",
      "days": 4
    }
    """
    claims = get_jwt()
    if claims.get("role") != "employee":
        return jsonify({"message": "Employees only"}), 403
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
        status="Pending"
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
    query = LeaveRequest.query
    if employee_id:
        query = query.filter_by(employee_id=employee_id)
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
            "created_at": r.created_at.isoformat()
        })
    return jsonify(data), 200

# Approve/Reject a Leave Request (PUT)
@app.route('/leave/requests/decision/<int:req_id>', methods=['PUT'])
@jwt_required()
def decide_leave_request(req_id):
    """
    Expects JSON:
    {
      "status": "Approved" or "Rejected"
    }
    If approving for the first time, subtract from user's annual balance.
    """
    claims = get_jwt()
    if claims.get("role") != "admin":
        return jsonify({"message": "Admins only"}), 403
    
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
        "created_at": req.created_at.isoformat()
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
####################################################
# MAIN
####################################################
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Tables created (if not already present).")
    socketio.run(app, debug=True, port=5000)
