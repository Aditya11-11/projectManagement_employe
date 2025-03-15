import os
from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO, emit, join_room, leave_room

####################################################
# FLASK & DATABASE CONFIGURATION
####################################################
app = Flask(__name__)

# Local MySQL Database Configuration
# username = "root"         # Adjust as needed
# password = "password"     # Adjust as needed
# host = "localhost"
# database_name = "DashboardDB"
# connection_string = f"mysql+pymysql://{username}:{password}@{host}/{database_name}"
# app.config['SQLALCHEMY_DATABASE_URI'] = connection_string
# app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///test.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize SQLAlchemy and SocketIO
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")  # For development only

####################################################
# MODELS
####################################################
# Common Models
class Employee(db.Model):
    __tablename__ = 'employees'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    department = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, default=True)
    # Additional fields for Policy/Security
    two_factor_enabled = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(50), default='Employee')

class Task(db.Model):
    __tablename__ = 'tasks'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(500), default='')
    due_date = db.Column(db.String(50), default='')   # e.g., "dd-mm-yyyy"
    priority = db.Column(db.String(20), default='Medium')  # "High", "Medium", "Low"
    status = db.Column(db.String(50), default='Open')
    assigned_to = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=True)

class Shift(db.Model):
    __tablename__ = 'shifts'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    start_time = db.Column(db.String(50), nullable=False)
    end_time = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Active')

class TimeOffRequest(db.Model):
    __tablename__ = 'timeoff_requests'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    start_date = db.Column(db.String(50), nullable=False)
    end_date = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='Pending')

class Performance(db.Model):
    __tablename__ = 'performance'
    id = db.Column(db.Integer, primary_key=True)
    date = db.Column(db.String(50), default='')  # e.g., "YYYY-MM-DD"
    tasks_completed = db.Column(db.Integer, default=0)
    hours_worked = db.Column(db.Integer, default=0)

class ActivityLog(db.Model):
    __tablename__ = 'activity_log'
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Event(db.Model):
    __tablename__ = 'events'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    date = db.Column(db.String(50), nullable=False)   # "dd-mm-yyyy"
    time = db.Column(db.String(50), nullable=False)   # "hh:mm AM/PM"
    duration = db.Column(db.String(50), default='30 minutes')
    description = db.Column(db.String(500), default='')
    participants = db.Column(db.String(255), default='')
    color = db.Column(db.String(20), default='blue')

# Chat Models
class ChatRoom(db.Model):
    __tablename__ = 'chat_rooms'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatRoomMember(db.Model):
    __tablename__ = 'chat_room_members'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_rooms.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)

class ChatMessage(db.Model):
    __tablename__ = 'chat_messages'
    id = db.Column(db.Integer, primary_key=True)
    room_id = db.Column(db.Integer, db.ForeignKey('chat_rooms.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    content = db.Column(db.String(1000), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Leave Management Models
class EmployeeLeaveBalance(db.Model):
    __tablename__ = 'employee_leave_balance'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    year = db.Column(db.Integer, default=datetime.now().year)
    annual_remaining = db.Column(db.Float, default=0.0)
    sick_remaining = db.Column(db.Float, default=0.0)
    other_remaining = db.Column(db.Float, default=0.0)
    total_taken = db.Column(db.Float, default=0.0)

class LeaveRequest(db.Model):
    __tablename__ = 'leave_requests'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    leave_type = db.Column(db.String(20), default='Annual')  # "Annual", "Sick", "Other"
    start_date = db.Column(db.String(50), nullable=False)    # "YYYY-MM-DD"
    end_date = db.Column(db.String(50), nullable=False)      # "YYYY-MM-DD"
    days = db.Column(db.Float, default=1.0)
    status = db.Column(db.String(20), default='Pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Policy Models
class PolicyDocument(db.Model):
    __tablename__ = 'policy_documents'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(500), default='')
    status = db.Column(db.String(50), default='Active')
    doc_url = db.Column(db.String(500), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class PolicyAcknowledgement(db.Model):
    __tablename__ = 'policy_acknowledgements'
    id = db.Column(db.Integer, primary_key=True)
    policy_id = db.Column(db.Integer, db.ForeignKey('policy_documents.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    ack_status = db.Column(db.String(50), default='Acknowledged')
    ack_date = db.Column(db.DateTime, default=datetime.utcnow)

# Time Tracking Models
class Attendance(db.Model):
    __tablename__ = 'attendance'
    id = db.Column(db.Integer, primary_key=True)
    employee_id = db.Column(db.Integer, db.ForeignKey('employees.id'), nullable=False)
    date = db.Column(db.String(50), nullable=False)  # "YYYY-MM-DD"
    is_late = db.Column(db.Boolean, default=False)
    hours_worked = db.Column(db.Float, default=0.0)
    break_time = db.Column(db.Float, default=0.0)
    status = db.Column(db.String(20), default='Present')

class Project(db.Model):
    __tablename__ = 'projects'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    progress = db.Column(db.Integer, default=0)  # 0-100

####################################################
# ENDPOINTS
####################################################
# ------------------------------
# DASHBOARD ENDPOINTS
# ------------------------------
@app.route('/dashboard/summary', methods=['GET'])
def get_dashboard_summary():
    active_employees = Employee.query.filter_by(is_active=True).count()
    open_tasks = Task.query.filter_by(status='Open').count()
    todays_shifts = Shift.query.filter_by(status='Active').count()
    pending_requests = TimeOffRequest.query.filter_by(status='Pending').count()
    return jsonify({
        "activeEmployees": active_employees,
        "openTasks": open_tasks,
        "todaysShifts": todays_shifts,
        "timeOffRequests": pending_requests
    }), 200

@app.route('/activities', methods=['GET'])
def get_activities():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(10).all()
    results = [{"description": log.description, "timestamp": log.timestamp.isoformat()} for log in logs]
    return jsonify(results), 200

@app.route('/performance', methods=['GET'])
def get_performance():
    records = Performance.query.all()
    results = [{"date": r.date, "tasks_completed": r.tasks_completed, "hours_worked": r.hours_worked} for r in records]
    return jsonify(results), 200

@app.route('/shifts', methods=['GET'])
def get_shifts():
    shifts = Shift.query.all()
    results = [{"id": s.id, "employee_id": s.employee_id, "start_time": s.start_time, "end_time": s.end_time, "status": s.status} for s in shifts]
    return jsonify(results), 200

@app.route('/timeoff', methods=['GET'])
def get_timeoff_requests():
    reqs = TimeOffRequest.query.all()
    results = [{"id": r.id, "employee_id": r.employee_id, "start_date": r.start_date, "end_date": r.end_date, "status": r.status} for r in reqs]
    return jsonify(results), 200

# ------------------------------
# TASKS ENDPOINTS
# ------------------------------
@app.route('/tasks', methods=['GET'])
def get_all_tasks():
    tasks = Task.query.all()
    results = []
    for t in tasks:
        results.append({
            "id": t.id,
            "title": t.title,
            "description": t.description,
            "due_date": t.due_date,
            "priority": t.priority,
            "status": t.status,
            "assigned_to": t.assigned_to
        })
    return jsonify(results), 200

@app.route('/tasks/<int:task_id>', methods=['GET'])
def get_single_task(task_id):
    t = Task.query.get_or_404(task_id)
    return jsonify({
        "id": t.id,
        "title": t.title,
        "description": t.description,
        "due_date": t.due_date,
        "priority": t.priority,
        "status": t.status,
        "assigned_to": t.assigned_to
    }), 200

@app.route('/tasks', methods=['POST'])
def create_task():
    data = request.get_json()
    if not data or "title" not in data:
        return jsonify({"message": "title is required"}), 400
    new_task = Task(
        title=data["title"],
        description=data.get("description", ""),
        due_date=data.get("due_date", ""),
        priority=data.get("priority", "Medium"),
        status=data.get("status", "Open"),
        assigned_to=data.get("assigned_to")
    )
    db.session.add(new_task)
    db.session.commit()
    return jsonify({"message": "Task created", "task_id": new_task.id}), 201

@app.route('/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    t = Task.query.get_or_404(task_id)
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data"}), 400
    t.title = data.get("title", t.title)
    t.description = data.get("description", t.description)
    t.due_date = data.get("due_date", t.due_date)
    t.priority = data.get("priority", t.priority)
    t.status = data.get("status", t.status)
    t.assigned_to = data.get("assigned_to", t.assigned_to)
    db.session.commit()
    return jsonify({"message": "Task updated"}), 200

@app.route('/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    t = Task.query.get_or_404(task_id)
    db.session.delete(t)
    db.session.commit()
    return jsonify({"message": "Task deleted"}), 200

# ------------------------------
# SCHEDULE (CALENDAR) ENDPOINTS
# ------------------------------
@app.route('/schedule/events', methods=['POST'])
def create_event_route():
    data = request.get_json()
    if not data or not all(k in data for k in ("title", "date", "time")):
        return jsonify({"message": "title, date, and time are required"}), 400
    new_event = Event(
        title=data["title"],
        date=data["date"],
        time=data["time"],
        duration=data.get("duration", "30 minutes"),
        description=data.get("description", ""),
        participants=data.get("participants", ""),
        color=data.get("color", "blue")
    )
    db.session.add(new_event)
    db.session.commit()
    return jsonify({"message": "Event created", "event_id": new_event.id}), 201

@app.route('/schedule/events', methods=['GET'])
def get_events():
    view = request.args.get("view")  # day, week, month
    refDate = request.args.get("refDate")  # "YYYY-MM-DD"
    if view and refDate:
        try:
            ref_date_obj = datetime.strptime(refDate, "%Y-%m-%d").date()
        except ValueError:
            return jsonify({"message": "Invalid refDate format. Use YYYY-MM-DD."}), 400
        if view == "day":
            day_str = ref_date_obj.strftime("%d-%m-%Y")
            events = Event.query.filter(Event.date == day_str).all()
        elif view == "week":
            date_list = [(ref_date_obj + timedelta(days=i)).strftime("%d-%m-%Y") for i in range(7)]
            events = Event.query.filter(Event.date.in_(date_list)).all()
        elif view == "month":
            all_events = Event.query.all()
            events = []
            for ev in all_events:
                try:
                    ev_date = datetime.strptime(ev.date, "%d-%m-%Y").date()
                    if ev_date.year == ref_date_obj.year and ev_date.month == ref_date_obj.month:
                        events.append(ev)
                except:
                    pass
        else:
            return jsonify({"message": "Invalid view param. Use day, week, or month."}), 400
    else:
        events = Event.query.all()
    results = [{
        "id": ev.id,
        "title": ev.title,
        "date": ev.date,
        "time": ev.time,
        "duration": ev.duration,
        "description": ev.description,
        "participants": ev.participants,
        "color": ev.color
    } for ev in events]
    return jsonify(results), 200

@app.route('/schedule/events/<int:event_id>', methods=['GET'])
def get_event(event_id):
    ev = Event.query.get_or_404(event_id)
    return jsonify({
        "id": ev.id,
        "title": ev.title,
        "date": ev.date,
        "time": ev.time,
        "duration": ev.duration,
        "description": ev.description,
        "participants": ev.participants,
        "color": ev.color
    }), 200

@app.route('/schedule/events/<int:event_id>', methods=['PUT'])
def update_event_route(event_id):
    ev = Event.query.get_or_404(event_id)
    data = request.get_json()
    if not data:
        return jsonify({"message": "No input data"}), 400
    ev.title = data.get("title", ev.title)
    ev.date = data.get("date", ev.date)
    ev.time = data.get("time", ev.time)
    ev.duration = data.get("duration", ev.duration)
    ev.description = data.get("description", ev.description)
    ev.participants = data.get("participants", ev.participants)
    ev.color = data.get("color", ev.color)
    db.session.commit()
    return jsonify({"message": "Event updated"}), 200

@app.route('/schedule/events/<int:event_id>', methods=['DELETE'])
def delete_event_route(event_id):
    ev = Event.query.get_or_404(event_id)
    db.session.delete(ev)
    db.session.commit()
    return jsonify({"message": "Event deleted"}), 200

# ------------------------------
# CHAT ENDPOINTS & SOCKET.IO EVENTS
# ------------------------------
@app.route('/chat/rooms', methods=['GET'])
def get_chat_rooms():
    rooms = ChatRoom.query.all()
    data = [{"id": r.id, "name": r.name, "created_at": r.created_at.isoformat()} for r in rooms]
    return jsonify(data), 200

@app.route('/chat/rooms', methods=['POST'])
def create_chat_room():
    data = request.get_json()
    if not data or "name" not in data:
        return jsonify({"message": "Room name is required"}), 400
    new_room = ChatRoom(name=data["name"])
    db.session.add(new_room)
    db.session.commit()
    # Add members if provided
    members = data.get("members", [])
    for user_id in members:
        membership = ChatRoomMember(room_id=new_room.id, user_id=user_id)
        db.session.add(membership)
    db.session.commit()
    return jsonify({"message": "Chat room created", "room_id": new_room.id}), 201

@app.route('/chat/rooms/<int:room_id>/members', methods=['POST'])
def add_members_to_room(room_id):
    data = request.get_json()
    if not data or "members" not in data:
        return jsonify({"message": "members list is required"}), 400
    room = ChatRoom.query.get_or_404(room_id)
    for user_id in data["members"]:
        if not ChatRoomMember.query.filter_by(room_id=room_id, user_id=user_id).first():
            membership = ChatRoomMember(room_id=room_id, user_id=user_id)
            db.session.add(membership)
    db.session.commit()
    return jsonify({"message": "Members added to room"}), 200

@app.route('/chat/rooms/<int:room_id>/messages', methods=['GET'])
def get_room_messages():
    ChatRoom.query.get_or_404(room_id=request.view_args.get('room_id'))
    messages = ChatMessage.query.filter_by(room_id=request.view_args.get('room_id')).order_by(ChatMessage.timestamp.asc()).all()
    data = [{"id": m.id, "room_id": m.room_id, "sender_id": m.sender_id, "content": m.content, "timestamp": m.timestamp.isoformat()} for m in messages]
    return jsonify(data), 200

@app.route('/chat/rooms/<int:room_id>/messages', methods=['POST'])
def post_room_message():
    data = request.get_json()
    if not data or "sender_id" not in data or "content" not in data:
        return jsonify({"message": "sender_id and content are required"}), 400
    room = ChatRoom.query.get_or_404(room_id=request.view_args.get('room_id'))
    new_msg = ChatMessage(room_id=room.id, sender_id=data["sender_id"], content=data["content"])
    db.session.add(new_msg)
    db.session.commit()
    socketio.emit("new_message", {
        "id": new_msg.id,
        "room_id": new_msg.room_id,
        "sender_id": new_msg.sender_id,
        "content": new_msg.content,
        "timestamp": new_msg.timestamp.isoformat()
    }, room=str(room.id))
    return jsonify({"message": "Message sent", "msg_id": new_msg.id}), 201

@socketio.on('join')
def on_join(data):
    room_id = data.get("room_id")
    user_id = data.get("user_id")
    if room_id and user_id:
        join_room(str(room_id))
        print(f"User {user_id} joined room {room_id}")

@socketio.on('leave')
def on_leave(data):
    room_id = data.get("room_id")
    user_id = data.get("user_id")
    if room_id and user_id:
        leave_room(str(room_id))
        print(f"User {user_id} left room {room_id}")

@socketio.on('send_message')
def on_send_message(data):
    room_id = data.get("room_id")
    sender_id = data.get("sender_id")
    content = data.get("content")
    if not room_id or not sender_id or not content:
        return
    new_msg = ChatMessage(room_id=room_id, sender_id=sender_id, content=content)
    db.session.add(new_msg)
    db.session.commit()
    socketio.emit("new_message", {
        "id": new_msg.id,
        "room_id": new_msg.room_id,
        "sender_id": new_msg.sender_id,
        "content": new_msg.content,
        "timestamp": new_msg.timestamp.isoformat()
    }, room=str(room_id))

# ------------------------------
# LEAVE MANAGEMENT ENDPOINTS
# ------------------------------
@app.route('/leave/summary', methods=['GET'])
def get_leave_summary():
    employee_id = request.args.get("employee_id", type=int)
    year = request.args.get("year", type=int, default=datetime.now().year)
    if not employee_id:
        return jsonify({"message": "employee_id is required"}), 400
    bal = EmployeeLeaveBalance.query.filter_by(employee_id=employee_id, year=year).first()
    if not bal:
        return jsonify({
            "annualRemaining": 0,
            "sickRemaining": 0,
            "otherRemaining": 0,
            "totalTaken": 0
        }), 200
    return jsonify({
        "annualRemaining": bal.annual_remaining,
        "sickRemaining": bal.sick_remaining,
        "otherRemaining": bal.other_remaining,
        "totalTaken": bal.total_taken
    }), 200

@app.route('/leave/requests', methods=['GET'])
def get_leave_requests():
    employee_id = request.args.get("employee_id", type=int)
    if not employee_id:
        return jsonify({"message": "employee_id is required"}), 400
    reqs = LeaveRequest.query.filter_by(employee_id=employee_id).order_by(LeaveRequest.created_at.desc()).limit(10).all()
    data = [{"id": r.id, "date": r.start_date, "type": r.leave_type, "duration": r.days, "status": r.status} for r in reqs]
    return jsonify(data), 200

@app.route('/leave/requests', methods=['POST'])
def apply_new_leave():
    data = request.get_json()
    required = ["employee_id", "leave_type", "start_date", "end_date", "days"]
    if not data or not all(field in data for field in required):
        return jsonify({"message": "Missing required fields"}), 400
    new_req = LeaveRequest(
        employee_id=data["employee_id"],
        leave_type=data["leave_type"],
        start_date=data["start_date"],
        end_date=data["end_date"],
        days=data["days"],
        status=data.get("status", "Pending")
    )
    db.session.add(new_req)
    db.session.commit()
    return jsonify({"message": "Leave request created", "request_id": new_req.id}), 201

@app.route('/leave/stats', methods=['GET'])
def get_leave_stats():
    employee_id = request.args.get("employee_id", type=int)
    year = request.args.get("year", type=int, default=datetime.now().year)
    if not employee_id:
        return jsonify({"message": "employee_id is required"}), 400
    all_reqs = LeaveRequest.query.filter_by(employee_id=employee_id).all()
    stats = {i: {"annual": 0, "sick": 0, "other": 0} for i in range(1, 13)}
    months = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"]
    for r in all_reqs:
        try:
            dt_obj = datetime.strptime(r.start_date, "%Y-%m-%d")
            if dt_obj.year == year:
                m = dt_obj.month
                lt = r.leave_type.lower()
                if "annual" in lt:
                    stats[m]["annual"] += r.days
                elif "sick" in lt:
                    stats[m]["sick"] += r.days
                else:
                    stats[m]["other"] += r.days
        except:
            pass
    results = [{"month": months[m-1], "annual": stats[m]["annual"], "sick": stats[m]["sick"], "other": stats[m]["other"]} for m in range(1, 13)]
    return jsonify(results), 200

@app.route('/leave/requests/<int:req_id>', methods=['GET'])
def get_leave_request_detail(req_id):
    r = LeaveRequest.query.get_or_404(req_id)
    return jsonify({
        "id": r.id,
        "employee_id": r.employee_id,
        "leave_type": r.leave_type,
        "start_date": r.start_date,
        "end_date": r.end_date,
        "days": r.days,
        "status": r.status,
        "created_at": r.created_at.isoformat()
    }), 200

# ------------------------------
# POLICY ENDPOINTS
# ------------------------------
@app.route('/policy/documents', methods=['GET'])
def get_policy_documents():
    user_id = request.args.get("user_id", type=int)
    docs = PolicyDocument.query.order_by(PolicyDocument.created_at.desc()).all()
    data = []
    for d in docs:
        doc_info = {
            "id": d.id,
            "title": d.title,
            "description": d.description,
            "status": d.status,
            "doc_url": d.doc_url,
            "created_at": d.created_at.isoformat()
        }
        if user_id:
            ack = PolicyAcknowledgement.query.filter_by(policy_id=d.id, user_id=user_id).first()
            if ack:
                doc_info["acknowledged"] = True
                doc_info["ack_date"] = ack.ack_date.isoformat()
            else:
                doc_info["acknowledged"] = False
                doc_info["ack_date"] = None
        data.append(doc_info)
    return jsonify(data), 200

@app.route('/policy/documents', methods=['POST'])
def create_policy_document():
    data = request.get_json()
    if not data or "title" not in data:
        return jsonify({"message": "title is required"}), 400
    new_doc = PolicyDocument(
        title=data["title"],
        description=data.get("description", ""),
        status=data.get("status", "Active"),
        doc_url=data.get("doc_url", "")
    )
    db.session.add(new_doc)
    db.session.commit()
    return jsonify({"message": "Policy document created", "doc_id": new_doc.id}), 201

@app.route('/policy/documents/<int:doc_id>/acknowledge', methods=['POST'])
def acknowledge_policy(doc_id):
    data = request.get_json()
    if not data or "user_id" not in data:
        return jsonify({"message": "user_id is required"}), 400
    PolicyDocument.query.get_or_404(doc_id)
    user_id = data["user_id"]
    if PolicyAcknowledgement.query.filter_by(policy_id=doc_id, user_id=user_id).first():
        return jsonify({"message": "Already acknowledged"}), 200
    new_ack = PolicyAcknowledgement(policy_id=doc_id, user_id=user_id, ack_status="Acknowledged")
    db.session.add(new_ack)
    db.session.commit()
    return jsonify({"message": "Policy acknowledged"}), 201

@app.route('/policy/ack-history', methods=['GET'])
def get_ack_history():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"message": "user_id query param is required"}), 400
    acks = db.session.query(PolicyAcknowledgement, PolicyDocument).join(PolicyDocument, PolicyAcknowledgement.policy_id == PolicyDocument.id).filter(PolicyAcknowledgement.user_id == user_id).order_by(PolicyAcknowledgement.ack_date.desc()).all()
    data = []
    for ack, doc in acks:
        data.append({
            "policy_id": doc.id,
            "title": doc.title,
            "ack_status": ack.ack_status,
            "ack_date": ack.ack_date.isoformat()
        })
    return jsonify(data), 200

@app.route('/policy/security', methods=['GET'])
def get_security_settings():
    user_id = request.args.get("user_id", type=int)
    if not user_id:
        return jsonify({"message": "user_id is required"}), 400
    emp = Employee.query.get_or_404(user_id)
    permissions = []
    if emp.role == "Senior Employee":
        permissions = ["Access to all company policies", "View department-specific guidelines", "No editing privileges"]
    elif emp.role == "Admin":
        permissions = ["Full editing privileges", "Manage employee roles", "Access to all policies"]
    else:
        permissions = ["Basic policy access", "View own department guidelines"]
    return jsonify({
        "twoFactor": emp.two_factor_enabled,
        "role": emp.role,
        "permissions": permissions
    }), 200

@app.route('/policy/security', methods=['PUT'])
def update_security_settings():
    data = request.get_json()
    if not data or "user_id" not in data:
        return jsonify({"message": "user_id is required"}), 400
    emp = Employee.query.get_or_404(data["user_id"])
    if "twoFactor" in data:
        emp.two_factor_enabled = data["twoFactor"]
    db.session.commit()
    return jsonify({"message": "Security settings updated"}), 200

# ------------------------------
# TIME TRACKING ENDPOINTS
# ------------------------------
@app.route('/time/attendance', methods=['GET'])
def get_attendance_overview():
    total_emps = Employee.query.count()
    today_str = datetime.now().strftime("%Y-%m-%d")
    records = Attendance.query.filter_by(date=today_str).all()
    present_count = sum(1 for a in records if a.status == 'Present')
    absent_count = sum(1 for a in records if a.status == 'Absent')
    late_count = sum(1 for a in records if a.is_late)
    undertime_count = sum(1 for a in records if a.hours_worked < 8 and a.status == 'Present')
    present_percentage = (present_count / total_emps * 100) if total_emps else 0.0
    return jsonify({
        "logged_in": present_count,
        "absent": absent_count,
        "late": late_count,
        "undertime": undertime_count,
        "totalEmployees": total_emps,
        "presentPercentage": round(present_percentage, 1)
    }), 200

@app.route('/time/overview', methods=['GET'])
def get_time_overview():
    results = []
    for i in range(7):
        day_obj = datetime.now() - timedelta(days=6 - i)
        day_str = day_obj.strftime("%Y-%m-%d")
        records = Attendance.query.filter_by(date=day_str).all()
        total_hours = sum(a.hours_worked for a in records)
        results.append({"date": day_str, "hours_worked": total_hours})
    return jsonify(results), 200

@app.route('/time/today', methods=['GET'])
def get_todays_summary():
    today_str = datetime.now().strftime("%Y-%m-%d")
    records = Attendance.query.filter_by(date=today_str).all()
    if not records:
        return jsonify({"hoursWorked": 0, "break": 0, "productivity": 0}), 200
    total_hours = sum(a.hours_worked for a in records)
    total_break = sum(a.break_time for a in records)
    avg_productivity = (total_hours / (8 * len(records)) * 100) if records else 0
    return jsonify({
        "hoursWorked": round(total_hours, 1),
        "break": round(total_break, 1),
        "productivity": round(avg_productivity, 1)
    }), 200

@app.route('/time/activities', methods=['GET'])
def get_time_activities():
    logs = ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(5).all()
    results = [{"description": log.description, "timestamp": log.timestamp.isoformat()} for log in logs]
    return jsonify(results), 200

@app.route('/time/projects', methods=['GET'])
def get_projects_progress():
    projects = Project.query.all()
    results = [{"id": p.id, "name": p.name, "progress": p.progress} for p in projects]
    return jsonify(results), 200

####################################################
# MAIN & TABLE CREATION
####################################################
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Tables created (if not already present).")
    socketio.run(app, debug=True, port=5000)
