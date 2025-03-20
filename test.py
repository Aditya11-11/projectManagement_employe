# 1. Apply for Leave (POST)
@app.route('/leave/requests', methods=['POST'])
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

# 2. Get Leave Requests (GET)
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

# 3. Approve/Reject a Leave Request (PUT)
@app.route('/leave/requests/<int:req_id>/decision', methods=['PUT'])
def decide_leave_request(req_id):
    """
    Expects JSON:
    {
      "status": "Approved" or "Rejected"
    }
    If approving for the first time, subtract from user's annual balance.
    """
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

# 4. Get a Single Leave Request (GET)
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

# 5. Get Total Leave of an Employee in a Given Month (GET)
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

# 6. (Optional) Check Current Annual Balance
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
