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
    required_fields = ["project_name", "lead_id"]
    if not all(field in data for field in required_fields):
        return jsonify({"message": "Missing required fields: project_name and project_lead_id are required"}), 400

    # Get project lead id and verify it is an integer
    try:
        project_lead_id = int(data.get("lead_id"))
    except ValueError:
        return jsonify({"message": "Invalid project_lead_id"}), 400

    # Lookup the employee using project_lead_id
    project_lead_employee = Employee.query.get(project_lead_id)
    if not project_lead_employee:
        return jsonify({"message": f"Employee with id {project_lead_id} not found"}), 404

    
    team_members = data.get("team_members", [])
    if isinstance(team_members, list):
        team_members_str = json.dumps(team_members)
    else:
        team_members_str = json.dumps(team_members.split(','))


    new_project = Project(
        project_name=data["project_name"],
        description=data.get("description", ""),
        project_lead=data.get("project_lead", ""),
        lead_id=project_lead_employee
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
            "project_lead": r.project_lead,
            "start_date": r.start_date,
            "due_date": r.due_date,
            "team_members": r.team_members,
            "project_status": r.project_status
        })
    return jsonify(results), 200