from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project, ProjectVersion
from config import Config
import os
import json
from io import BytesIO
import networkx as nx

app = Flask(__name__)
app.config.from_object(Config)

db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_default_user():
    username = 'fede'
    password = 'admin'
    if not User.query.filter_by(username=username).first():
        new_user = User(username=username, password=generate_password_hash(password), is_admin=True)
        db.session.add(new_user)
        db.session.commit()
        print(f"Default user '{username}' created.")
    else:
        print(f"Default user '{username}' already exists.")

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        is_admin = request.form.get('is_admin') == 'on'
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
        else:
            new_user = User(username=username, password=generate_password_hash(password), is_admin=is_admin)
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/save_project', methods=['POST'])
@login_required
def save_project():
    data = request.json
    project = Project.query.filter_by(user_id=current_user.id, name=data['name']).first()
    
    if project:
        # Update existing project
        project.content = json.dumps(data['content'])
        version_number = len(project.versions) + 1
    else:
        # Create new project
        project = Project(user_id=current_user.id, name=data['name'], content=json.dumps(data['content']))
        db.session.add(project)
        version_number = 1
    
    # Create new version
    new_version = ProjectVersion(project=project, version_number=version_number, content=json.dumps(data['content']))
    db.session.add(new_version)
    db.session.commit()
    
    return jsonify({'success': True, 'version': version_number})

@app.route('/get_projects')
@login_required
def get_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return jsonify([{'id': p.id, 'name': p.name, 'content': json.loads(p.content)} for p in projects])

@app.route('/get_project_versions/<int:project_id>')
@login_required
def get_project_versions(project_id):
    project = Project.query.get(project_id)
    if project and project.user_id == current_user.id:
        versions = ProjectVersion.query.filter_by(project_id=project_id).order_by(ProjectVersion.version_number.desc()).all()
        return jsonify([{'version': v.version_number, 'created_at': v.created_at.isoformat()} for v in versions])
    return jsonify({'error': 'Project not found'}), 404

@app.route('/load_project_version/<int:project_id>/<int:version_number>')
@login_required
def load_project_version(project_id, version_number):
    project = Project.query.get(project_id)
    if project and project.user_id == current_user.id:
        version = ProjectVersion.query.filter_by(project_id=project_id, version_number=version_number).first()
        if version:
            return jsonify({'content': json.loads(version.content)})
    return jsonify({'error': 'Version not found'}), 404

# ... (rest of the code remains the same)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(host='0.0.0.0', port=5000)
