from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project
from config import Config
import os
import json
from io import BytesIO

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
    project = Project(user_id=current_user.id, name=data['name'], content=data['content'])
    db.session.add(project)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/get_projects')
@login_required
def get_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return jsonify([{'id': p.id, 'name': p.name, 'content': p.content} for p in projects])

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    projects = Project.query.all()
    return render_template('admin.html', projects=projects)

@app.route('/export_current_graph', methods=['POST'])
@login_required
def export_current_graph():
    data = request.json
    json_data = json.dumps(data, indent=2)
    return send_file(
        BytesIO(json_data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name='current_graph.json'
    )

@app.route('/export_all_graphs')
@login_required
def export_all_graphs():
    if not current_user.is_admin:
        flash('Access denied')
        return redirect(url_for('index'))
    
    projects = Project.query.all()
    all_graphs = {p.name: json.loads(p.content) for p in projects}
    json_data = json.dumps(all_graphs, indent=2)
    
    return send_file(
        BytesIO(json_data.encode()),
        mimetype='application/json',
        as_attachment=True,
        download_name='all_graphs.json'
    )

@app.route('/load_project_from_file', methods=['POST'])
@login_required
def load_project_from_file():
    data = request.json
    content = data.get('content')
    try:
        json.loads(content)  # Validate JSON
        return jsonify({'success': True})
    except json.JSONDecodeError:
        return jsonify({'success': False, 'error': 'Invalid JSON format'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(host='0.0.0.0', port=5000)
