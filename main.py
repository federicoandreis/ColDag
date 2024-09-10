from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, send_file
from flask_login import LoginManager, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from models import db, User, Project
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
    project = Project(user_id=current_user.id, name=data['name'], content=json.dumps(data['content']))
    db.session.add(project)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/get_projects')
@login_required
def get_projects():
    projects = Project.query.filter_by(user_id=current_user.id).all()
    return jsonify([{'id': p.id, 'name': p.name, 'content': json.loads(p.content)} for p in projects])

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

@app.route('/graph_statistics', methods=['POST'])
@login_required
def graph_statistics():
    data = request.json
    nodes = data.get('nodes', [])
    edges = data.get('edges', [])

    G = nx.DiGraph()
    for node in nodes:
        G.add_node(node['id'])
    for edge in edges:
        G.add_edge(edge['from'], edge['to'])

    stats = {
        'num_nodes': G.number_of_nodes(),
        'num_edges': G.number_of_edges(),
        'avg_degree': sum(dict(G.degree()).values()) / G.number_of_nodes() if G.number_of_nodes() > 0 else 0,
        'is_dag': nx.is_directed_acyclic_graph(G),
        'connected_components': nx.number_connected_components(G.to_undirected()),
        'strongly_connected_components': nx.number_strongly_connected_components(G),
    }

    if stats['is_dag']:
        longest_path = nx.dag_longest_path(G)
        stats['longest_path_length'] = len(longest_path) - 1
        stats['longest_path_nodes'] = [nodes[i]['label'] for i in longest_path]

        articulation_points = list(nx.articulation_points(G.to_undirected()))
        stats['critical_nodes'] = [nodes[i]['label'] for i in articulation_points]

        topo_sort = list(nx.topological_sort(G))
        stats['topological_order'] = [nodes[i]['label'] for i in topo_sort]

    stats['degree_centrality'] = nx.degree_centrality(G)
    stats['betweenness_centrality'] = nx.betweenness_centrality(G)
    stats['closeness_centrality'] = nx.closeness_centrality(G)

    stats['eccentricity'] = nx.eccentricity(G.to_undirected())
    stats['radius'] = nx.radius(G.to_undirected())
    stats['diameter'] = nx.diameter(G.to_undirected())
    stats['clustering_coefficient'] = nx.average_clustering(G.to_undirected())
    stats['pagerank'] = nx.pagerank(G)

    # Graph Coloring
    coloring = nx.greedy_color(G.to_undirected())
    stats['graph_coloring'] = {nodes[node_id]['label']: color for node_id, color in coloring.items()}
    stats['chromatic_number'] = max(coloring.values()) + 1

    # Minimum Spanning Tree (for undirected graphs)
    if not nx.is_directed(G):
        mst = list(nx.minimum_spanning_tree(G).edges())
        stats['minimum_spanning_tree'] = [f"{nodes[u]['label']} - {nodes[v]['label']}" for u, v in mst]

    # Shortest Path (Dijkstra's algorithm)
    if len(nodes) > 1:
        source = nodes[0]['id']
        target = nodes[-1]['id']
        try:
            shortest_path = nx.dijkstra_path(G, source, target)
            stats['shortest_path'] = [nodes[i]['label'] for i in shortest_path]
            stats['shortest_path_length'] = nx.dijkstra_path_length(G, source, target)
        except nx.NetworkXNoPath:
            stats['shortest_path'] = "No path exists between the first and last nodes"
            stats['shortest_path_length'] = float('inf')

    # Cycle detection
    try:
        cycle = nx.find_cycle(G)
        stats['has_cycle'] = True
        stats['cycle'] = [nodes[node]['label'] for node in cycle]
    except nx.NetworkXNoCycle:
        stats['has_cycle'] = False

    # Graph density
    stats['graph_density'] = nx.density(G)

    # Graph diameter explanation
    stats['diameter_explanation'] = "The diameter of a graph is the maximum eccentricity of any vertex in the graph. In other words, it is the greatest distance between any pair of vertices."

    # New advanced operations
    # Eigenvector centrality
    stats['eigenvector_centrality'] = nx.eigenvector_centrality(G)

    # Assortativity coefficient
    stats['assortativity_coefficient'] = nx.degree_assortativity_coefficient(G)

    # Graph planarity
    stats['is_planar'] = nx.check_planarity(G)[0]

    # Convert node IDs to labels in measures
    for measure in ['degree_centrality', 'betweenness_centrality', 'closeness_centrality', 'eccentricity', 'pagerank', 'eigenvector_centrality']:
        stats[measure] = {nodes[node_id]['label']: value for node_id, value in stats[measure].items()}

    return jsonify(stats)

@app.route('/get_node_suggestions')
@login_required
def get_node_suggestions():
    with open('node_suggestions.json', 'r') as f:
        suggestions = json.load(f)
    return jsonify(suggestions)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()
    app.run(host='0.0.0.0', port=5000)
