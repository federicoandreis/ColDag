document.addEventListener('DOMContentLoaded', () => {
    const graphDiv = document.getElementById('graph');
    const saveProjectBtn = document.getElementById('save-project');
    const projectNameInput = document.getElementById('project-name');
    const projectsList = document.getElementById('projects-list');
    const nodeLabelInput = document.getElementById('node-label');
    const addNodeBtn = document.getElementById('add-node');
    const addEdgeBtn = document.getElementById('add-edge');
    const removeSelectedBtn = document.getElementById('remove-selected');
    const clearAllBtn = document.getElementById('clear-all');
    const instructionsBtn = document.getElementById('instructions');
    const instructionsModal = document.getElementById('instructions-modal');
    const closeModal = document.getElementsByClassName('close')[0];
    const exportJsonBtn = document.getElementById('export-json');
    const loadProjectBtn = document.getElementById('load-project');
    const loadProjectFile = document.getElementById('load-project-file');
    const showStatisticsBtn = document.getElementById('show-statistics');
    const statisticsModal = document.getElementById('statistics-modal');
    const closeStatisticsModal = statisticsModal.getElementsByClassName('close')[0];
    const statisticsList = document.getElementById('statistics-list');
    const suggestedNodesList = document.getElementById('suggested-nodes-list');

    let nodes = new vis.DataSet();
    let edges = new vis.DataSet();

    let network = new vis.Network(graphDiv, { nodes, edges }, {
        manipulation: {
            enabled: true,
            addEdge: function(edgeData, callback) {
                if (edgeData.from === edgeData.to) {
                    var r = confirm("Do you want to connect the node to itself?");
                    if (r === true) {
                        callback(edgeData);
                    }
                }
                else {
                    callback(edgeData);
                }
            }
        },
        edges: {
            arrows: {
                to: { enabled: true, scaleFactor: 1, type: 'arrow' }
            }
        }
    });

    function saveProject() {
        const name = projectNameInput.value;
        const content = {
            nodes: nodes.get().map(node => ({
                id: node.id,
                label: node.label,
                annotation: node.title
            })),
            edges: edges.get().map(edge => ({
                from: edge.from,
                to: edge.to
            }))
        };
        
        if (!name) {
            alert('Please provide a project name');
            return;
        }

        fetch('/save_project', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ name, content }),
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                alert('Project saved successfully');
                loadProjects();
            }
        })
        .catch(error => console.error('Error:', error));
    }

    function loadProjects() {
        fetch('/get_projects')
        .then(response => response.json())
        .then(projects => {
            projectsList.innerHTML = '<h2>Your Projects</h2>';
            const ul = document.createElement('ul');
            projects.forEach(project => {
                const li = document.createElement('li');
                li.textContent = project.name;
                li.addEventListener('click', () => {
                    const data = project.content;
                    nodes.clear();
                    edges.clear();
                    nodes.add(data.nodes.map(node => ({
                        id: node.id,
                        label: node.label,
                        title: node.annotation
                    })));
                    edges.add(data.edges);
                    projectNameInput.value = project.name;
                });
                ul.appendChild(li);
            });
            projectsList.appendChild(ul);
        })
        .catch(error => console.error('Error:', error));
    }

    function loadSuggestedNodes() {
        fetch('/get_node_suggestions')
        .then(response => response.json())
        .then(data => {
            suggestedNodesList.innerHTML = '';
            data.nodes.forEach(node => {
                const div = document.createElement('div');
                div.textContent = node.label;
                div.title = node.annotation;
                div.addEventListener('click', () => {
                    nodes.add({ label: node.label, title: node.annotation });
                });
                suggestedNodesList.appendChild(div);
            });
        })
        .catch(error => console.error('Error:', error));
    }

    saveProjectBtn.addEventListener('click', saveProject);

    addNodeBtn.addEventListener('click', () => {
        const label = nodeLabelInput.value || 'New Node';
        nodes.add({ label: label });
        nodeLabelInput.value = '';
    });

    addEdgeBtn.addEventListener('click', () => {
        network.addEdgeMode();
    });

    removeSelectedBtn.addEventListener('click', () => {
        const selectedNodes = network.getSelectedNodes();
        const selectedEdges = network.getSelectedEdges();
        nodes.remove(selectedNodes);
        edges.remove(selectedEdges);
    });

    clearAllBtn.addEventListener('click', () => {
        nodes.clear();
        edges.clear();
    });

    instructionsBtn.addEventListener('click', () => {
        instructionsModal.style.display = 'block';
    });

    closeModal.addEventListener('click', () => {
        instructionsModal.style.display = 'none';
    });

    window.addEventListener('click', (event) => {
        if (event.target == instructionsModal) {
            instructionsModal.style.display = 'none';
        }
        if (event.target == statisticsModal) {
            statisticsModal.style.display = 'none';
        }
    });

    exportJsonBtn.addEventListener('click', () => {
        const graphData = {
            nodes: nodes.get().map(node => ({
                id: node.id,
                label: node.label,
                annotation: node.title
            })),
            edges: edges.get().map(edge => ({
                from: edge.from,
                to: edge.to
            }))
        };

        fetch('/export_current_graph', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(graphData),
        })
        .then(response => response.blob())
        .then(blob => {
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.style.display = 'none';
            a.href = url;
            a.download = 'current_graph.json';
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
        })
        .catch(error => console.error('Error:', error));
    });

    loadProjectBtn.addEventListener('click', () => {
        const file = loadProjectFile.files[0];
        if (file) {
            const reader = new FileReader();
            reader.onload = function(e) {
                const content = e.target.result;
                fetch('/load_project_from_file', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ content: content }),
                })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        const graphData = JSON.parse(content);
                        nodes.clear();
                        edges.clear();
                        nodes.add(graphData.nodes.map(node => ({
                            id: node.id,
                            label: node.label,
                            title: node.annotation
                        })));
                        edges.add(graphData.edges);
                        alert('Project loaded successfully');
                    } else {
                        alert('Failed to load project');
                    }
                })
                .catch(error => console.error('Error:', error));
            };
            reader.readAsText(file);
        }
    });

    showStatisticsBtn.addEventListener('click', () => {
        const graphData = {
            nodes: nodes.get(),
            edges: edges.get()
        };

        fetch('/graph_statistics', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(graphData),
        })
        .then(response => response.json())
        .then(stats => {
            statisticsList.innerHTML = '';
            
            const categories = {
                'Basic Statistics': ['num_nodes', 'num_edges', 'avg_degree', 'is_dag', 'connected_components', 'strongly_connected_components', 'graph_density'],
                'Centrality Measures': ['degree_centrality', 'betweenness_centrality', 'closeness_centrality', 'eigenvector_centrality', 'pagerank'],
                'Path and Connectivity': ['longest_path_length', 'longest_path_nodes', 'critical_nodes', 'shortest_path', 'shortest_path_length'],
                'Graph Properties': ['eccentricity', 'radius', 'diameter', 'clustering_coefficient', 'assortativity_coefficient', 'is_planar'],
                'Graph Coloring': ['graph_coloring', 'chromatic_number'],
                'Other': ['topological_order', 'minimum_spanning_tree', 'has_cycle', 'cycle']
            };

            for (const [category, keys] of Object.entries(categories)) {
                const categoryDiv = document.createElement('div');
                categoryDiv.innerHTML = `<h3>${category}</h3>`;
                const ul = document.createElement('ul');

                keys.forEach(key => {
                    if (key in stats) {
                        const li = document.createElement('li');
                        const value = stats[key];
                        if (typeof value === 'object') {
                            li.textContent = `${key.replace(/_/g, ' ')}:`;
                            const subUl = document.createElement('ul');
                            for (const [subKey, subValue] of Object.entries(value)) {
                                const subLi = document.createElement('li');
                                if (typeof subValue === 'number') {
                                    subLi.textContent = `${subKey}: ${subValue.toFixed(4)}`;
                                } else {
                                    subLi.textContent = `${subKey}: ${subValue}`;
                                }
                                subUl.appendChild(subLi);
                            }
                            li.appendChild(subUl);
                        } else if (Array.isArray(value)) {
                            li.textContent = `${key.replace(/_/g, ' ')}: ${value.join(', ')}`;
                        } else if (typeof value === 'number') {
                            li.textContent = `${key.replace(/_/g, ' ')}: ${value.toFixed(4)}`;
                        } else {
                            li.textContent = `${key.replace(/_/g, ' ')}: ${value}`;
                        }
                        ul.appendChild(li);
                    }
                });

                categoryDiv.appendChild(ul);
                statisticsList.appendChild(categoryDiv);
            }

            if ('diameter_explanation' in stats) {
                const explanationDiv = document.createElement('div');
                explanationDiv.innerHTML = `<h3>Explanations</h3><p>${stats.diameter_explanation}</p>`;
                statisticsList.appendChild(explanationDiv);
            }

            statisticsModal.style.display = 'block';
        })
        .catch(error => console.error('Error:', error));
    });

    closeStatisticsModal.addEventListener('click', () => {
        statisticsModal.style.display = 'none';
    });

    // Right-click annotation functionality
    network.on("oncontext", function (params) {
        params.event.preventDefault();
        const nodeId = network.getNodeAt(params.pointer.DOM);
        if (nodeId) {
            const annotation = prompt('Enter annotation:');
            if (annotation) {
                const node = nodes.get(nodeId);
                node.title = annotation;
                nodes.update(node);
            }
        }
    });

    // Initial project and suggested nodes load
    loadProjects();
    loadSuggestedNodes();
});
