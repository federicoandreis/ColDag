document.addEventListener('DOMContentLoaded', () => {
    // ... (existing code)

    const versionHistoryBtn = document.getElementById('version-history');
    const versionHistoryModal = document.getElementById('version-history-modal');
    const closeVersionHistoryModal = versionHistoryModal.getElementsByClassName('close')[0];
    const versionList = document.getElementById('version-list');

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
                alert(`Project saved successfully (Version ${data.version})`);
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
                    loadProject(project);
                });
                ul.appendChild(li);
            });
            projectsList.appendChild(ul);
        })
        .catch(error => console.error('Error:', error));
    }

    function loadProject(project) {
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
    }

    function showVersionHistory() {
        const projectName = projectNameInput.value;
        if (!projectName) {
            alert('Please select a project first');
            return;
        }

        fetch(`/get_project_versions/${projectName}`)
        .then(response => response.json())
        .then(versions => {
            versionList.innerHTML = '';
            versions.forEach(version => {
                const li = document.createElement('li');
                li.textContent = `Version ${version.version} (${new Date(version.created_at).toLocaleString()})`;
                li.addEventListener('click', () => loadProjectVersion(projectName, version.version));
                versionList.appendChild(li);
            });
            versionHistoryModal.style.display = 'block';
        })
        .catch(error => console.error('Error:', error));
    }

    function loadProjectVersion(projectName, versionNumber) {
        fetch(`/load_project_version/${projectName}/${versionNumber}`)
        .then(response => response.json())
        .then(data => {
            if (data.content) {
                nodes.clear();
                edges.clear();
                nodes.add(data.content.nodes.map(node => ({
                    id: node.id,
                    label: node.label,
                    title: node.annotation
                })));
                edges.add(data.content.edges);
                versionHistoryModal.style.display = 'none';
                alert(`Loaded version ${versionNumber}`);
            }
        })
        .catch(error => console.error('Error:', error));
    }

    saveProjectBtn.addEventListener('click', saveProject);
    versionHistoryBtn.addEventListener('click', showVersionHistory);
    closeVersionHistoryModal.addEventListener('click', () => {
        versionHistoryModal.style.display = 'none';
    });

    window.addEventListener('click', (event) => {
        if (event.target == versionHistoryModal) {
            versionHistoryModal.style.display = 'none';
        }
    });

    // ... (rest of the existing code)

    // Initial project and suggested nodes load
    loadProjects();
    loadSuggestedNodes();
});
