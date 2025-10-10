// Project Revelare - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    initThemeSystem();
});

// --- Theme System ---
function initThemeSystem() {
    const savedTheme = localStorage.getItem('revelare-theme') || 'cyber-blue';
    setTheme(savedTheme);
}

function setTheme(theme) {
    document.body.setAttribute('data-theme', theme);
    localStorage.setItem('revelare-theme', theme);
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.remove('active');
        if (btn.getAttribute('data-theme') === theme) {
            btn.classList.add('active');
        }
    });
}

// --- File Tree Manager ---
class FileTreeManager {
    constructor(containerId, searchInputId, expandBtnId, collapseBtnId) {
        this.container = document.getElementById(containerId);
        if (!this.container) return;
        
        this.searchInput = document.getElementById(searchInputId);
        this.expandBtn = document.getElementById(expandBtnId);
        this.collapseBtn = document.getElementById(collapseBtnId);
        this.searchTimeout = null;

        this.init();
    }

    init() {
        this.container.addEventListener('click', (e) => {
            const header = e.target.closest('.tree-node-header');
            if (header) {
                this.toggleNode(header);
            }
        });

        this.expandBtn.addEventListener('click', () => this.expandAll());
        this.collapseBtn.addEventListener('click', () => this.collapseAll());

        this.searchInput.addEventListener('input', () => {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = setTimeout(() => this.searchFiles(), 300);
        });
    }

    toggleNode(header) {
        const node = header.parentElement;
        const children = node.querySelector('.tree-children');
        if (children) {
            node.classList.toggle('expanded');
            children.style.display = node.classList.contains('expanded') ? 'block' : 'none';
        }
    }

    expandAll() {
        this.container.querySelectorAll('.tree-node').forEach(node => {
            const children = node.querySelector('.tree-children');
            if (children) {
                node.classList.add('expanded');
                children.style.display = 'block';
            }
        });
    }

    collapseAll() {
        this.container.querySelectorAll('.tree-node.expanded').forEach(node => {
            node.classList.remove('expanded');
            const children = node.querySelector('.tree-children');
            if(children) {
                children.style.display = 'none';
            }
        });
    }

    searchFiles() {
        const searchTerm = this.searchInput.value.toLowerCase();
        this.container.querySelectorAll('.tree-node').forEach(node => {
            const nodeNameEl = node.querySelector('.tree-name');
            const nodeName = nodeNameEl.textContent.toLowerCase();
            const isMatch = searchTerm === '' || nodeName.includes(searchTerm);

            node.style.display = isMatch ? '' : 'none';

            // Highlight match
            const originalText = nodeNameEl.dataset.originalText || nodeNameEl.textContent;
            nodeNameEl.dataset.originalText = originalText;

            if (isMatch && searchTerm !== '') {
                const regex = new RegExp(`(${searchTerm})`, 'gi');
                nodeNameEl.innerHTML = originalText.replace(regex, '<span class="search-match">$1</span>');
            } else {
                nodeNameEl.innerHTML = originalText;
            }

            if (isMatch && searchTerm !== '') {
                this.showNodeAndParents(node);
            }
        });
    }
    
    showNodeAndParents(node) {
        let parent = node.parentElement;
        while (parent && parent.classList.contains('tree-children')) {
            parent.style.display = 'block';
            const parentNode = parent.parentElement;
            if (parentNode) {
                parentNode.style.display = '';
                parentNode.classList.add('expanded');
                parent = parentNode.parentElement;
            } else {
                break;
            }
        }
    }
}

// --- Exit Application ---
function exitApp() {
    if (confirm('Are you sure you want to exit Project Revelare?')) {
        fetch('/shutdown', { method: 'POST' })
            .then(() => {
                document.body.innerHTML = "<h1>Shutting down... You can close this window.</h1>";
                setTimeout(() => window.close(), 1000);
            })
            .catch(() => {
                // Fallback for browsers that don't allow window.close()
                window.location.href = 'about:blank';
            });
    }
}

// Export functions for global use
window.setTheme = setTheme;
window.exitApp = exitApp;
window.FileTreeManager = FileTreeManager;