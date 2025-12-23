class DataTableManager {
    constructor(options) {
        this.endpoint = options.endpoint;
        this.dataKey = options.dataKey;
        this.tableContentId = options.tableContentId;
        this.tableStatsId = options.tableStatsId;
        this.filterStatsId = options.filterStatsId;
        this.filterIds = options.filterIds || {};
        this.columns = options.columns || [];
        this.filterFunction = options.filterFunction || ((item) => true);
        this.renderRow = options.renderRow || null;
        this.data = [];
        this.filtered = [];
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.pageSize = options.pageSize || 50;
        this.currentPage = 1;
        this.paginationId = options.paginationId || null;
    }

    async init() {
        await this.load();
        this.populateFilterOptions();
        this.bindFilters();
        this.render();
    }

    async load() {
        try {
            const res = await fetch(this.endpoint, { headers: { 'Accept': 'application/json' } });
            const json = await res.json();
            this.data = this.dataKey ? (json[this.dataKey] || []) : (json || []);
            this.filtered = this.data.slice();
        } catch (e) {
            this.data = [];
            this.filtered = [];
        }
    }

    bindFilters() {
        Object.entries(this.filterIds).forEach(([key, id]) => {
            const el = document.getElementById(id);
            if (el) {
                el.addEventListener('input', () => this.applyFilters());
                el.addEventListener('change', () => this.applyFilters());
            }
        });
    }

    getFilters() {
        const filters = {};
        Object.entries(this.filterIds).forEach(([key, id]) => {
            const el = document.getElementById(id);
            filters[key] = el ? (el.value || '').toString() : '';
        });
        return filters;
    }

    applyFilters() {
        const filters = this.getFilters();
        this.filtered = this.data.filter(item => this.filterFunction(item, filters));
        this.currentPage = 1; // Reset to first page on filter
        // Reapply sorting if a sort column is set
        if (this.sortColumn) {
            this.sort(this.sortColumn, false); // false = don't toggle, just reapply
        } else {
            this.render();
        }
    }
    
    populateFilterOptions() {
        // Populate category filter
        if (this.filterIds.category) {
            const categoryEl = document.getElementById(this.filterIds.category);
            if (categoryEl) {
                const categories = [...new Set(this.data.map(item => item.category).filter(c => c))].sort();
                categories.forEach(cat => {
                    const option = document.createElement('option');
                    option.value = cat;
                    option.textContent = cat.replace(/_/g, ' ');
                    categoryEl.appendChild(option);
                });
            }
        }
        
        // Populate file filter
        if (this.filterIds.file) {
            const fileEl = document.getElementById(this.filterIds.file);
            if (fileEl) {
                const files = [...new Set(this.data.map(item => item.file).filter(f => f))].sort();
                files.forEach(file => {
                    const option = document.createElement('option');
                    option.value = file;
                    option.textContent = file;
                    fileEl.appendChild(option);
                });
            }
        }
        
        // Populate type filter (for files page)
        if (this.filterIds.type) {
            const typeEl = document.getElementById(this.filterIds.type);
            if (typeEl) {
                const types = [...new Set(this.data.map(item => item.type).filter(t => t))].sort();
                types.forEach(type => {
                    const option = document.createElement('option');
                    option.value = type;
                    option.textContent = type || 'unknown';
                    typeEl.appendChild(option);
                });
            }
        }
        
        // Populate country filter (for geographic page)
        if (this.filterIds.country) {
            const countryEl = document.getElementById(this.filterIds.country);
            if (countryEl) {
                const countries = [...new Set(this.data.map(item => item.country).filter(c => c))].sort();
                countries.forEach(country => {
                    const option = document.createElement('option');
                    option.value = country;
                    option.textContent = country;
                    countryEl.appendChild(option);
                });
            }
        }
        
        // Populate component filter (for technical page)
        if (this.filterIds.component) {
            const componentEl = document.getElementById(this.filterIds.component);
            if (componentEl) {
                const components = [...new Set(this.data.map(item => item.component).filter(c => c))].sort();
                components.forEach(component => {
                    const option = document.createElement('option');
                    option.value = component;
                    option.textContent = component;
                    componentEl.appendChild(option);
                });
            }
        }
    }

    render() {
        const container = document.getElementById(this.tableContentId);
        const stats = document.getElementById(this.tableStatsId);
        const filterStats = document.getElementById(this.filterStatsId);
        if (!container) return;

        // Calculate pagination
        const totalPages = Math.ceil(this.filtered.length / this.pageSize);
        const startIdx = (this.currentPage - 1) * this.pageSize;
        const endIdx = Math.min(startIdx + this.pageSize, this.filtered.length);
        const pageData = this.filtered.slice(startIdx, endIdx);

        const rowsHtml = (this.renderRow
            ? pageData.map(item => this.renderRow(item)).join('')
            : pageData.map(item => {
                const tds = this.columns.map(col => `<td>${this.escapeHtml(item[col.key] ?? '')}</td>`).join('');
                return `<tr>${tds}</tr>`;
            }).join(''));

        const thead = this.columns.map(col => {
            const sortIcon = this.sortColumn === col.key 
                ? (this.sortDirection === 'asc' ? ' ↑' : ' ↓') 
                : '';
            return `<th class="sortable" data-column="${col.key}">${this.escapeHtml(col.label)}${sortIcon}</th>`;
        }).join('');
        
        const tableHtml = `
            <div class="table-wrapper">
                <table class="data-table table">
                    <thead><tr>${thead}</tr></thead>
                    <tbody>${rowsHtml || '<tr><td colspan="' + this.columns.length + '" class="empty-state">No data matches your filters</td></tr>'}</tbody>
                </table>
            </div>
        `;
        container.innerHTML = tableHtml;

        // Bind sort events
        container.querySelectorAll('.sortable').forEach(th => {
            th.style.cursor = 'pointer';
            th.title = 'Click to sort';
            th.addEventListener('click', () => {
                this.currentPage = 1; // Reset to first page on sort
                this.sort(th.dataset.column);
            });
        });

        // Render pagination
        if (this.paginationId) {
            this.renderPagination(totalPages);
        }

        if (stats) {
            const showing = this.filtered.length > 0 ? `${startIdx + 1}-${endIdx}` : '0';
            stats.textContent = `Showing ${showing} of ${this.filtered.length} (${this.data.length} total)`;
        }
        if (filterStats) {
            filterStats.textContent = this.buildFilterSummary();
        }
    }

    renderPagination(totalPages) {
        const paginationEl = document.getElementById(this.paginationId);
        if (!paginationEl || totalPages <= 1) {
            if (paginationEl) paginationEl.innerHTML = '';
            return;
        }

        let paginationHtml = '<div class="pagination">';
        
        // Previous button
        paginationHtml += `<button class="page-btn" ${this.currentPage === 1 ? 'disabled' : ''} onclick="manager.goToPage(${this.currentPage - 1})">‹ Prev</button>`;
        
        // Page numbers
        const maxVisible = 7;
        let startPage = Math.max(1, this.currentPage - Math.floor(maxVisible / 2));
        let endPage = Math.min(totalPages, startPage + maxVisible - 1);
        
        if (endPage - startPage < maxVisible - 1) {
            startPage = Math.max(1, endPage - maxVisible + 1);
        }
        
        if (startPage > 1) {
            paginationHtml += `<button class="page-btn" onclick="manager.goToPage(1)">1</button>`;
            if (startPage > 2) paginationHtml += `<span class="page-ellipsis">...</span>`;
        }
        
        for (let i = startPage; i <= endPage; i++) {
            paginationHtml += `<button class="page-btn ${i === this.currentPage ? 'active' : ''}" onclick="manager.goToPage(${i})">${i}</button>`;
        }
        
        if (endPage < totalPages) {
            if (endPage < totalPages - 1) paginationHtml += `<span class="page-ellipsis">...</span>`;
            paginationHtml += `<button class="page-btn" onclick="manager.goToPage(${totalPages})">${totalPages}</button>`;
        }
        
        // Next button
        paginationHtml += `<button class="page-btn" ${this.currentPage === totalPages ? 'disabled' : ''} onclick="manager.goToPage(${this.currentPage + 1})">Next ›</button>`;
        
        paginationHtml += '</div>';
        paginationEl.innerHTML = paginationHtml;
    }

    goToPage(page) {
        const totalPages = Math.ceil(this.filtered.length / this.pageSize);
        if (page >= 1 && page <= totalPages) {
            this.currentPage = page;
            this.render();
            // Scroll to top of table
            const container = document.getElementById(this.tableContentId);
            if (container) container.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    buildFilterSummary() {
        const filters = this.getFilters();
        const parts = Object.entries(filters)
            .filter(([k, v]) => v && v.length > 0)
            .map(([k, v]) => `${k}: ${v}`);
        return parts.length ? `Filters - ${parts.join(' | ')}` : '';
    }

    clearFilters() {
        Object.values(this.filterIds).forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        this.sortColumn = null;
        this.sortDirection = 'asc';
        this.applyFilters();
    }

    sort(column, toggle = true) {
        if (toggle) {
            if (this.sortColumn === column) {
                this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
            } else {
                this.sortColumn = column;
                this.sortDirection = 'asc';
            }
        }
        
        this.filtered.sort((a, b) => {
            let aVal = a[column];
            let bVal = b[column];
            
            // Handle null/undefined values
            if (aVal == null) aVal = '';
            if (bVal == null) bVal = '';
            
            // Try to parse as numbers
            const aNum = parseFloat(aVal);
            const bNum = parseFloat(bVal);
            
            if (!isNaN(aNum) && !isNaN(bNum)) {
                return this.sortDirection === 'asc' ? aNum - bNum : bNum - aNum;
            }
            
            // String comparison
            const aStr = String(aVal).toLowerCase();
            const bStr = String(bVal).toLowerCase();
            
            if (this.sortDirection === 'asc') {
                return aStr < bStr ? -1 : aStr > bStr ? 1 : 0;
            } else {
                return aStr > bStr ? -1 : aStr < bStr ? 1 : 0;
            }
        });
        
        this.render();
    }

    escapeHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }
}

window.DataTableManager = DataTableManager;


