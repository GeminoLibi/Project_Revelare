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
    }

    async init() {
        await this.load();
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
        this.render();
    }

    render() {
        const container = document.getElementById(this.tableContentId);
        const stats = document.getElementById(this.tableStatsId);
        const filterStats = document.getElementById(this.filterStatsId);
        if (!container) return;

        const rowsHtml = (this.renderRow
            ? this.filtered.map(item => this.renderRow(item)).join('')
            : this.filtered.map(item => {
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
            <table class="data-table">
                <thead><tr>${thead}</tr></thead>
                <tbody>${rowsHtml}</tbody>
            </table>
        `;
        container.innerHTML = tableHtml;

        // Bind sort events
        container.querySelectorAll('.sortable').forEach(th => {
            th.addEventListener('click', () => this.sort(th.dataset.column));
        });

        if (stats) {
            stats.textContent = `${this.filtered.length} of ${this.data.length} rows`;
        }
        if (filterStats) {
            filterStats.textContent = this.buildFilterSummary();
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
        this.applyFilters();
    }

    sort(column) {
        if (this.sortColumn === column) {
            this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
            this.sortColumn = column;
            this.sortDirection = 'asc';
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


