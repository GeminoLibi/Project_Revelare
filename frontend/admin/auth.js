// Admin Authentication Check
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function checkAdminAuth() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            credentials: 'include'
        });

        if (!response.ok) {
            window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
            return;
        }

        const userData = await response.json();
        
        if (!userData.isAdmin) {
            alert('Access denied. Admin privileges required.');
            window.location.href = '/user-dashboard.html';
            return;
        }

        // User is authenticated and is admin
        return userData;
    } catch (error) {
        console.error('Admin auth check failed:', error);
        window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
    }
}

// Run auth check when page loads
document.addEventListener('DOMContentLoaded', checkAdminAuth);

