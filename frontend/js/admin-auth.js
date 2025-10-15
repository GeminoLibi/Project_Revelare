// Admin Authentication Script - Ensures only admins can access admin pages
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function checkAdminAccess() {
    // Wait a bit for navigation to load first
    await new Promise(resolve => setTimeout(resolve, 500));
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            credentials: 'include' // This ensures cookies are sent
        });

        if (!response.ok) {
            console.log('Auth check failed, status:', response.status);
            window.location.href = '/login.html';
            return;
        }

        const userData = await response.json();
        
        // Check if user is admin
        if (!userData.isAdmin) {
            // Redirect non-admin users to their appropriate dashboard
            if (userData.accessTier === 'enterprise') {
                window.location.href = '/hob/dashboard.html';
            } else if (userData.accessTier === 'professional') {
                window.location.href = '/hob/dashboard.html';
            } else {
                window.location.href = '/hob/dashboard.html';
            }
            return;
        }
        
        // Admin access confirmed - continue loading page
        console.log('Admin access confirmed for:', userData.firstName, userData.lastName);
        
    } catch (error) {
        console.error('Admin auth check failed:', error);
        window.location.href = '/login.html';
    }
}

// Run check when page loads
document.addEventListener('DOMContentLoaded', function() {
    checkAdminAccess();
});
