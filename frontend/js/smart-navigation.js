// Smart Navigation Loader - Loads navigation based on user's highest tier
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function loadSmartNavigation() {
    const token = localStorage.getItem('authToken');
    
    if (!token) {
        // Not logged in - load public navigation
        await loadNavigationComponent('/components/navigation-public.html');
        return;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!response.ok) {
            // Auth failed - load public navigation
            localStorage.removeItem('authToken');
            await loadNavigationComponent('/components/navigation-public.html');
            return;
        }

        const userData = await response.json();
        
        // Determine navigation based on user's highest tier
        if (userData.isAdmin) {
            await loadNavigationComponent('/components/navigation-admin.html');
        } else if (userData.accessTier === 'enterprise') {
            await loadNavigationComponent('/components/navigation-enterprise.html');
        } else if (userData.accessTier === 'professional') {
            await loadNavigationComponent('/components/navigation-professional.html');
        } else {
            // Hobbyist or any other authenticated user
            await loadNavigationComponent('/components/navigation-hobbyist.html');
        }
        
    } catch (error) {
        console.error('Failed to load user data:', error);
        // Fallback to public navigation
        await loadNavigationComponent('/components/navigation-public.html');
    }
}

async function loadNavigationComponent(path) {
    try {
        const response = await fetch(path);
        const html = await response.text();
        const container = document.getElementById('navigation-container');
        if (container) {
            container.innerHTML = html;
        }
    } catch (error) {
        console.error('Failed to load navigation component:', error);
    }
}

// Initialize smart navigation when DOM loads
document.addEventListener('DOMContentLoaded', loadSmartNavigation);

