// Hobbyist Features Authentication Check
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

async function checkHobAuth() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            credentials: 'include'
        });

        if (!response.ok) {
            window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
            return;
        }

        const userData = await response.json();
        
        // Any authenticated user can access hobbyist features
        return userData;
    } catch (error) {
        console.error('Hob auth check failed:', error);
        window.location.href = '/login?redirect=' + encodeURIComponent(window.location.pathname);
    }
}

// Run auth check when page loads
document.addEventListener('DOMContentLoaded', checkHobAuth);

