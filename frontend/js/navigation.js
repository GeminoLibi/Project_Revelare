// Simple Navigation JavaScript
const API_BASE_URL = 'https://project-revelare-backend.liberatorgeminorum.workers.dev';

let isLoggedIn = false;
let userData = null;

// Mobile menu toggle
function toggleMobileMenu() {
    const mobileMenu = document.getElementById('mobileMenu');
    mobileMenu.classList.toggle('hidden');
}

// Logout function
async function logout() {
    try {
        await fetch(`${API_BASE_URL}/api/logout`, { method: 'POST' });
        localStorage.removeItem('authToken');
        window.location.href = '/index.html';
    } catch (error) {
        console.error('Logout error:', error);
        localStorage.removeItem('authToken');
        window.location.href = '/index.html';
    }
}

// Check authentication
async function checkAuth() {
    const token = localStorage.getItem('authToken');
    if (!token) {
        isLoggedIn = false;
        userData = null;
        return false;
    }

    try {
        const response = await fetch(`${API_BASE_URL}/api/me`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (response.ok) {
            userData = await response.json();
            isLoggedIn = true;
            return true;
        } else {
            localStorage.removeItem('authToken');
            isLoggedIn = false;
            userData = null;
            return false;
        }
    } catch (error) {
        console.error('Auth check error:', error);
        localStorage.removeItem('authToken');
        isLoggedIn = false;
        userData = null;
        return false;
    }
}

// Update navigation
function updateNavigation() {
    const mainNav = document.getElementById('mainNav');
    const userSection = document.getElementById('userSection');
    const mobileNavContent = document.getElementById('mobileNavContent');
    
    if (!mainNav || !userSection || !mobileNavContent) return;

    if (isLoggedIn && userData) {
        // Logged in navigation
        mainNav.innerHTML = `
            <a href="/hob/dashboard.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Dashboard</a>
            <a href="/pub/cybersecurity-news.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">News</a>
            <a href="/hob/forum.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Forum</a>
            <a href="/pub/gumshoe/shared/gumshoe-terminal.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Gumshoe</a>
            ${userData.isAdmin ? '<a href="/admin/dashboard.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Admin</a>' : ''}
        `;
        
        userSection.innerHTML = `
            <span class="text-gray-300 text-sm">${userData.firstName} ${userData.lastName}</span>
            <button onclick="logout()" class="bg-gray-700 hover:bg-gray-600 text-white px-3 py-2 rounded-md text-sm font-medium">Logout</button>
        `;
        
        mobileNavContent.innerHTML = `
            <a href="/hob/dashboard.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Dashboard</a>
            <a href="/pub/cybersecurity-news.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">News</a>
            <a href="/hob/forum.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Forum</a>
            <a href="/pub/gumshoe/shared/gumshoe-terminal.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Gumshoe</a>
            ${userData.isAdmin ? '<a href="/admin/dashboard.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Admin</a>' : ''}
            <button onclick="logout()" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Logout</button>
        `;
    } else {
        // Not logged in navigation
        mainNav.innerHTML = `
            <a href="/index.html#features" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Features</a>
            <a href="/index.html#gumshoe" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Gumshoe</a>
            <a href="/index.html#pricing" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Pricing</a>
            <a href="/pub/free-resources.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Resources</a>
            <a href="/pub/cybersecurity-news.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">News</a>
        `;
        
        userSection.innerHTML = `
            <a href="/login.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Login</a>
            <a href="/register.html" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium">Register</a>
        `;
        
        mobileNavContent.innerHTML = `
            <a href="/index.html#features" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Features</a>
            <a href="/index.html#gumshoe" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Gumshoe</a>
            <a href="/index.html#pricing" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Pricing</a>
            <a href="/pub/free-resources.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Resources</a>
            <a href="/pub/cybersecurity-news.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">News</a>
            <a href="/login.html" class="text-gray-300 hover:text-white px-3 py-2 rounded-md text-sm font-medium">Login</a>
            <a href="/register.html" class="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-md text-sm font-medium">Register</a>
        `;
    }
}

// Initialize navigation
async function initNavigation() {
    await checkAuth();
    updateNavigation();
    
    // Set current page in breadcrumb
    const currentPage = document.getElementById('currentPage');
    if (currentPage) {
        const pageTitle = document.title.split(' - ')[0];
        currentPage.textContent = pageTitle;
    }
    
    // Add mobile menu event listener
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    if (mobileMenuBtn) {
        mobileMenuBtn.addEventListener('click', toggleMobileMenu);
    }
}

// Global function to check if user is logged in
function isUserLoggedIn() {
    return isLoggedIn;
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initNavigation);
