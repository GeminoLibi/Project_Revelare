// Project Revelare - Main JavaScript

document.addEventListener('DOMContentLoaded', function() {
    console.log('🎨 Project Revelare theme system loading...');
    // Initialize all components
    initThemeSystem();
    initFileUploads();
    console.log('✅ Theme system initialized!');
    initFormValidation();
    initTooltips();
    initAnimations();
});

// Theme System
function initThemeSystem() {
    // Load saved theme or default to cyber-blue
    const savedTheme = localStorage.getItem('revelare-theme') || 'cyber-blue';
    setTheme(savedTheme);
}

function setTheme(themeName) {
    // Remove existing theme classes
    document.documentElement.removeAttribute('data-theme');
    
    // Set new theme
    if (themeName !== 'cyber-blue') {
        document.documentElement.setAttribute('data-theme', themeName);
    }
    
    // Update active button
    document.querySelectorAll('.theme-btn').forEach(btn => {
        btn.classList.remove('active');
    });
    document.querySelector(`[data-theme="${themeName}"]`).classList.add('active');
    
    // Save theme preference
    localStorage.setItem('revelare-theme', themeName);
    
    // Add theme change animation
    document.body.style.transition = 'all 0.3s ease';
    setTimeout(() => {
        document.body.style.transition = '';
    }, 300);
}

// Make setTheme globally available
window.setTheme = setTheme;

// Exit application function
function exitApp() {
    if (confirm('Are you sure you want to exit Project Revelare? This will shut down the server.')) {
        // Show loading message
        const originalText = event.target.innerHTML;
        if (event.target.tagName === 'BUTTON') {
            event.target.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Shutting down...';
            event.target.disabled = true;
        }
        
        // Send shutdown request to server
        fetch('/shutdown', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            }
        })
        .then(response => {
            if (response.ok) {
                // Server is shutting down
                document.body.innerHTML = `
                    <div style="display: flex; justify-content: center; align-items: center; height: 100vh; background: linear-gradient(135deg, #1E3A8A, #3B82F6); color: white; font-family: 'Inter', sans-serif;">
                        <div style="text-align: center;">
                            <i class="fas fa-power-off" style="font-size: 4rem; margin-bottom: 1rem; color: #10B981;"></i>
                            <h1>Project Revelare</h1>
                            <p>Server shutting down...</p>
                            <p style="opacity: 0.7; margin-top: 2rem;">You can now close this browser tab.</p>
                        </div>
                    </div>
                `;
            } else {
                throw new Error('Server shutdown failed');
            }
        })
        .catch(error => {
            console.error('Error shutting down server:', error);
            alert('Failed to shut down server. Please close this browser tab manually.');
            if (event.target.tagName === 'BUTTON') {
                event.target.innerHTML = originalText;
                event.target.disabled = false;
            }
        });
    }
}

// Make exitApp globally available
window.exitApp = exitApp;

// File Upload Functionality
function initFileUploads() {
    const fileUploadAreas = document.querySelectorAll('.file-upload-area');
    
    fileUploadAreas.forEach(area => {
        const fileInput = area.querySelector('input[type="file"]');
        const fileList = area.querySelector('.file-list, .file-info');
        
        if (!fileInput) return;
        
        // Drag and drop handlers
        area.addEventListener('dragover', function(e) {
            e.preventDefault();
            area.classList.add('dragover');
        });
        
        area.addEventListener('dragleave', function(e) {
            e.preventDefault();
            area.classList.remove('dragover');
        });
        
        area.addEventListener('drop', function(e) {
            e.preventDefault();
            area.classList.remove('dragover');
            fileInput.files = e.dataTransfer.files;
            updateFileDisplay(fileInput, fileList);
        });
        
        // Click to upload
        area.addEventListener('click', function() {
            fileInput.click();
        });
        
        // File input change
        fileInput.addEventListener('change', function() {
            updateFileDisplay(fileInput, fileList);
        });
    });
}

// Update file display
function updateFileDisplay(fileInput, container) {
    if (!container) return;
    
    const files = Array.from(fileInput.files);
    
    if (files.length === 0) {
        container.innerHTML = '';
        return;
    }
    
    if (container.classList.contains('file-info')) {
        // Single file display
        const file = files[0];
        container.innerHTML = `
            <div class="file-details">
                <i class="fas fa-file"></i>
                <div class="file-details-content">
                    <div class="file-name">${file.name}</div>
                    <div class="file-size">${formatFileSize(file.size)}</div>
                </div>
            </div>
        `;
    } else {
        // Multiple files display
        container.innerHTML = '';
        files.forEach(file => {
            const fileItem = document.createElement('div');
            fileItem.className = 'file-item';
            fileItem.innerHTML = `
                <i class="fas fa-file"></i>
                <span>${file.name}</span>
                <span class="file-size">(${formatFileSize(file.size)})</span>
            `;
            container.appendChild(fileItem);
        });
    }
}

// Format file size
function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// Form Validation
function initFormValidation() {
    const forms = document.querySelectorAll('form');
    
    forms.forEach(form => {
        form.addEventListener('submit', function(e) {
            if (!validateForm(form)) {
                e.preventDefault();
            } else {
                showLoadingState(form);
            }
        });
    });
}

// Validate form
function validateForm(form) {
    let isValid = true;
    const requiredFields = form.querySelectorAll('[required]');
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            showFieldError(field, 'This field is required');
            isValid = false;
        } else {
            clearFieldError(field);
        }
    });
    
    // Validate project name format
    const projectNameField = form.querySelector('input[name="project_name"]');
    if (projectNameField && projectNameField.value) {
        const projectName = projectNameField.value.trim();
        const projectNameRegex = /^[a-zA-Z0-9_-]+$/;
        if (!projectNameRegex.test(projectName)) {
            showFieldError(projectNameField, 'Project name can only contain letters, numbers, underscores, and hyphens');
            isValid = false;
        }
    }
    
    // Validate file uploads
    const fileInputs = form.querySelectorAll('input[type="file"]');
    fileInputs.forEach(input => {
        if (input.hasAttribute('required') && input.files.length === 0) {
            showFieldError(input, 'Please select at least one file');
            isValid = false;
        }
    });
    
    return isValid;
}

// Show field error
function showFieldError(field, message) {
    clearFieldError(field);
    
    const errorDiv = document.createElement('div');
    errorDiv.className = 'field-error';
    errorDiv.textContent = message;
    errorDiv.style.color = '#dc3545';
    errorDiv.style.fontSize = '0.875rem';
    errorDiv.style.marginTop = '0.25rem';
    
    field.parentNode.appendChild(errorDiv);
    field.style.borderColor = '#dc3545';
}

// Clear field error
function clearFieldError(field) {
    const existingError = field.parentNode.querySelector('.field-error');
    if (existingError) {
        existingError.remove();
    }
    field.style.borderColor = '';
}

// Show loading state
function showLoadingState(form) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Processing...';
        submitBtn.disabled = true;
        
        // Re-enable after timeout (in case of errors)
        setTimeout(() => {
            submitBtn.innerHTML = originalText;
            submitBtn.disabled = false;
        }, 30000);
    }
}

// Initialize tooltips
function initTooltips() {
    const tooltipElements = document.querySelectorAll('[data-tooltip]');
    
    tooltipElements.forEach(element => {
        element.addEventListener('mouseenter', showTooltip);
        element.addEventListener('mouseleave', hideTooltip);
    });
}

// Show tooltip
function showTooltip(e) {
    const text = e.target.getAttribute('data-tooltip');
    if (!text) return;
    
    const tooltip = document.createElement('div');
    tooltip.className = 'tooltip';
    tooltip.textContent = text;
    tooltip.style.cssText = `
        position: absolute;
        background: #333;
        color: white;
        padding: 0.5rem;
        border-radius: 4px;
        font-size: 0.875rem;
        z-index: 1000;
        pointer-events: none;
        white-space: nowrap;
    `;
    
    document.body.appendChild(tooltip);
    
    const rect = e.target.getBoundingClientRect();
    tooltip.style.left = rect.left + (rect.width / 2) - (tooltip.offsetWidth / 2) + 'px';
    tooltip.style.top = rect.top - tooltip.offsetHeight - 5 + 'px';
    
    e.target._tooltip = tooltip;
}

// Hide tooltip
function hideTooltip(e) {
    if (e.target._tooltip) {
        e.target._tooltip.remove();
        delete e.target._tooltip;
    }
}

// Initialize animations
function initAnimations() {
    // Fade in elements on scroll
    const observerOptions = {
        threshold: 0.1,
        rootMargin: '0px 0px -50px 0px'
    };
    
    const observer = new IntersectionObserver(function(entries) {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                entry.target.style.opacity = '1';
                entry.target.style.transform = 'translateY(0)';
            }
        });
    }, observerOptions);
    
    const animatedElements = document.querySelectorAll('.feature-card, .project-card, .help-step');
    animatedElements.forEach(el => {
        el.style.opacity = '0';
        el.style.transform = 'translateY(20px)';
        el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
        observer.observe(el);
    });
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-triangle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${type === 'success' ? '#28a745' : type === 'error' ? '#dc3545' : '#17a2b8'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 4px;
        box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        z-index: 1000;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        animation: slideIn 0.3s ease;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => notification.remove(), 300);
    }, 5000);
}

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(100%); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Export functions for global use
window.RevelareUI = {
    showNotification,
    formatFileSize,
    validateForm
};
