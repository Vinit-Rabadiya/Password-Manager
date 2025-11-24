// UI State Management
let keychainActive = false;

// Check keychain status on load
window.addEventListener('load', async () => {
    const status = await fetchAPI('/api/status');
    if (status.active) {
        showManagerSection();
    }
});

// API Helper
async function fetchAPI(url, options = {}) {
    try {
        const response = await fetch(url, {
            ...options,
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            }
        });
        const data = await response.json();
        if (!response.ok) {
            throw new Error(data.error || 'Request failed');
        }
        return data;
    } catch (error) {
        showMessage(error.message, 'error');
        throw error;
    }
}

// Show/Hide Functions
function showInitForm() {
    hideSetupForms();
    document.getElementById('init-form').classList.remove('hidden');
}

function showLoadForm() {
    hideSetupForms();
    document.getElementById('load-form').classList.remove('hidden');
}

function hideSetupForms() {
    document.getElementById('init-form').classList.add('hidden');
    document.getElementById('load-form').classList.add('hidden');
}

function showManagerSection() {
    document.getElementById('setup-section').classList.add('hidden');
    document.getElementById('manager-section').classList.remove('hidden');
    keychainActive = true;
}

function showMessage(message, type = 'success') {
    const messageEl = document.getElementById('message');
    messageEl.textContent = message;
    messageEl.className = `message ${type} show`;
    setTimeout(() => {
        messageEl.classList.remove('show');
    }, 3000);
}

// Keychain Operations
async function initKeychain() {
    const password = document.getElementById('init-password').value;
    if (!password) {
        showMessage('Please enter a master password', 'error');
        return;
    }
    
    try {
        const result = await fetchAPI('/api/init', {
            method: 'POST',
            body: JSON.stringify({ password })
        });
        showMessage(result.message, 'success');
        document.getElementById('init-password').value = '';
        showManagerSection();
    } catch (error) {
        // Error already shown by fetchAPI
    }
}

async function loadKeychain() {
    const password = document.getElementById('load-password').value;
    const data = document.getElementById('load-data').value;
    const checksum = document.getElementById('load-checksum').value || undefined;
    
    if (!password || !data) {
        showMessage('Please enter password and keychain data', 'error');
        return;
    }
    
    try {
        const result = await fetchAPI('/api/load', {
            method: 'POST',
            body: JSON.stringify({ password, data, checksum })
        });
        showMessage(result.message, 'success');
        document.getElementById('load-password').value = '';
        document.getElementById('load-data').value = '';
        document.getElementById('load-checksum').value = '';
        showManagerSection();
    } catch (error) {
        // Error already shown by fetchAPI
    }
}

async function setPassword() {
    const name = document.getElementById('set-name').value;
    const password = document.getElementById('set-password').value;
    
    if (!name || !password) {
        showMessage('Please enter both domain and password', 'error');
        return;
    }
    
    try {
        const result = await fetchAPI('/api/set', {
            method: 'POST',
            body: JSON.stringify({ name, password })
        });
        showMessage(result.message, 'success');
        document.getElementById('set-name').value = '';
        document.getElementById('set-password').value = '';
    } catch (error) {
        // Error already shown by fetchAPI
    }
}

async function getPassword() {
    const name = document.getElementById('get-name').value;
    
    if (!name) {
        showMessage('Please enter a domain name', 'error');
        return;
    }
    
    try {
        const result = await fetchAPI('/api/get', {
            method: 'POST',
            body: JSON.stringify({ name })
        });
        
        const resultEl = document.getElementById('get-result');
        if (result.password === null) {
            resultEl.textContent = 'No password found for this domain';
            resultEl.style.background = '#fff3cd';
            resultEl.style.borderColor = '#ffc107';
        } else {
            resultEl.textContent = `Password: ${result.password}`;
            resultEl.style.background = '#e7f3ff';
            resultEl.style.borderColor = '#2196F3';
        }
    } catch (error) {
        // Error already shown by fetchAPI
    }
}

async function removePassword() {
    const name = document.getElementById('remove-name').value;
    
    if (!name) {
        showMessage('Please enter a domain name', 'error');
        return;
    }
    
    try {
        const result = await fetchAPI('/api/remove', {
            method: 'POST',
            body: JSON.stringify({ name })
        });
        showMessage(result.message, result.success ? 'success' : 'error');
        document.getElementById('remove-name').value = '';
    } catch (error) {
        // Error already shown by fetchAPI
    }
}

async function exportKeychain() {
    try {
        const result = await fetchAPI('/api/dump');
        document.getElementById('export-data').value = result.data;
        document.getElementById('export-checksum').value = result.checksum;
        document.getElementById('export-modal').classList.remove('hidden');
    } catch (error) {
        // Error already shown by fetchAPI
    }
}

function closeExportModal() {
    document.getElementById('export-modal').classList.add('hidden');
}

async function changeMasterPassword() {
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    
    if (!currentPassword || !newPassword || !confirmPassword) {
        showMessage('Please fill in all password fields', 'error');
        return;
    }
    
    if (newPassword !== confirmPassword) {
        showMessage('New passwords do not match', 'error');
        return;
    }
    
    if (newPassword.length < 8) {
        showMessage('New password should be at least 8 characters', 'error');
        return;
    }
    
    try {
        const result = await fetchAPI('/api/change-password', {
            method: 'POST',
            body: JSON.stringify({ currentPassword, newPassword })
        });
        showMessage(result.message, 'success');
        document.getElementById('current-password').value = '';
        document.getElementById('new-password').value = '';
        document.getElementById('confirm-password').value = '';
    } catch (error) {
        // Error already shown by fetchAPI
    }
}
