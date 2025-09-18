document.addEventListener("DOMContentLoaded", function () {
    fetchUsers();
    setupEventListeners();
});

let users = [];
let editMode = false;
let editUserId = null;
let deleteUserId = null;

function setupEventListeners() {
    const userForm = document.getElementById("userForm");
    userForm.addEventListener("submit", function (e) {
        e.preventDefault();
        saveUser();
    });

    // Search functionality
    const searchInput = document.getElementById("searchUsers");
    searchInput.addEventListener("input", function(e) {
        filterUsers();
    });

    // Filter functionality
    const roleFilter = document.getElementById("roleFilter");
    const sortBy = document.getElementById("sortBy");
    
    roleFilter.addEventListener("change", filterUsers);
    sortBy.addEventListener("change", filterUsers);
}

function fetchUsers() {
    fetch('/api/users')
        .then(res => res.json())
        .then(data => {
            users = data;
            displayUsers(users);
            updateStatistics(users);
        })
        .catch(error => {
            console.error('Error fetching users:', error);
            showNotification('Error loading users', 'error');
        });
}

function displayUsers(userList) {
    const tableBody = document.getElementById("userTableBody");
    tableBody.innerHTML = "";

    if (userList.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="8" style="text-align: center; padding: 40px; color: #6b7280;">
                    <i class="fas fa-users" style="font-size: 48px; margin-bottom: 16px; display: block;"></i>
                    No users found
                </td>
            </tr>
        `;
        return;
    }

    userList.forEach(user => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>
                <div style="width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, var(--primary-color), var(--accent-color)); display: flex; align-items: center; justify-content: center; color: white; font-weight: 600;">
                    ${(user.first_name || user.username || 'U').charAt(0).toUpperCase()}
                </div>
            </td>
            <td><strong>#${user.id}</strong></td>
            <td>${user.username}</td>
            <td>${user.first_name || ''} ${user.last_name || ''}</td>
            <td>${user.email}</td>
            <td>
                <span class="role-badge role-${user.role.toLowerCase()}">${user.role}</span>
            </td>
            <td>
                <span class="status-badge status-active">Active</span>
            </td>
           
        `;
        tableBody.appendChild(row);
    });

    // Add role and status badge styles
    addBadgeStyles();
}

function addBadgeStyles() {
    if (!document.getElementById('user-badge-styles')) {
        const style = document.createElement('style');
        style.id = 'user-badge-styles';
        style.textContent = `
            .role-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .role-owner {
                background-color: rgba(255, 193, 7, 0.1);
                color: #ffc107;
            }
            .role-admin {
                background-color: rgba(220, 53, 69, 0.1);
                color: #dc3545;
            }
            .role-employee {
                background-color: rgba(52, 152, 219, 0.1);
                color: #3498db;
            }
            .role-customer {
                background-color: rgba(39, 174, 96, 0.1);
                color: #27ae60;
            }
            .status-badge {
                padding: 4px 12px;
                border-radius: 20px;
                font-size: 12px;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            .status-active {
                background-color: rgba(39, 174, 96, 0.1);
                color: #27ae60;
            }
        `;
        document.head.appendChild(style);
    }
}

function updateStatistics(userList) {
    const totalUsers = userList.length;
    const totalOwners = userList.filter(user => user.role === 'owner').length;
    const totalAdmins = userList.filter(user => user.role === 'admin').length;
    const totalCustomers = userList.filter(user => user.role === 'customer').length;

    document.getElementById('totalUsers').textContent = totalUsers;
    document.getElementById('totalOwners').textContent = totalOwners;
    document.getElementById('totalAdmins').textContent = totalAdmins;
    document.getElementById('totalCustomers').textContent = totalCustomers;
}

function filterUsers() {
    const searchTerm = document.getElementById("searchUsers").value.toLowerCase();
    const roleFilter = document.getElementById("roleFilter").value;
    const sortBy = document.getElementById("sortBy").value;

    let filteredUsers = users.filter(user => {
        const matchesSearch = user.username.toLowerCase().includes(searchTerm) ||
                            user.email.toLowerCase().includes(searchTerm) ||
                            (user.first_name && user.first_name.toLowerCase().includes(searchTerm)) ||
                            (user.last_name && user.last_name.toLowerCase().includes(searchTerm));
        const matchesRole = !roleFilter || user.role === roleFilter;
        return matchesSearch && matchesRole;
    });

    // Sort users
    filteredUsers.sort((a, b) => {
        switch(sortBy) {
            case 'username':
                return a.username.localeCompare(b.username);
            case 'email':
                return a.email.localeCompare(b.email);
            case 'role':
                return a.role.localeCompare(b.role);
            default:
                return 0;
        }
    });

    displayUsers(filteredUsers);
}

function openModal() {
    document.getElementById("userModal").style.display = "block";
    document.getElementById("modalTitle").innerText = editMode ? "Edit User" : "Add User";
    document.getElementById("password").required = !editMode;
    document.body.style.overflow = "hidden";
}

function closeModal() {
    document.getElementById("userModal").style.display = "none";
    document.getElementById("userForm").reset();
    editMode = false;
    editUserId = null;
    document.body.style.overflow = "auto";
}

function openDeleteModal(userId) {
    deleteUserId = userId;
    document.getElementById("deleteModal").style.display = "block";
    document.body.style.overflow = "hidden";
}

function closeDeleteModal() {
    document.getElementById("deleteModal").style.display = "none";
    deleteUserId = null;
    document.body.style.overflow = "auto";
}

function saveUser() {
    const userData = {
        username: document.getElementById("username").value.trim(),
        email: document.getElementById("email").value.trim(),
        firstName: document.getElementById("firstName").value.trim(),
        lastName: document.getElementById("lastName").value.trim(),
        role: document.getElementById("role").value,
        password: document.getElementById("password").value.trim()
    };

    // Validation
    if (!validateUser(userData)) {
        return;
    }

    const url = editMode ? `/api/users/${editUserId}` : "/api/users";
    const method = editMode ? "PUT" : "POST";

    // Don't send password if it's empty during edit
    if (editMode && !userData.password) {
        delete userData.password;
    }

    fetch(url, {
        method: method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(userData)
    })
    .then(res => res.json())
    .then(data => {
        if (data.success) {
            closeModal();
            fetchUsers();
            showNotification(
                editMode ? 'User added successfully!':'User updated successfully!'  ,
                'success'
            );
        } else {
            showNotification(data.message || 'Error saving user', 'error');
        }
    })
    .catch(error => {
        console.error('Error saving user:', error);
        showNotification('Error saving user', 'error');
    });
}

function validateUser(userData) {
    // Check if username already exists (for new users)
    if (!editMode && users.some(user => user.username === userData.username)) {
        showNotification('Username already exists', 'error');
        return false;
    }

    // Check if email already exists
    const existingEmail = users.find(user => user.email === userData.email);
    if (existingEmail && (!editMode || existingEmail.id !== editUserId)) {
        showNotification('Email already exists', 'error');
        return false;
    }

    // Validate password for new users
    if (!editMode && userData.password.length < 6) {
        showNotification('Password must be at least 8 characters long', 'error');
        return false;
    }

    return true;
}

function editUser(id) {
    const user = users.find(u => u.id === id);
    if (user) {
        editMode = true;
        editUserId = id;
        
        document.getElementById("username").value = user.username;
        document.getElementById("email").value = user.email;
        document.getElementById("firstName").value = user.first_name || '';
        document.getElementById("lastName").value = user.last_name || '';
        document.getElementById("role").value = user.role;
        document.getElementById("password").value = '';
        
        openModal();
    }
}

function confirmDelete() {
    if (!deleteUserId) return;

    fetch(`/api/users/${deleteUserId}`, {
        method: "DELETE"
    })
    .then(res => res.json())
    .then(data => {
        closeDeleteModal();
        fetchUsers();
        showNotification('User deleted successfully!', 'success');
    })
    .catch(error => {
        console.error('Error deleting user:', error);
        showNotification('Error deleting user', 'error');
    });
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <div class="notification-content">
            <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
            <span>${message}</span>
        </div>
    `;

    // Add notification styles if not already added
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                padding: 16px 20px;
                border-radius: 8px;
                color: white;
                font-weight: 500;
                z-index: 10000;
                animation: slideInRight 0.3s ease;
                min-width: 300px;
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            }
            .notification-success { background-color: #27ae60; }
            .notification-error { background-color: #e74c3c; }
            .notification-info { background-color: #3498db; }
            .notification-content {
                display: flex;
                align-items: center;
                gap: 10px;
            }
            @keyframes slideInRight {
                from { transform: translateX(100%); opacity: 0; }
                to { transform: translateX(0); opacity: 1; }
            }
        `;
        document.head.appendChild(style);
    }

    document.body.appendChild(notification);

    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideInRight 0.3s ease reverse';
            setTimeout(() => notification.remove(), 300);
        }
    }, 3000);
}

// Close modals when clicking outside
window.onclick = function (event) {
    const userModal = document.getElementById("userModal");
    const deleteModal = document.getElementById("deleteModal");
    
    if (event.target === userModal) {
        closeModal();
    }
    if (event.target === deleteModal) {
        closeDeleteModal();
    }
};