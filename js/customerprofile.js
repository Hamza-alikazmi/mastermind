document.addEventListener('DOMContentLoaded', function() {
    loadUserProfile();
    loadOrderHistory();
    
    // Form submissions
    document.getElementById('profileForm').addEventListener('submit', updateProfile);
    document.getElementById('passwordForm').addEventListener('submit', changePassword);
});

async function loadUserProfile() {
    try {
        const response = await fetch('/whoami', {
            credentials: 'include'
        });
        const userData = await response.json();
        
        if (userData.user_id) {
            // Fetch detailed user information
            const userResponse = await fetch(`/api/user/${userData.user_id}`, {
                credentials: 'include'
            });
            const userDetails = await userResponse.json();
            
            if (userDetails) {
                populateForm(userDetails);
            }
        }
    } catch (error) {
        console.error('Error loading user profile:', error);
        showNotification('Error loading profile data', 'error');
    }
}

function populateForm(userData) {
    document.getElementById('username').value = userData.username || '';
    document.getElementById('email').value = userData.email || '';
    document.getElementById('firstName').value = userData.first_name || '';
    document.getElementById('lastName').value = userData.last_name || '';
    document.getElementById('phone').value = userData.phone || '';
    document.getElementById('dateOfBirth').value = userData.date_of_birth || '';
    document.getElementById('address').value = userData.address || '';
    document.getElementById('city').value = userData.city || '';
    document.getElementById('postalCode').value = userData.postal_code || '';
}

async function updateProfile(event) {
    event.preventDefault();
    
    const formData = {
        first_name: document.getElementById('firstName').value,
        last_name: document.getElementById('lastName').value,
        phone: document.getElementById('phone').value,
        date_of_birth: document.getElementById('dateOfBirth').value,
        address: document.getElementById('address').value,
        city: document.getElementById('city').value,
        postal_code: document.getElementById('postalCode').value
    };
    
    try {
        const response = await fetch('/api/update-profile', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            const successModal = new bootstrap.Modal(document.getElementById('successModal'));
            successModal.show();
        } else {
            showNotification(result.message || 'Error updating profile', 'error');
        }
    } catch (error) {
        console.error('Error updating profile:', error);
        showNotification('Error updating profile', 'error');
    }
}

async function changePassword(event) {
    event.preventDefault();
    
    const currentPassword = document.getElementById('currentPassword').value;
    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (newPassword !== confirmPassword) {
        showNotification('New passwords do not match', 'error');
        return;
    }
    
    if (newPassword.length < 6) {
        showNotification('Password must be at least 6 characters long', 'error');
        return;
    }
    
    try {
        const response = await fetch('/api/change-password', {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include',
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('Password changed successfully!', 'success');
            document.getElementById('passwordForm').reset();
        } else {
            showNotification(result.message || 'Error changing password', 'error');
        }
    } catch (error) {
        console.error('Error changing password:', error);
        showNotification('Error changing password', 'error');
    }
}

async function loadOrderHistory() {
    try {
        const response = await fetch('/api/my-orders', {
            credentials: 'include'
        });
        const orders = await response.json();
        
        const tbody = document.getElementById('orderHistoryBody');
        tbody.innerHTML = '';
        
        if (orders.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="5" class="text-center text-muted py-4">
                        <i class="bi bi-cart-x fs-1 d-block mb-2"></i>
                        No orders found
                    </td>
                </tr>
            `;
            return;
        }
        
        orders.forEach(order => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>#${order.order_id}</td>
                <td>${new Date(order.order_date).toLocaleDateString()}</td>
                <td>${order.item_count || 0} items</td>
                <td>Rs. ${parseFloat(order.total_amount).toFixed(2)}</td>
                <td><span class="badge bg-success">Completed</span></td>
            `;
            tbody.appendChild(row);
        });
    } catch (error) {
        console.error('Error loading order history:', error);
    }
}

function previewProfilePicture(event) {
    const file = event.target.files[0];
    if (file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            document.getElementById('profilePicture').src = e.target.result;
        };
        reader.readAsDataURL(file);
    }
}

function resetForm() {
    loadUserProfile();
    showNotification('Form reset to original values', 'info');
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type === 'error' ? 'danger' : type === 'success' ? 'success' : 'info'} alert-dismissible fade show position-fixed`;
    notification.style.cssText = `
        top: 20px;
        right: 20px;
        z-index: 9999;
        min-width: 300px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
    `;
    
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="bi bi-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-triangle' : 'info-circle'} me-2"></i>
            ${message}
        </div>
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 5000);
}