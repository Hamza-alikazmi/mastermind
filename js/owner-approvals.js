let pendingApprovals = [];

document.addEventListener('DOMContentLoaded', function() {
    fetchPendingApprovals();
});

async function fetchPendingApprovals() {
    try {
        const response = await fetch('/api/pending-approvals');
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        pendingApprovals = data;
        displayApprovals(pendingApprovals);
        updateStatistics();
        
    } catch (error) {
        console.error('Error fetching pending approvals:', error);
        
    }
}

function displayApprovals(approvals) {
    const container = document.getElementById('approvalsContainer');
    
    if (approvals.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-check-circle"></i>
                <h3>No Pending Approvals</h3>
                <p>All registration requests have been processed.</p>
            </div>
        `;
        return;
    }
    
    container.innerHTML = approvals.map(approval => `
        <div class="approval-card">
            <div class="approval-header">
                <div>
                    <h3 style="margin: 0; color: var(--text-primary);">
                        ${approval.first_name} ${approval.last_name}
                    </h3>
                    <span class="role-badge role-${approval.role}">${approval.role}</span>
                </div>
                <div style="color: #666; font-size: 14px;">
                    <i class="fas fa-clock"></i> 
                    Requested: ${new Date(approval.created_at).toLocaleDateString()}
                </div>
            </div>
            
            <div class="user-info">
                <div class="info-item">
                    <span class="info-label">Username</span>
                    <span class="info-value">${approval.username}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Email</span>
                    <span class="info-value">${approval.email}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Full Name</span>
                    <span class="info-value">${approval.first_name} ${approval.last_name}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Role Requested</span>
                    <span class="info-value">${approval.role.charAt(0).toUpperCase() + approval.role.slice(1)}</span>
                </div>
            </div>
            
            <div class="approval-actions">
                <button class="btn-reject" onclick="handleApproval(${approval.id}, 'reject')">
                    <i class="fas fa-times"></i> Reject
                </button>
                <button class="btn-approve" onclick="handleApproval(${approval.id}, 'approve')">
                    <i class="fas fa-check"></i> Approve
                </button>
            </div>
        </div>
    `).join('');
}

function updateStatistics() {
    const totalPending = pendingApprovals.length;
    const adminRequests = pendingApprovals.filter(a => a.role === 'admin').length;

    
    document.getElementById('totalPending').textContent = totalPending;
    document.getElementById('totalAdminRequests').textContent = adminRequests;
    
}

async function handleApproval(approvalId, action) {
    const approval = pendingApprovals.find(a => a.id === approvalId);
    if (!approval) return;

    // Set modal content dynamically
    const modal = document.getElementById('confirmationModal');
    const modalTitle = document.getElementById('modalTitle');
    const modalMessage = document.getElementById('modalMessage');

    modalTitle.textContent = action === 'approve' ? 'Approve Employee' : 'Reject Employee';
    modalMessage.textContent = action === 'approve'
        ? `Are you sure you want to approve ${approval.first_name} ${approval.last_name} as ${approval.role}?`
        : `Are you sure you want to reject ${approval.first_name} ${approval.last_name}'s ${approval.role} request?`;

    // Show modal
    modal.style.display = 'flex';

    const okBtn = document.getElementById('okBtn');
    const cancelBtn = document.getElementById('cancelBtn');

    // Remove old listeners to avoid duplication
    okBtn.replaceWith(okBtn.cloneNode(true));
    cancelBtn.replaceWith(cancelBtn.cloneNode(true));

    const newOkBtn = document.getElementById('okBtn');
    const newCancelBtn = document.getElementById('cancelBtn');

    // OK button → Proceed with approval/rejection
    newOkBtn.addEventListener('click', async () => {
        modal.style.display = 'none';

        try {
            const response = await fetch('/api/handle-approval', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    approval_id: approvalId,
                    action: action
                })
            });

            const result = await response.json();

            if (result.success) {
                showNotification(
                    action === 'approve'
                        ? `${approval.first_name} ${approval.last_name} has been approved as ${approval.role}!`
                        : `${approval.first_name} ${approval.last_name}'s request has been rejected.`,
                    action === 'approve' ? 'success' : 'info'
                );

                // Refresh list after approval/rejection
                fetchPendingApprovals();
            } else {
                showNotification(result.message || `Failed to ${action} user`, 'error');
            }
        } catch (error) {
            console.error(`Error ${action}ing user:`, error);
            showNotification(`Error ${action}ing user`, 'error');
        }
    });

    // Cancel button → Close modal
    newCancelBtn.addEventListener('click', () => {
        modal.style.display = 'none';
    });
}

function refreshApprovals() {
    showNotification('Refreshing approvals...', 'info');
    fetchPendingApprovals();
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'error' ? '#E74C3C' : type === 'success' ? '#27AE60' : '#3498DB'};
        color: white;
        border-radius: 8px;
        z-index: 9999;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        font-weight: 500;
        animation: slideIn 0.3s ease;
    `;
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : 'info-circle'}"></i>
            ${message}
        </div>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        if (notification.parentNode) {
            notification.style.animation = 'slideOut 0.3s ease';
            setTimeout(() => notification.remove(), 300);
        }
    }, 4000);
}

// Add CSS for animations
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
