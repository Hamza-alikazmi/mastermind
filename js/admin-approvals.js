let pendingApprovals = [];
let currentAction = null;
let currentApprovalId = null;

document.addEventListener('DOMContentLoaded', function() {
    fetchPendingApprovals();
});

async function fetchPendingApprovals() {
    try {
        const response = await fetch('/api/admin/pending-approvals');
        const data = await response.json();
        if (data.error) throw new Error(data.error);
        pendingApprovals = data;
        displayApprovals(pendingApprovals);
        updateStatistics();
    } catch (error) {
        console.error('Error fetching pending approvals:', error);
        showNotification('Error loading pending approvals', 'error');
    }
}

function displayApprovals(approvals) {
    const container = document.getElementById('approvalsContainer');
    if (approvals.length === 0) {
        container.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-check-circle"></i>
                <h3>No Pending Approvals</h3>
                <p>All employee registration requests have been processed.</p>
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
                <button class="btn-reject" onclick="openApprovalPopup(${approval.id}, 'reject')">
                    <i class="fas fa-times"></i> Reject
                </button>
                <button class="btn-approve" onclick="openApprovalPopup(${approval.id}, 'approve')">
                    <i class="fas fa-check"></i> Approve
                </button>
            </div>
        </div>
    `).join('');
}

function updateStatistics() {
    const totalPending = pendingApprovals.length;
    document.getElementById('totalPending').textContent = totalPending;
}

// Open modal popup 
function openApprovalPopup(approvalId, action) {
    const approval = pendingApprovals.find(a => a.id === approvalId);
    if (!approval) return;

    currentApprovalId = approvalId;
    currentAction = action;

    const title = action === 'approve' ? 'Approve Employee' : 'Reject Employee';
    const message = action === 'approve'
        ? `Are you sure you want to approve ${approval.first_name} ${approval.last_name} as ${approval.role}?`
        : `Are you sure you want to reject ${approval.first_name} ${approval.last_name}'s ${approval.role} request?`;

    document.getElementById("popupTitle").innerText = title;
    document.getElementById("popupMessage").innerText = message;
    document.getElementById("popupModal").style.display = "flex";
}

// Confirm action from popup
async function confirmApproval() {
    if (!currentApprovalId || !currentAction) return;

    try {
        const response = await fetch('/api/admin/handle-approval', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ approval_id: currentApprovalId, action: currentAction })
        });
        const result = await response.json();
        if (result.success) {
            showNotification(currentAction === 'approve' ? 'Approved successfully' : 'Rejected successfully',
                currentAction === 'approve' ? 'success' : 'info');
            fetchPendingApprovals();
        } else {
            showNotification(result.message || `Failed to ${currentAction}`, 'error');
        }
    } catch (error) {
        console.error(`Error ${currentAction}ing user:`, error);
        showNotification(`Error ${currentAction}ing user`, 'error');
    }

    closePopup();
}

// Close popup
function closePopup() {
    document.getElementById("popupModal").style.display = "none";
    currentApprovalId = null;
    currentAction = null;
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
    }, 3000);
}

const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
    @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100%); opacity: 0; } }
`;
document.head.appendChild(style);

    // Show popup 
    function showPopup(title, message) {
      document.getElementById("popupTitle").innerText = title;
      document.getElementById("popupMessage").innerText = message;
      document.getElementById("popupModal").style.display = "flex";
    }

    function closePopup() {
      document.getElementById("popupModal").style.display = "none";
    }

   
  