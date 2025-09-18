document.addEventListener("DOMContentLoaded", function () {
    fetchEmployees();
    setupEventListeners();
});

let employees = [];
let editMode = false;
let editEmployeeId = null;
let deleteEmployeeId = null;

function setupEventListeners() {
    const employeeForm = document.getElementById("employeeForm");
    employeeForm.addEventListener("submit", function (e) {
        e.preventDefault();
        saveEmployee();
    });

    // Search functionality
    const searchInput = document.getElementById("searchEmployees");
    searchInput.addEventListener("input", function(e) {
        filterEmployees();
    });

    // Filter functionality
    const sortBy = document.getElementById("sortBy");
    sortBy.addEventListener("change", filterEmployees);
}

function fetchEmployees() {
    fetch('/api/employees')
        .then(res => res.json())
        .then(data => {
            employees = data;
            displayEmployees(employees);
            updateStatistics(employees);
        })
        .catch(error => {
            console.error('Error fetching employees:', error);
            showNotification('Error loading employees', 'error');
        });
}

function displayEmployees(employeeList) {
    const tableBody = document.getElementById("employeeTableBody");
    tableBody.innerHTML = "";

    if (employeeList.length === 0) {
        tableBody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; padding: 40px; color: #6b7280;">
                    <i class="fas fa-users" style="font-size: 48px; margin-bottom: 16px; display: block;"></i>
                    No employees found
                </td>
            </tr>
        `;
        return;
    }

    employeeList.forEach(emp => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>
                <div style="width: 40px; height: 40px; border-radius: 50%; background: linear-gradient(135deg, var(--primary-color), var(--accent-color)); display: flex; align-items: center; justify-content: center; color: white; font-weight: 600;">
                    ${emp.name.charAt(0).toUpperCase()}
                </div>
            </td>
            <td><strong>${emp.employee_id}</strong></td>
            <td>${emp.name}</td>
            <td>${emp.email}</td>
            <td>${emp.phone}</td>
            <td>${emp.cnic}</td>
            <td>${emp.emergency}</td>
            <td><strong>Rs. ${parseInt(emp.salary).toLocaleString()}</strong></td>
            <td>
                <button class="action-btn edit-btn" onclick="editEmployee('${emp.employee_id}')" title="Edit Employee">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="action-btn delete-btn" onclick="openDeleteModal('${emp.employee_id}')" title="Delete Employee">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        `;
        tableBody.appendChild(row);
    });
}

function updateStatistics(employeeList) {
    const totalEmployees = employeeList.length;
    const totalSalary = employeeList.reduce((sum, emp) => sum + parseInt(emp.salary), 0);

    document.getElementById('totalEmployees').textContent = totalEmployees;
    document.getElementById('totalSalary').textContent = `Rs. ${totalSalary.toLocaleString()}`;
}

function filterEmployees() {
    const searchTerm = document.getElementById("searchEmployees").value.toLowerCase();
    const sortBy = document.getElementById("sortBy").value;

    let filteredEmployees = employees.filter(emp => {
        const matchesSearch = emp.name.toLowerCase().includes(searchTerm) ||
                            emp.email.toLowerCase().includes(searchTerm) ||
                            emp.employee_id.toLowerCase().includes(searchTerm);
        return matchesSearch;
    });

    // Sort employees
    filteredEmployees.sort((a, b) => {
        switch(sortBy) {
            case 'name':
                return a.name.localeCompare(b.name);
            case 'salary':
                return parseInt(b.salary) - parseInt(a.salary);
            default:
                return 0;
        }
    });

    displayEmployees(filteredEmployees);
}

function openModal() {
    document.getElementById("employeeModal").style.display = "block";
    document.getElementById("modalTitle").innerText = editMode ? "Edit Employee" : "Add Employee";
    document.body.style.overflow = "hidden";
}

function closeModal() {
    document.getElementById("employeeModal").style.display = "none";
    document.getElementById("employeeForm").reset();
    document.getElementById("empId").disabled = false;
    editMode = false;
    editEmployeeId = null;
    document.body.style.overflow = "auto";
}

function openDeleteModal(employeeId) {
    deleteEmployeeId = employeeId;
    document.getElementById("deleteModal").style.display = "block";
    document.body.style.overflow = "hidden";
}

function closeDeleteModal() {
    document.getElementById("deleteModal").style.display = "none";
    deleteEmployeeId = null;
    document.body.style.overflow = "auto";
}

function saveEmployee() {
    const employee = {
        id: document.getElementById("empId").value.trim(),
        name: document.getElementById("name").value.trim(),
        email: document.getElementById("email").value.trim(),
        phone: document.getElementById("phone").value.trim(),
        cnic: document.getElementById("cnic").value.trim(),
        emergency_contact: document.getElementById("emergency").value.trim(),
        role: "Employee", // Fixed role
        salary: document.getElementById("salary").value.trim()
    };

    // Validation
    if (!validateEmployee(employee)) {
        return;
    }

    const url = editMode
        ? `/api/employees/${editEmployeeId}`
        : "/employees/add";
    const method = editMode ? "PUT" : "POST";

    fetch(url, {
        method: method,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(employee)
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === 'success') {
            closeModal();
            fetchEmployees();
            showNotification(
                editMode ? 'Employee updated successfully!' : 'Employee added successfully!',
                'success'
            );
        } else {
            showNotification(data.message || 'Error saving employee', 'error');
        }
    })
    .catch(error => {
        console.error('Error saving employee:', error);
        showNotification('Error saving employee', 'error');
    });
}

function validateEmployee(employee) {
    // Check if employee ID already exists (for new employees)
    if (!editMode && employees.some(emp => emp.employee_id === employee.id)) {
        showNotification('Employee ID already exists', 'error');
        return false;
    }

    // Check if email already exists
    const existingEmail = employees.find(emp => emp.email === employee.email);
    if (existingEmail && (!editMode || existingEmail.employee_id !== editEmployeeId)) {
        showNotification('Email already exists', 'error');
        return false;
    }

    // Validate CNIC format (basic validation)
    if (!/^\d{5}-\d{7}-\d{1}$/.test(employee.cnic)) {
        showNotification('CNIC format should be: 12345-1234567-1', 'error');
        return false;
    }

    // Validate phone number
    if (!/^\d{11}$/.test(employee.phone.replace(/[-\s]/g, ''))) {
        showNotification('Phone number should be 11 digits', 'error');
        return false;
    }

    return true;
}

function editEmployee(id) {
    const emp = employees.find(e => e.employee_id === id);
    if (emp) {
        editMode = true;
        editEmployeeId = id;
        
        document.getElementById("empId").value = emp.employee_id;
        document.getElementById("empId").disabled = true;
        document.getElementById("name").value = emp.name;
        document.getElementById("email").value = emp.email;
        document.getElementById("phone").value = emp.phone;
        document.getElementById("cnic").value = emp.cnic;
        document.getElementById("emergency").value = emp.emergency;
        document.getElementById("salary").value = emp.salary;
        
        openModal();
    }
}

function confirmDelete() {
    if (!deleteEmployeeId) return;

    fetch(`/api/employees/${deleteEmployeeId}`, {
        method: "DELETE"
    })
    .then(res => res.json())
    .then(data => {
        closeDeleteModal();
        fetchEmployees();
        showNotification('Employee deleted successfully!', 'success');
    })
    .catch(error => {
        console.error('Error deleting employee:', error);
        showNotification('Error deleting employee', 'error');
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
    const employeeModal = document.getElementById("employeeModal");
    const deleteModal = document.getElementById("deleteModal");
    
    if (event.target === employeeModal) {
        closeModal();
    }
    if (event.target === deleteModal) {
        closeDeleteModal();
    }
};