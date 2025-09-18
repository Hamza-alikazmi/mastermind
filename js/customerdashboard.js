let customers = [];
let allOrders = [];

document.addEventListener('DOMContentLoaded', function() {
    fetchCustomerData();
    
    // Add event listeners
    document.getElementById('searchCustomer').addEventListener('input', filterCustomers);
    document.getElementById('sortBy').addEventListener('change', sortCustomers);
    
    // Modal close functionality
    document.querySelector('.close-modal').addEventListener('click', closeModal);
    window.addEventListener('click', function(event) {
        const modal = document.getElementById('customerModal');
        if (event.target === modal) {
            closeModal();
        }
    });
});

async function fetchCustomerData() {
    try {
        // Fetch users and orders data
        const [usersResponse, ordersResponse] = await Promise.all([
            fetch('/api/customers'),
            fetch('/api/customer-orders')
        ]);
        
        if (!usersResponse.ok || !ordersResponse.ok) {
            throw new Error('Failed to fetch data');
        }
        
        const users = await usersResponse.json();
        allOrders = await ordersResponse.json();
        
        // Process customer data
        customers = processCustomerData(users, allOrders);
        
        // Update UI
        updateStatistics();
        displayCustomers(customers);
        
    } catch (error) {
        console.error('Error fetching customer data:', error);
        showNotification('Error loading customer data', 'error');
    }
}

function processCustomerData(users, orders) {
    const customerMap = new Map();
    
    // Initialize customers from users
    users.forEach(user => {
        if (user.role === 'customer') {
            customerMap.set(user.id, {
                id: user.id,
                name: `${user.first_name} ${user.last_name}`,
                email: user.email,
                username: user.username,
                totalOrders: 0,
                totalSpent: 0,
                lastOrderDate: null,
                orders: []
            });
        }
    });
    
    // Add order data
    orders.forEach(order => {
        if (order.customer_id && customerMap.has(order.customer_id)) {
            const customer = customerMap.get(order.customer_id);
            customer.totalOrders++;
            customer.totalSpent += parseFloat(order.total_amount || 0);
            customer.orders.push(order);
            
            const orderDate = new Date(order.order_date);
            if (!customer.lastOrderDate || orderDate > customer.lastOrderDate) {
                customer.lastOrderDate = orderDate;
            }
        }
    });
    
    return Array.from(customerMap.values());
}

function updateStatistics() {
    const totalCustomers = customers.length;
    const totalOrders = allOrders.length;
    const totalRevenue = allOrders.reduce((sum, order) => sum + parseFloat(order.total_amount || 0), 0);
    const avgOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;
    
    document.getElementById('totalCustomers').textContent = totalCustomers;
    document.getElementById('totalOrders').textContent = totalOrders;
    document.getElementById('totalRevenue').textContent = `Rs. ${totalRevenue.toFixed(2)}`;
    document.getElementById('avgOrderValue').textContent = `Rs. ${avgOrderValue.toFixed(2)}`;
}

function displayCustomers(customersToShow) {
    const tbody = document.getElementById('customerTableBody');
    tbody.innerHTML = '';
    
    if (customersToShow.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align: center; padding: 20px; color: #666;">No customers found</td></tr>';
        return;
    }
    
    customersToShow.forEach(customer => {
        const row = document.createElement('tr');
        row.style.borderBottom = '1px solid #eee';
        row.innerHTML = `
            <td style="padding: 15px;">${customer.id}</td>
            <td style="padding: 15px; font-weight: 500;">${customer.name}</td>
            <td style="padding: 15px;">${customer.email}</td>
            <td style="padding: 15px; text-align: center;">
                <span style="background: var(--primary-color); color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.9rem;">
                    ${customer.totalOrders}
                </span>
            </td>
            <td style="padding: 15px; font-weight: 600; color: var(--success-color);">Rs. ${customer.totalSpent.toFixed(2)}</td>
            <td style="padding: 15px;">${customer.lastOrderDate ? customer.lastOrderDate.toLocaleDateString() : 'No orders'}</td>
            <td style="padding: 15px;">
                <button onclick="viewCustomerDetails(${customer.id})" 
                        style="background: var(--accent-color); color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer; margin-right: 5px;">
                    <i class="fas fa-eye"></i> View Details
                </button>
                <button onclick="openCustomerLedger(${customer.id})" 
                        style="background: var(--primary-color); color: white; border: none; padding: 8px 16px; border-radius: 5px; cursor: pointer;">
                    <i class="fas fa-book"></i> Ledger
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function filterCustomers() {
    const searchTerm = document.getElementById('searchCustomer').value.toLowerCase();
    const filtered = customers.filter(customer => 
        customer.name.toLowerCase().includes(searchTerm) ||
        customer.email.toLowerCase().includes(searchTerm) ||
        customer.username.toLowerCase().includes(searchTerm)
    );
    displayCustomers(filtered);
}

function sortCustomers() {
    const sortBy = document.getElementById('sortBy').value;
    const sorted = [...customers].sort((a, b) => {
        switch (sortBy) {
            case 'name':
                return a.name.localeCompare(b.name);
            case 'total_spent':
                return b.totalSpent - a.totalSpent;
            case 'order_count':
                return b.totalOrders - a.totalOrders;
            case 'last_order':
                if (!a.lastOrderDate && !b.lastOrderDate) return 0;
                if (!a.lastOrderDate) return 1;
                if (!b.lastOrderDate) return -1;
                return b.lastOrderDate - a.lastOrderDate;
            default:
                return 0;
        }
    });
    displayCustomers(sorted);
}

async function viewCustomerDetails(customerId) {
    const customer = customers.find(c => c.id === customerId);
    if (!customer) return;
    
    try {
        // Fetch detailed order items for this customer
        const response = await fetch(`/api/customer-order-details/${customerId}`);
        const orderDetails = await response.json();
        
        const modal = document.getElementById('customerModal');
        const modalBody = document.getElementById('modalBody');
        
        modalBody.innerHTML = `
            <h2 style="color: var(--primary-color); margin-bottom: 20px;">
                <i class="fas fa-user"></i> ${customer.name} - Customer Details
            </h2>
            
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px;">
                <div style="background: var(--background-light); padding: 20px; border-radius: 8px;">
                    <h4><i class="fas fa-envelope"></i> Contact Information</h4>
                    <p><strong>Email:</strong> ${customer.email}</p>
                    <p><strong>Username:</strong> ${customer.username}</p>
                    <p><strong>Customer ID:</strong> ${customer.id}</p>
                </div>
                <div style="background: var(--background-light); padding: 20px; border-radius: 8px;">
                    <h4><i class="fas fa-chart-bar"></i> Purchase Statistics</h4>
                    <p><strong>Total Orders:</strong> ${customer.totalOrders}</p>
                    <p><strong>Total Spent:</strong> Rs. ${customer.totalSpent.toFixed(2)}</p>
                    <p><strong>Average Order:</strong> Rs. ${customer.totalOrders > 0 ? (customer.totalSpent / customer.totalOrders).toFixed(2) : '0.00'}</p>
                </div>
            </div>
            
            <h3 style="margin-bottom: 20px;"><i class="fas fa-shopping-cart"></i> Order History</h3>
            <div style="max-height: 400px; overflow-y: auto;">
                ${generateOrderHistoryHTML(orderDetails)}
            </div>
        `;
        
        modal.style.display = 'block';
        
    } catch (error) {
        console.error('Error fetching customer details:', error);
        showNotification('Error loading customer details', 'error');
    }
}

function generateOrderHistoryHTML(orderDetails) {
    if (!orderDetails || orderDetails.length === 0) {
        return '<p style="text-align: center; color: #666; padding: 20px;">No orders found for this customer.</p>';
    }
    
    let html = '<table style="width: 100%; border-collapse: collapse;">';
    html += `
        <thead>
            <tr style="background: var(--background-light);">
                <th style="padding: 12px; border: 1px solid #ddd;">Order ID</th>
                <th style="padding: 12px; border: 1px solid #ddd;">Date</th>
                <th style="padding: 12px; border: 1px solid #ddd;">Products</th>
                <th style="padding: 12px; border: 1px solid #ddd;">Total Amount</th>
                <th style="padding: 12px; border: 1px solid #ddd;">Payment Status</th>
            </tr>
        </thead>
        <tbody>
    `;
    
    orderDetails.forEach(order => {
        console.log("Order data:", order); // 🔍 Check this in browser console

        const orderDate = new Date(order.order_date).toLocaleDateString();
        const products = order.items ? order.items.map(item => 
            `${item.product_name} (${item.quantity}x)`
        ).join(', ') : 'No items';

        const paymentStatus = order.payment_status || 'N/A'; // Safe fallback

        html += `
            <tr style="border-bottom: 1px solid #eee;">
                <td style="padding: 12px; border: 1px solid #ddd;">#${order.order_id}</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${orderDate}</td>
                <td style="padding: 12px; border: 1px solid #ddd;">${products}</td>
                <td style="padding: 12px; border: 1px solid #ddd; color: var(--success-color); font-weight: 600;">Rs. ${parseFloat(order.total_amount).toFixed(2)}</td>
                <td style="padding: 12px; border: 1px solid #ddd;">
                    <span style="background: var(--success-color); color: black; padding: 4px 8px; border-radius: 12px;">
                        ${paymentStatus}
                    </span>
                </td>
            </tr>
        `;
    });

    html += '</tbody></table>';
    return html;
}

function closeModal() {
    document.getElementById('customerModal').style.display = 'none';
}

function refreshCustomerData() {
    showNotification('Refreshing customer data...', 'info');
    fetchCustomerData();
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 20px;
        background: ${type === 'error' ? '#E74C3C' : type === 'success' ? '#27AE60' : '#3498DB'};
        color: white;
        border-radius: 5px;
        z-index: 9999;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    `;
    notification.textContent = message;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        if (notification.parentNode) {
            notification.remove();
        }
    }, 3000);
}