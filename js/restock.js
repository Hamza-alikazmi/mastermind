let restockData = [];
let selectedProducts = [];

document.addEventListener('DOMContentLoaded', function() {
    setupEventListeners();
});

function setupEventListeners() {
    document.getElementById('showRestockProducts').addEventListener('click', fetchRestockData);
    document.getElementById('addToOrderBtn').addEventListener('click', addSelectedToOrder);
}

async function fetchRestockData() {
    try {
        showLoading(true);
        
        const response = await fetch('/api/predict_restocks');
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        restockData = data;
        displayRestockProducts(restockData);
        
        document.getElementById('restockProductsSection').style.display = 'block';
        showLoading(false);
        
        // Auto-save to database
        await saveRestockPredictionsToDatabase(restockData);
        
    } catch (error) {
        console.error('Error fetching restock data:', error);
        showNotification('Error loading restock predictions', 'error');
        showLoading(false);
    }
}

async function saveRestockPredictionsToDatabase(predictions) {
    try {
        // Prepare data for auto order
        const orderData = predictions.map(pred => ({
            product_id: pred.product_id,
            prediction_id: pred.product_id, // Using product_id as prediction_id
            recommended_quantity: pred.recommended_quantity,
            estimated_cost: pred.recommended_quantity * 100 // Assuming average cost of 100 per unit
        }));
        
        const response = await fetch('/api/save_auto_order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ predictions: orderData })
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification(`Restock predictions saved! Order ID: ${result.auto_order_id}`, 'success');
        } else {
            console.error('Failed to save predictions:', result.message);
        }
        
    } catch (error) {
        console.error('Error saving predictions to database:', error);
    }
}

function displayRestockProducts(products) {
    const tbody = document.getElementById('restockTableBody');
    tbody.innerHTML = '';
    
    if (products.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="7" style="text-align: center; padding: 40px; color: #666;">
                    <i class="fas fa-check-circle" style="font-size: 48px; margin-bottom: 16px; display: block; color: #27AE60;"></i>
                    All products are well stocked!
                </td>
            </tr>
        `;
        return;
    }
    
    // Sort by urgency (days until restock)
    products.sort((a, b) => a.predicted_days_until_restock - b.predicted_days_until_restock);
    
    products.forEach(product => {
        const row = document.createElement('tr');
        const urgency = getUrgencyLevel(product.predicted_days_until_restock);
        
        row.innerHTML = `
            <td style="padding: 12px; border: 1px solid #ddd; text-align: center;">
                <input type="checkbox" class="product-checkbox" value="${product.product_id}" 
                       data-product='${JSON.stringify(product)}' onchange="updateSelectedProducts()">
            </td>
            <td style="padding: 12px; border: 1px solid #ddd; font-weight: 600;">${product.product_name}</td>
            <td style="padding: 12px; border: 1px solid #ddd; text-align: center;">
                <span style="color: ${product.stock_quantity < 10 ? '#E74C3C' : '#27AE60'}; font-weight: 600;">
                    ${product.stock_quantity}
                </span>
            </td>
            <td style="padding: 12px; border: 1px solid #ddd; text-align: center;">
                <span style="color: ${urgency.color}; font-weight: 600;">
                    ${product.predicted_days_until_restock} days
                </span>
            </td>
            <td style="padding: 12px; border: 1px solid #ddd; text-align: center; font-weight: 600;">
                ${product.recommended_quantity}
            </td>
            <td style="padding: 12px; border: 1px solid #ddd;">
                ${new Date(product.restock_date).toLocaleDateString()}
            </td>
            <td style="padding: 12px; border: 1px solid #ddd; text-align: center;">
                <span class="priority-badge" style="background: ${urgency.color}; color: white; padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 600;">
                    ${urgency.level}
                </span>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function getUrgencyLevel(days) {
    if (days <= 7) return { level: 'URGENT', color: '#E74C3C' };
    if (days <= 14) return { level: 'HIGH', color: '#F39C12' };
    if (days <= 30) return { level: 'MEDIUM', color: '#3498DB' };
    return { level: 'LOW', color: '#27AE60' };
}

function toggleSelectAll() {
    const selectAll = document.getElementById('selectAll');
    const checkboxes = document.querySelectorAll('.product-checkbox');
    
    checkboxes.forEach(checkbox => {
        checkbox.checked = selectAll.checked;
    });
    
    updateSelectedProducts();
}

function updateSelectedProducts() {
    const checkboxes = document.querySelectorAll('.product-checkbox:checked');
    selectedProducts = Array.from(checkboxes).map(cb => {
        const productData = JSON.parse(cb.getAttribute('data-product'));
        return {
            product_id: productData.product_id,
            name: productData.product_name,
            price: 100, // Default price - you can modify this
            quantity: productData.recommended_quantity
        };
    });
    
    const addBtn = document.getElementById('addToOrderBtn');
    if (selectedProducts.length > 0) {
        addBtn.style.display = 'inline-block';
        addBtn.innerHTML = `<i class="fas fa-cart-plus"></i> Add ${selectedProducts.length} Products to Order Cart`;
    } else {
        addBtn.style.display = 'none';
    }
}

function addSelectedToOrder() {
    if (selectedProducts.length === 0) {
        showNotification('Please select products to add to order', 'warning');
        return;
    }
    
    // Store selected products in sessionStorage
    sessionStorage.setItem('restockProducts', JSON.stringify(selectedProducts));
    
    showNotification(`${selectedProducts.length} products added to order cart!`, 'success');
    
    // Redirect to order page after a short delay
    setTimeout(() => {
        window.location.href = '/order';
    }, 1500);
}

function showLoading(show) {
    const btn = document.getElementById('showRestockProducts');
    if (show) {
        btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Loading...';
        btn.disabled = true;
    } else {
        btn.innerHTML = '<i class="fas fa-exclamation-triangle"></i> Show Products Needing Restock';
        btn.disabled = false;
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'error' ? '#E74C3C' : type === 'success' ? '#27AE60' : type === 'warning' ? '#F39C12' : '#3498DB'};
        color: white;
        border-radius: 8px;
        z-index: 9999;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        font-weight: 500;
        animation: slideIn 0.3s ease;
    `;
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 10px;">
            <i class="fas fa-${type === 'error' ? 'exclamation-triangle' : type === 'success' ? 'check-circle' : type === 'warning' ? 'exclamation-triangle' : 'info-circle'}"></i>
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
    
    .card {
        background: white;
        padding: 25px;
        border-radius: 12px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        margin-bottom: 25px;
    }
`;
document.head.appendChild(style);