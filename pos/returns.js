let currentInvoiceData = null;

document.getElementById('invoice-form').addEventListener('submit', function(event) {
    event.preventDefault();
    
    const invoiceNumber = document.getElementById('invoice-number').value.trim();
    if (!invoiceNumber) {
        showNotification('Please enter an invoice number', 'warning');
        return;
    }
    
    // Fetch invoice details
    fetchInvoiceForReturn(invoiceNumber);
});

async function fetchInvoiceForReturn(invoiceNumber) {
    try {
        const response = await fetch(`/api/invoice/${invoiceNumber}`);
        
        if (!response.ok) {
            throw new Error('Invoice not found');
        }
        
        const data = await response.json();
        
        if (!data || !data.order || data.items.length === 0) {
            showNotification('No invoice found for this number', 'error');
            return;
        }
        
        currentInvoiceData = data;
        setupReturnForm(data);
        
    } catch (error) {
        console.error('Error fetching invoice:', error);
        showNotification('Invoice not found or error occurred', 'error');
    }
}

function setupReturnForm(invoiceData) {
    const { order, items } = invoiceData;
    
    // Generate return ID and set dates
    const returnId = 'RET' + Date.now();
    const returnDate = new Date().toLocaleDateString();
    
    document.getElementById('return-id').textContent = returnId;
    document.getElementById('return-date').textContent = returnDate;
    document.getElementById('against-invoice').textContent = order.order_id;
    
    // Show invoice details
    const invoiceDetails = document.getElementById('invoice-details');
    invoiceDetails.innerHTML = `
        <h4>Invoice Details</h4>
        <p><strong>Order Date:</strong> ${new Date(order.order_date).toLocaleDateString()}</p>
        <p><strong>Total Amount:</strong> Rs. ${parseFloat(order.total_amount).toFixed(2)}</p>
        <p><strong>Customer:</strong> ${order.customer_id ? `Customer ID: ${order.customer_id}` : 'Walk-in Customer'}</p>
        <p><strong>Payment Method:</strong> ${order.payment_method || 'Cash'}</p>
    `;
    
    // Populate product dropdown
    const productSelect = document.getElementById('product');
    productSelect.innerHTML = '<option value="">Select Product</option>';
    
    items.forEach(item => {
        const option = document.createElement('option');
        option.value = JSON.stringify({
            product_name: item.product_name,
            quantity: item.quantity,
            unit_price: item.unit_price,
            product_id: item.product_id
        });
        option.textContent = `${item.product_name} (Qty: ${item.quantity})`;
        productSelect.appendChild(option);
    });
    
    // Show return form
    document.getElementById('claim-invoice').classList.add('hidden');
    document.getElementById('process-return').classList.remove('hidden');
}

function updateProductDetails() {
    const productSelect = document.getElementById('product');
    const selectedValue = productSelect.value;
    
    if (selectedValue) {
        const productData = JSON.parse(selectedValue);
        
        // Set max quantity and price
        document.getElementById('quantity').max = productData.quantity;
        document.getElementById('quantity').value = 1;
        document.getElementById('price').value = productData.unit_price;
        
        updateTotal();
    }
}

function updateTotal() {
    const quantity = parseFloat(document.getElementById('quantity').value) || 0;
    const price = parseFloat(document.getElementById('price').value) || 0;
    const total = (quantity * price).toFixed(2);
    document.getElementById('total').value = total;
}

function increaseQuantity() {
    let quantityInput = document.getElementById('quantity');
    let currentQuantity = parseInt(quantityInput.value, 10);
    const maxQuantity = parseInt(quantityInput.max) || 999;
    
    if (currentQuantity < maxQuantity) {
        quantityInput.value = currentQuantity + 1;
        updateTotal();
    }
}

function decreaseQuantity() {
    let quantityInput = document.getElementById('quantity');
    let currentQuantity = parseInt(quantityInput.value, 10);
    if (currentQuantity > 1) {
        quantityInput.value = currentQuantity - 1;
        updateTotal();
    }
}

// Handle return form submission
document.getElementById('return-form').addEventListener('submit', async function(event) {
    event.preventDefault();
    
    const productSelect = document.getElementById('product');
    const selectedValue = productSelect.value;
    
    if (!selectedValue) {
        showNotification('Please select a product to return', 'warning');
        return;
    }
    
    const productData = JSON.parse(selectedValue);
    const returnQuantity = parseInt(document.getElementById('quantity').value);
    const returnReason = document.getElementById('return-reason').value;
    const comment = document.getElementById('comment').value;
    
    if (returnQuantity > productData.quantity) {
        showNotification('Return quantity cannot exceed original quantity', 'error');
        return;
    }
    
    const returnData = {
        invoice_number: currentInvoiceData.order.order_id,
        product_name: productData.product_name,
        original_quantity: productData.quantity,
        return_quantity: returnQuantity,
        unit_price: productData.unit_price,
        return_amount: returnQuantity * productData.unit_price,
        return_reason: returnReason,
        return_notes: comment
    };
    
    try {
        const response = await fetch('/api/process_return', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(returnData)
        });
        
        const result = await response.json();
        
        if (result.success) {
            showNotification('Return processed successfully!', 'success');
            
            // Reset form after successful return
            setTimeout(() => {
                document.getElementById('process-return').classList.add('hidden');
                document.getElementById('claim-invoice').classList.remove('hidden');
                document.getElementById('invoice-form').reset();
                document.getElementById('return-form').reset();
                currentInvoiceData = null;
            }, 2000);
            
        } else {
            showNotification(result.message || 'Error processing return', 'error');
        }
        
    } catch (error) {
        console.error('Error processing return:', error);
        showNotification('Error processing return', 'error');
    }
});

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        padding: 15px 25px;
        background: ${type === 'error' ? '#e74c3c' : type === 'success' ? '#27ae60' : type === 'warning' ? '#f39c12' : '#3498db'};
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
    
    .hidden {
        display: none !important;
    }
`;
document.head.appendChild(style);