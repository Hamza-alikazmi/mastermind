document.addEventListener('DOMContentLoaded', () => {
    document.getElementById('invoiceDisplay').style.display = 'none';
});

function searchInvoice() {
    const invoiceNumber = document.getElementById('invoiceNumber').value.trim();
    const invoiceDisplay = document.getElementById('invoiceDisplay');

    if (invoiceNumber === '') {
        showNotification('Please enter an invoice/order number', 'warning');
        return;
    }

    invoiceDisplay.innerHTML = `
        <div style="text-align: center; padding: 40px;">
            <i class="fas fa-spinner fa-spin" style="font-size: 2rem; color: var(--primary-color);"></i>
            <p style="margin-top: 15px;">Searching for invoice...</p>
        </div>
    `;
    invoiceDisplay.style.display = 'block';

    fetch(`/api/invoice/${invoiceNumber}`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Invoice not found');
            }
            return response.json();
        })
        .then(data => {
            if (!data || !data.order || data.items.length === 0) {
                invoiceDisplay.innerHTML = `
                    <div style="text-align: center; padding: 40px; color: #e74c3c;">
                        <i class="fas fa-exclamation-triangle" style="font-size: 3rem; margin-bottom: 20px;"></i>
                        <h3>No Invoice Found</h3>
                        <p>No invoice found for ID: ${invoiceNumber}</p>
                    </div>
                `;
                return;
            }

            const { order, items } = data;
            const date = new Date(order.order_date).toLocaleDateString();
            const customerInfo = order.customer_id ? `Customer ID: ${order.customer_id}` : 'Walk-in Customer';

            let invoiceHTML = `
                <div class="invoice-header">
                    <h3>Invoice #${invoiceNumber}</h3>
                    <span class="date"><i class="far fa-calendar-alt"></i> ${date}</span>
                </div>
                <div class="customer-info">
                    <p><i class="far fa-user"></i> <strong>Customer:</strong> ${customerInfo}</p>
                    <p><i class="fas fa-credit-card"></i> <strong>Payment Method:</strong> ${order.payment_method || 'Cash'}</p>
                    ${order.card_holder ? `<p><i class="fas fa-user"></i> <strong>Card Holder:</strong> ${order.card_holder}</p>` : ''}
                    ${order.card_last_four ? `<p><i class="fas fa-credit-card"></i> <strong>Card:</strong> ****${order.card_last_four}</p>` : ''}
                </div>
                <table class="invoice-items">
                    <thead>
                        <tr>
                            <th>Item</th>
                            <th>Quantity</th>
                            <th>Unit Price</th>
                            <th>Total</th>
                        </tr>
                    </thead>
                    <tbody>`;

            let total = 0;
            items.forEach(item => {
                const itemTotal = parseFloat(item.total_price) || 0;
                total += itemTotal;

                invoiceHTML += `
                    <tr>
                        <td>${item.product_name}</td>
                        <td>${item.quantity}</td>
                        <td>Rs. ${parseFloat(item.unit_price).toFixed(2)}</td>
                        <td>Rs. ${itemTotal.toFixed(2)}</td>
                    </tr>`;
            });

            invoiceHTML += `</tbody>
                <tfoot>
                    <tr>
                        <td colspan="3"><strong>Subtotal</strong></td>
                        <td><strong>Rs. ${total.toFixed(2)}</strong></td>
                    </tr>
                    <tr>
                        <td colspan="3"><strong>Paid Amount</strong></td>
                        <td><strong>Rs. ${(parseFloat(order.paid_amount) || 0).toFixed(2)}</strong></td>
                    </tr>
                    <tr>
                        <td colspan="3"><strong>Change Returned</strong></td>
                        <td><strong>Rs. ${(parseFloat(order.change_amount) || 0).toFixed(2)}</strong></td>
                    </tr>
                </tfoot>
                </table>
            `;

            invoiceDisplay.innerHTML = invoiceHTML;
        })
        .catch(err => {
            invoiceDisplay.innerHTML = `
                <div style="text-align: center; padding: 40px; color: #e74c3c;">
                    <i class="fas fa-exclamation-triangle" style="font-size: 3rem; margin-bottom: 20px;"></i>
                    <h3>Error</h3>
                    <p>${err.message}</p>
                </div>
            `;
        });
}
