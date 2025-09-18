// Initialize Stripe with your publishable key
const stripe = Stripe('pk_test_51RvFpAFnsPUQVISnl0hS74vk609jQ9mbxHvDmCGRfYj1rx9bD2L4EnJhyLat2jHrHPuxwbtc2C5SSrzPGVYYve5300AV5Kyw7O');

let orderData = null;
let card = null;

// Load order data from sessionStorage
document.addEventListener('DOMContentLoaded', () => {
    loadOrderData();
    initializePaymentForm();
});

function loadOrderData() {
    const storedOrder = sessionStorage.getItem('pendingOrder');
    if (storedOrder) {
        orderData = JSON.parse(storedOrder);
        populateOrderSummary();
    } else {
        window.location.href = '/customer';
    }
}

function populateOrderSummary() {
    const orderItemsContainer = document.getElementById('orderItems');
    const subtotalElement = document.getElementById('subtotalAmount');
    const grandTotalElement = document.getElementById('grandTotal');

    if (!orderData || !orderData.cart) return;

    orderItemsContainer.innerHTML = '';
    orderData.cart.forEach(item => {
        const itemElement = document.createElement('div');
        itemElement.className = 'order-item';
        itemElement.innerHTML = `
            <div class="item-details">
                <h3>${item.name}</h3>
                <p>Quantity: ${item.quantity} × Rs. ${item.price.toFixed(2)}</p>
            </div>
            <span class="item-price">Rs. ${(item.price * item.quantity).toFixed(2)}</span>
        `;
        orderItemsContainer.appendChild(itemElement);
    });

    const total = orderData.total || 0;
    subtotalElement.textContent = `Rs. ${total.toFixed(2)}`;
    grandTotalElement.textContent = `Rs. ${total.toFixed(2)}`;
}

function initializePaymentForm() {
    const elements = stripe.elements();
    card = elements.create('card', {
        hidePostalCode: true,
        style: {
            base: {
                fontSize: '16px',
                color: '#424770',
                '::placeholder': {
                    color: '#aab7c4',
                },
            }
        }
    });
    card.mount('#cardElement');

    const paymentForm = document.getElementById('paymentForm');
    const successModal = document.getElementById('successModal');
    const downloadReceiptBtn = document.getElementById('downloadReceipt');
    const continueShoppingBtn = document.getElementById('continueShopping');

    paymentForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const payButton = paymentForm.querySelector('.pay-button');
        payButton.classList.add('loading');
        payButton.innerHTML = '<span>Processing Payment...</span>';

        try {
            const res = await fetch('/api/create_payment_intent', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    amount: Math.round(orderData.total * 100),
                    currency: 'pkr',
                    cart: orderData.cart
                })
            });

            const { client_secret, payment_intent_id } = await res.json();

            const { error, paymentIntent } = await stripe.confirmCardPayment(client_secret, {
                payment_method: {
                    card: card,
                }
            });

            if (error) throw new Error(error.message);

            if (paymentIntent.status === 'succeeded') {
                const saveResponse = await fetch('/api/save_customer_order', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        cart: orderData.cart,
                        total_amount: orderData.total,
                        paid_amount: orderData.total,
                        change_amount: 0,
                        payment_method: 'stripe',
                        payment_intent_id: paymentIntent.id,
                        card_last_four: paymentIntent?.charges?.data?.[0]?.payment_method_details?.card?.last4 || '0000',

                    })
                });

                const result = await saveResponse.json();

                if (result.success) {
                    sessionStorage.setItem('receiptUrl', result.pdf_url);
                    sessionStorage.setItem('orderId', result.order_id);
                    sessionStorage.removeItem('pendingOrder');
                    successModal.classList.add('show');
                } else {
                    throw new Error(result.error || 'Failed to save order');
                }
            } else {
                throw new Error('Payment was not successful');
            }
        } catch (err) {
            const errorModal = document.createElement('div');
            errorModal.className = 'modal show';
            errorModal.innerHTML = `
                <div class="modal-content">
                    <div class="error-icon" style="width: 72px; height: 72px; background-color: #E74C3C; color: white; border-radius: 50%; display: flex; justify-content: center; align-items: center; font-size: 2.5rem; margin: 0 auto 1.5rem;">✗</div>
                    <h2>Payment Failed</h2>
                    <p>${err.message}</p>
                    <div class="modal-buttons">
                        <button class="modal-button" onclick="this.closest('.modal').remove()">Try Again</button>
                    </div>
                </div>
            `;
            document.body.appendChild(errorModal);
        } finally {
            payButton.classList.remove('loading');
            payButton.innerHTML = '<span>Pay Now</span><span class="button-icon">→</span>';
        }
    });

    downloadReceiptBtn.addEventListener('click', () => {
        const receiptUrl = sessionStorage.getItem('receiptUrl');
        if (receiptUrl) window.open(receiptUrl, '_blank');
    });

    continueShoppingBtn.addEventListener('click', () => {
        window.location.href = '/customer';
    });
}
