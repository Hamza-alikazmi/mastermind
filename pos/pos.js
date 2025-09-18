let products = [];
let cart = [];

document.addEventListener("DOMContentLoaded", () => {
    fetchProducts();

    // Paid amount calculation
    document.getElementById("paidAmount").addEventListener("input", updateBillingSummary);

    // Search bar functionality
    document.getElementById("searchInput").addEventListener("keyup", function () {
        const filter = this.value.toLowerCase();

        // Filter products by name or product_id
        const filteredProducts = products.filter(product =>
            product.product_name.toLowerCase().includes(filter) ||
            product.product_id.toString().includes(filter)
        );

        // Show only matched products
        displayProducts(filteredProducts);
    });

    // Category filter
    document.getElementById("categorySelect").addEventListener("change", function () {
        const category = this.value;

        if (category === "All Categories") {
            displayProducts(products);
        } else {
            const filteredProducts = products.filter(product =>
                product.category && product.category.toLowerCase() === category.toLowerCase()
            );
            displayProducts(filteredProducts);
        }
    });
});

// Helper function to show popup messages
function showPopup(message, type = "success") {
    const existing = document.getElementById("popupMessage");
    if (existing) existing.remove();

    const popup = document.createElement("div");
    popup.id = "popupMessage";
    popup.textContent = message;
    popup.style.position = "fixed";
    popup.style.top = "20px";
    popup.style.right = "20px";
    popup.style.padding = "15px 25px";
    popup.style.borderRadius = "5px";
    popup.style.color = "#fff";
    popup.style.fontWeight = "bold";
    popup.style.zIndex = 1000;
    popup.style.boxShadow = "0 4px 8px rgba(0,0,0,0.2)";
    popup.style.transition = "opacity 0.5s";

    if (type === "success") {
        popup.style.backgroundColor = "#28a745"; // Green
    } else if (type === "error") {
        popup.style.backgroundColor = "#dc3545"; // Red
    }

    document.body.appendChild(popup);

    setTimeout(() => {
        popup.style.opacity = "0";
        setTimeout(() => popup.remove(), 500);
    }, 5000);
}

function fetchProducts() {
    fetch("/api/products")
        .then(res => res.json())
        .then(data => {
            products = data;
            displayProducts(products);
        })
        .catch(err => console.error("Error loading products:", err));
}

function displayProducts(products) {
    const tbody = document.getElementById("productTableBody");
    tbody.innerHTML = "";

    products.forEach(product => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td><img src="${product.image_path}" width="50"></td>
            <td>${product.product_name}</td>
            <td>${product.product_id}</td>
            <td>${product.stock_quantity}</td>
            <td>${product.price}</td>
            <td>
                <button class="btn btn-sm btn-success" onclick="addToCart(${product.product_id}, '${product.product_name.replace(/'/g, "\\'")}', ${product.price})">
                    <i class="bi bi-plus-circle"></i> Add
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });
}

function addToCart(product_id, name, price) {
    const existing = cart.find(item => item.product_id === product_id);
    if (existing) {
        existing.quantity += 1;
    } else {
        cart.push({ product_id, name, price, quantity: 1 });
    }
    updateCartDisplay();
}

function removeFromCart(product_id) {
    cart = cart.filter(item => item.product_id !== product_id);
    updateCartDisplay();
}

function clearCart() {
    cart = [];
    updateCartDisplay();
    document.getElementById("paidAmount").value = '';
    document.getElementById("returnedAmount").value = '';
}

function updateCartDisplay() {
    const tbody = document.getElementById("cartTableBody");
    tbody.innerHTML = "";
    let total = 0;

    cart.forEach(item => {
        const itemTotal = item.price * item.quantity;
        total += itemTotal;

        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${item.quantity}</td>
            <td>${item.name}</td>
            <td>${item.price.toFixed(2)}</td>
            <td>
                <button class="btn btn-sm btn-danger" onclick="removeFromCart(${item.product_id})">
                    <i class="bi bi-x"></i>
                </button>
            </td>
        `;
        tbody.appendChild(row);
    });

    document.getElementById("totalAmount").textContent = total.toFixed(2);
    document.getElementById("taxAmount").textContent = "0.00";
    document.getElementById("discountAmount").textContent = "0.00";

    updateBillingSummary();
}

function updateBillingSummary() {
    const paid = parseFloat(document.getElementById("paidAmount").value) || 0;
    const total = cart.reduce((acc, item) => acc + item.price * item.quantity, 0);
    const change = paid - total;

    document.getElementById("returnedAmount").value = change.toFixed(2);
}

async function saveOrder() {
    if (cart.length === 0) {
        showPopup("Cart is empty.", "error"); 
        return;
    }

    const paidAmount = parseFloat(document.getElementById("paidAmount").value) || 0;
    const totalAmount = cart.reduce((acc, item) => acc + item.price * item.quantity, 0);
    const changeAmount = paidAmount - totalAmount;

    // Validation check
    if (paidAmount <= 0) {
        showPopup("Please enter a valid paid amount.", "error");
        return;
    }

    if (changeAmount < 0) {
        showPopup("Paid amount is less than total. Cannot save order.", "error");
        return;
    }

    try {
        const response = await fetch('/api/save_order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                cart: cart,
                paid_amount: paidAmount,
                change_amount: changeAmount
            })
        });

        const result = await response.json();

        if (result.success) {
            showPopup(`Order saved successfully! Order ID: ${result.order_id}`, "success");

            setTimeout(() => {
                window.open(result.pdf_url, '_blank');
            }, 2000);

            clearCart();
            fetchProducts();
        } else {
            showPopup("Error saving order: " + result.error, "error");
        }
    } catch (err) {
        console.error("Error saving order:", err);
        showPopup("Server error while saving order.", "error");
    }
}

// newOrder() function 
function newOrder() {
    clearCart();
}

