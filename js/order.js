let cart = [];

// Load products from sessionStorage on page load
window.onload = function() {
    fetchProducts();
    loadStoredProducts();
};

function loadStoredProducts() {
    const expiryProducts = sessionStorage.getItem('expiryProducts');
    if (expiryProducts) {
        const products = JSON.parse(expiryProducts);
        products.forEach(product => cart.push(product));
        sessionStorage.removeItem('expiryProducts');
        updateCartDisplay();
        showPopup('Expiry products loaded into cart!', false);
    }

    const restockProducts = sessionStorage.getItem('restockProducts');
    if (restockProducts) {
        const products = JSON.parse(restockProducts);
        products.forEach(product => cart.push(product));
        sessionStorage.removeItem('restockProducts');
        updateCartDisplay();
        showPopup('Restock products loaded into cart!', false);
    }
}

// Fetch products from API
async function fetchProducts() {
    try {
        const res = await fetch("/api/products");
        const products = await res.json();
        displayProducts(products);
    } catch (err) {
        showPopup("Error fetching products: " + err.message, true);
    }
}

// Display products on page
function displayProducts(products) {
    const productList = document.getElementById("product-list");
    productList.innerHTML = "";
    products.forEach(product => {
        const card = document.createElement("div");
        card.className = "product-card";
        card.innerHTML = `
            <img src="${product.image_path}" alt="${product.product_name}" class="product-image" />
            <div class="product-info">
                <h4>${product.product_name}</h4>
                <p>${product.category}</p>
                <p>${product.price} Pkr</p>
                <button onclick="addToCart('${product.product_name}', ${product.price})">Add</button>
            </div>
        `;
        productList.appendChild(card);
    });
}

// Add to cart
function addToCart(name, price) {
    const existing = cart.find(item => item.name === name);
    if (existing) {
        existing.quantity += 1;
    } else {
        cart.push({ name, price, quantity: 1 });
    }
    updateCartDisplay();
}

// Update cart display
function updateCartDisplay() {
    const orderList = document.getElementById("order-list");
    const subtotalElem = document.getElementById("subtotal");
    const discountElem = document.getElementById("discount");
    const totalElem = document.getElementById("total");

    orderList.innerHTML = "";
    let subtotal = 0;

    cart.forEach(item => {
        subtotal += item.price * item.quantity;
        const row = document.createElement("div");
        row.innerHTML = `${item.name} - ${item.quantity} x ${item.price} = ${item.quantity * item.price} Pkr`;
        orderList.appendChild(row);
    });

    const discount = 0;
    const total = subtotal - discount;

    subtotalElem.textContent = `${subtotal} Pkr`;
    discountElem.textContent = `${discount} Pkr`;
    totalElem.textContent = `${total} Pkr`;
}

// Clear cart
document.getElementById("clear-cart").addEventListener("click", () => {
    cart = [];
    updateCartDisplay();
});

// Confirm order
document.getElementById("confirm-order").addEventListener("click", async () => {
    if (cart.length === 0) {
        showPopup("Cart is empty.", true);
        return;
    }

    const orderData = {
        supplier_name: "Default Supplier",
        expected_delivery_date: new Date().toISOString().split('T')[0],
        items: cart
    };

    try {
        const res = await fetch('/save_pharmacy_order', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(orderData)
        });

        const data = await res.json();

        if (res.ok && data.pdf_url) {
            showPopup("Order placed successfully!", false);
            setTimeout(() => {
        window.open(data.pdf_url, '_blank'); 
    }, 3000);

            cart = [];
            updateCartDisplay();
        } else {
            showPopup("Error: " + (data.error || "PDF not generated."), true);
        }

    } catch (error) {
        showPopup("Failed to confirm order: " + error.message, true);
    }
});

// Popup function
function showPopup(message, isError = false) {
    const popup = document.createElement("div");
    popup.className = "popup-message";
    if (isError) popup.classList.add("popup-error");
    popup.textContent = message;
    document.body.appendChild(popup);

    // Show smoothly
    setTimeout(() => popup.classList.add("popup-show"), 10);

    // Hide after 3s
    setTimeout(() => {
        popup.classList.remove("popup-show");
        setTimeout(() => popup.remove(), 300);
    }, 3000);
}
