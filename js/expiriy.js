let products = [];

// Fetch expiry data from Flask backend
async function fetchExpiryAlerts() {
    const loader = document.getElementById('loader');
    const container = document.getElementById('productsContainer');

    // Show the loader and hide the container
    loader.style.display = 'block';
    container.style.display = 'none';

    try {
        const response = await fetch('/expiry_alerts');
        const data = await response.json();

        if (data.error) {
            console.error('Backend error:', data.error);
            alert(`Error fetching expiry alerts: ${data.error}`);
            return;
        }

        products = data;

        const expiredProducts = products.filter(p => p.time_to_expiry < 0);
        const expiringProducts = products.filter(p => p.time_to_expiry >= 0);
        const sortedProducts = [...expiredProducts, ...expiringProducts];

        // Display products
        displayProducts(sortedProducts);
    } catch (err) {
        console.error('Fetch error:', err);
        alert(`Error fetching expiry alerts: ${err}`);
    } finally {
        // Hide the loader and show the container
        loader.style.display = 'none';
        container.style.display = 'block';
    }
}


// Function to get the 'role' query parameter from the URL
function getRoleFromUrl() {
    const params = new URLSearchParams(window.location.search);
    return params.get('role');
}

// Function to get expiry warning class
function getExpiryWarningClass(daysUntilExpiry) {
    if (daysUntilExpiry < 0) return 'warning-expired';
    if (daysUntilExpiry <= 1) return 'warning-day';
    if (daysUntilExpiry <= 7) return 'warning-week';
    if (daysUntilExpiry <= 30) return 'warning-month';
    if (daysUntilExpiry <= 60) return 'warning-caution';
    if (daysUntilExpiry <= 90) return 'warning-watch';
    if (daysUntilExpiry <= 180) return 'warning-attention';
    return 'warning-safe';
}

// Function to create product card
function createProductCard(product) {
    const warningClass = getExpiryWarningClass(product.time_to_expiry);
    const imageUrl = product.image_url || 'https://placehold.co/300x200';

    // Determine expiry status text
    const expiryText = product.time_to_expiry < 0 
        ? `EXPIRED ${Math.abs(product.time_to_expiry)} days ago`
        : `Expires in ${product.time_to_expiry} days`;

    return `
        <div class="product-card">
            <img src="${imageUrl}" alt="${product.product_name}" 
                 onerror="this.src='https://placehold.co/300x200'">
            <div class="product-info">
                <h3>${product.product_name}</h3>
                <p>Expiry Date: ${new Date(product.expiry_date).toLocaleDateString()}</p>
                <p>Demand: ${product.demand}</p>
                <div class="expiry-warning ${warningClass}">
                    ${product.expiry_alert} — ${expiryText}
                </div>
            </div>
        </div>
    `;
}

// Function to display filtered products
function displayProducts(productsToShow) {
    const container = document.getElementById('productsContainer');
    container.innerHTML = productsToShow.map(product => createProductCard(product)).join('');
}

// Function to filter products
function filterProducts() {
    const timeFilter = document.getElementById('timeFilter').value;
    const searchText = document.getElementById('searchProduct').value.toLowerCase();

    const filteredProducts = products.filter(product => {
        const daysUntilExpiry = product.time_to_expiry;
        const matchesSearch =
            product.product_name.toLowerCase().includes(searchText) ||
            product.demand.toLowerCase().includes(searchText);

        switch (timeFilter) {
            case 'day':
                return daysUntilExpiry <= 1 && matchesSearch;
            case 'week':
                return daysUntilExpiry <= 7 && matchesSearch;
            case 'month':
                return daysUntilExpiry <= 30 && matchesSearch;
            case 'expired':
                return daysUntilExpiry < 0 && matchesSearch;
            default:
                return matchesSearch;
        }
    });

    displayProducts(filteredProducts);
}

// Event listeners
document.getElementById('timeFilter').addEventListener('change', filterProducts);
document.getElementById('searchProduct').addEventListener('input', filterProducts);

// Initial load
window.addEventListener('DOMContentLoaded', fetchExpiryAlerts);
