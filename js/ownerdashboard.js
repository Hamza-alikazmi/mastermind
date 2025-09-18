// Monthly Sales Chart
const monthlyCtx = document.getElementById('monthlyChart').getContext('2d');
const monthlyChart = new Chart(monthlyCtx, {
    type: 'bar',
    data: {
        labels: ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun'],
        datasets: [{
            label: 'Monthly Sales',
            data: [12000, 19000, 15000, 25000, 22000, 30000],
            backgroundColor: '#138BA8',
            borderColor: '#138BA8',
            borderWidth: 1
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

// Yearly Sales Chart
const yearlyCtx = document.getElementById('yearlyChart').getContext('2d');
const yearlyChart = new Chart(yearlyCtx, {
    type: 'line',
    data: {
        labels: ['2019', '2020', '2021', '2022', '2023'],
        datasets: [{
            label: 'Yearly Sales',
            data: [300000, 400000, 350000, 450000, 548950],
            backgroundColor: 'rgba(19, 139, 168, 0.2)',
            borderColor: '#138BA8',
            borderWidth: 2,
            fill: true
        }]
    },
    options: {
        responsive: true,
        scales: {
            y: {
                beginAtZero: true
            }
        }
    }
});

// Add event listeners for sidebar navigation
document.querySelectorAll('.nav-item').forEach(item => {
    item.addEventListener('click', () => {
        document.querySelectorAll('.nav-item').forEach(nav => nav.classList.remove('active'));
        item.classList.add('active');
    });
});

// Add event listeners for replace buttons
document.querySelectorAll('.replace-btn').forEach(button => {
    button.addEventListener('click', function() {
        alert('Replacement order initiated!');
    });
});

// Search functionality
const searchInput = document.querySelector('.search-bar input');
searchInput.addEventListener('input', function(e) {
    console.log('Searching for:', e.target.value);
    // Implement search functionality here
});