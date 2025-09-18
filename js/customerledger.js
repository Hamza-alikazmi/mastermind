let customerLedgerData = [];
let filteredLedgerData = [];

// Open Customer Ledger Modal
function openCustomerLedger(customerId) {
    const modal = document.getElementById('customerLedgerModal');
    modal.style.display = 'block';
    document.body.style.overflow = 'hidden';
    
    // Fetch ledger data for the customer
    fetchCustomerLedger(customerId);
}

// Close Customer Ledger Modal
function closeCustomerLedger() {
    const modal = document.getElementById('customerLedgerModal');
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
}

// Fetch Customer Ledger Data
async function fetchCustomerLedger(customerId) {
    try {
        showLedgerLoading(true);
        
        const response = await fetch(`/api/customer-ledger/${customerId}`);
        const data = await response.json();
        
        if (data.error) {
            throw new Error(data.error);
        }
        
        customerLedgerData = data.transactions || [];
        filteredLedgerData = [...customerLedgerData];
        
        // Update customer info in header
        updateLedgerHeader(data.customer_info);
        
        // Update summary
        updateLedgerSummary(data.summary);
        
        // Display transactions
        displayLedgerTransactions(filteredLedgerData);
        
        showLedgerLoading(false);
        
    } catch (error) {
        console.error('Error fetching customer ledger:', error);
        showLedgerError('Error loading customer ledger data');
        showLedgerLoading(false);
    }
}

// Update Ledger Header
function updateLedgerHeader(customerInfo) {
    const headerTitle = document.querySelector('.ledger-header h2');
    if (customerInfo) {
        headerTitle.textContent = `Customer Ledger - ${customerInfo.name} (ID: ${customerInfo.id})`;
    } else {
        headerTitle.textContent = 'Customer Ledger';
    }
}

// Update Ledger Summary
function updateLedgerSummary(summary) {
    if (!summary) return;
    
    document.getElementById('openingBalance').textContent = `Rs. ${summary.opening_balance.toFixed(2)}`;
    document.getElementById('totalDebit').textContent = `Rs. ${summary.total_debit.toFixed(2)}`;
    document.getElementById('totalCredit').textContent = `Rs. ${summary.total_credit.toFixed(2)}`;
    document.getElementById('endingBalance').textContent = `Rs. ${summary.ending_balance.toFixed(2)}`;
}

// Display Ledger Transactions
function displayLedgerTransactions(transactions) {
    const tbody = document.getElementById('ledgerTableBody');
    tbody.innerHTML = '';
    
    if (transactions.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; padding: 40px; color: #666;">
                    <i class="fas fa-file-invoice" style="font-size: 48px; margin-bottom: 16px; display: block;"></i>
                    No transactions found
                </td>
            </tr>
        `;
        return;
    }
    
    transactions.forEach(transaction => {
        const row = document.createElement('tr');
        
        // Format date
        const date = new Date(transaction.date).toLocaleDateString('en-GB');
        
        // Determine transaction type class
        const transTypeClass = transaction.trans_type.toLowerCase().replace(/[^a-z]/g, '-');
        
        // Format amounts
        const creditAmount = transaction.credit_amount > 0 ? transaction.credit_amount.toFixed(2) : '0';
        const debitAmount = transaction.debit_amount > 0 ? transaction.debit_amount.toFixed(2) : '0';
        const balance = transaction.balance.toFixed(2);
        
        row.innerHTML = `
            <td>${date}</td>
            <td>${transaction.inv_no || '-'}</td>
            <td>
                <span class="trans-type ${transTypeClass}">${transaction.trans_type}</span>
            </td>
            <td>${transaction.item_name || '-'}</td>
            <td>${transaction.description || '-'}</td>
            <td style="text-align: center;">${transaction.qty || '-'}</td>
            <td style="text-align: right;">${transaction.rate ? `Rs. ${transaction.rate.toFixed(2)}` : '-'}</td>
            <td class="amount-cell credit">${creditAmount}</td>
            <td class="amount-cell debit">${debitAmount}</td>
            <td class="balance-cell">
                ${balance}
                <span class="dr-cr-indicator">${transaction.dr_cr}</span>
            </td>
        `;
        
        tbody.appendChild(row);
    });
}

// Filter Ledger Data
function filterLedgerData() {
    const dateFrom = document.getElementById('dateFrom').value;
    const dateTo = document.getElementById('dateTo').value;
    const transType = document.getElementById('transTypeFilter').value;
    const searchTerm = document.getElementById('searchLedger').value.toLowerCase();
    
    filteredLedgerData = customerLedgerData.filter(transaction => {
        // Date filter
        const transDate = new Date(transaction.date);
        const fromDate = dateFrom ? new Date(dateFrom) : null;
        const toDate = dateTo ? new Date(dateTo) : null;
        
        if (fromDate && transDate < fromDate) return false;
        if (toDate && transDate > toDate) return false;
        
        // Transaction type filter
        if (transType && transaction.trans_type !== transType) return false;
        
        // Search filter
        if (searchTerm) {
            const searchFields = [
                transaction.item_name,
                transaction.description,
                transaction.inv_no,
                transaction.trans_type
            ].filter(field => field).join(' ').toLowerCase();
            
            if (!searchFields.includes(searchTerm)) return false;
        }
        
        return true;
    });
    
    displayLedgerTransactions(filteredLedgerData);
    updateFilteredSummary();
}

// Update Summary for Filtered Data
function updateFilteredSummary() {
    const summary = {
        opening_balance: 0,
        total_debit: 0,
        total_credit: 0,
        ending_balance: 0
    };
    
    filteredLedgerData.forEach(transaction => {
        summary.total_debit += transaction.debit_amount;
        summary.total_credit += transaction.credit_amount;
    });
    
    if (filteredLedgerData.length > 0) {
        summary.ending_balance = filteredLedgerData[filteredLedgerData.length - 1].balance;
    }
    
    updateLedgerSummary(summary);
}

// Export Functions
function exportLedgerToPDF() {
    // Create a simple PDF export
    const printWindow = window.open('', '_blank');
    const customer = document.querySelector('.ledger-header h2').textContent;
    
    printWindow.document.write(`
        <html>
        <head>
            <title>Customer Ledger - ${customer}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                h1 { color: #138BA8; text-align: center; }
                table { width: 100%; border-collapse: collapse; margin-top: 20px; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; font-size: 12px; }
                th { background-color: #f8f9fa; font-weight: bold; }
                .amount { text-align: right; }
                .summary { margin-top: 20px; padding: 15px; background-color: #f8f9fa; }
            </style>
        </head>
        <body>
            <h1>${customer}</h1>
            <div class="summary">
                <strong>Summary:</strong><br>
                Opening Balance: ${document.getElementById('openingBalance').textContent}<br>
                Total Debit: ${document.getElementById('totalDebit').textContent}<br>
                Total Credit: ${document.getElementById('totalCredit').textContent}<br>
                Ending Balance: ${document.getElementById('endingBalance').textContent}
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Date</th>
                        <th>Inv.No</th>
                        <th>Trans Type</th>
                        <th>Item Name</th>
                        <th>Description</th>
                        <th>Qty</th>
                        <th>Rate</th>
                        <th>Credit</th>
                        <th>Debit</th>
                        <th>Balance</th>
                    </tr>
                </thead>
                <tbody>
    `);
    
    filteredLedgerData.forEach(transaction => {
        const date = new Date(transaction.date).toLocaleDateString('en-GB');
        const creditAmount = transaction.credit_amount > 0 ? transaction.credit_amount.toFixed(2) : '0';
        const debitAmount = transaction.debit_amount > 0 ? transaction.debit_amount.toFixed(2) : '0';
        
        printWindow.document.write(`
            <tr>
                <td>${date}</td>
                <td>${transaction.inv_no || '-'}</td>
                <td>${transaction.trans_type}</td>
                <td>${transaction.item_name || '-'}</td>
                <td>${transaction.description || '-'}</td>
                <td style="text-align: center;">${transaction.qty || '-'}</td>
                <td class="amount">${transaction.rate ? `Rs. ${transaction.rate.toFixed(2)}` : '-'}</td>
                <td class="amount">${creditAmount}</td>
                <td class="amount">${debitAmount}</td>
                <td class="amount">${transaction.balance.toFixed(2)} ${transaction.dr_cr}</td>
            </tr>
        `);
    });
    
    printWindow.document.write(`
                </tbody>
            </table>
        </body>
        </html>
    `);
    
    printWindow.document.close();
    printWindow.print();
}

function exportLedgerToExcel() {
    // Create CSV data
    let csvContent = "Date,Inv.No,Trans Type,Item Name,Description,Qty,Rate,Credit Amount,Debit Amount,Balance,DR/CR\n";
    
    filteredLedgerData.forEach(transaction => {
        const date = new Date(transaction.date).toLocaleDateString('en-GB');
        const creditAmount = transaction.credit_amount > 0 ? transaction.credit_amount.toFixed(2) : '0';
        const debitAmount = transaction.debit_amount > 0 ? transaction.debit_amount.toFixed(2) : '0';
        
        csvContent += `"${date}","${transaction.inv_no || ''}","${transaction.trans_type}","${transaction.item_name || ''}","${transaction.description || ''}","${transaction.qty || ''}","${transaction.rate || ''}","${creditAmount}","${debitAmount}","${transaction.balance.toFixed(2)}","${transaction.dr_cr}"\n`;
    });
    
    // Create and download file
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);
    link.setAttribute('href', url);
    link.setAttribute('download', `customer_ledger_${Date.now()}.csv`);
    link.style.visibility = 'hidden';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Utility Functions
function showLedgerLoading(show) {
    const tbody = document.getElementById('ledgerTableBody');
    if (show) {
        tbody.innerHTML = `
            <tr>
                <td colspan="9" style="text-align: center; padding: 40px;">
                    <div class="spinner-border text-primary" role="status">
                        <span class="visually-hidden">Loading...</span>
                    </div>
                    <div style="margin-top: 10px;">Loading ledger data...</div>
                </td>
            </tr>
        `;
    }
}

function showLedgerError(message) {
    const tbody = document.getElementById('ledgerTableBody');
    tbody.innerHTML = `
        <tr>
            <td colspan="9" style="text-align: center; padding: 40px; color: #e74c3c;">
                <i class="fas fa-exclamation-triangle" style="font-size: 48px; margin-bottom: 16px; display: block;"></i>
                ${message}
            </td>
        </tr>
    `;
}

// Event Listeners
document.addEventListener('DOMContentLoaded', function() {
    // Filter event listeners
    document.getElementById('dateFrom').addEventListener('change', filterLedgerData);
    document.getElementById('dateTo').addEventListener('change', filterLedgerData);
    document.getElementById('transTypeFilter').addEventListener('change', filterLedgerData);
    document.getElementById('searchLedger').addEventListener('input', filterLedgerData);
    
    // Close modal when clicking outside
    window.addEventListener('click', function(event) {
        const modal = document.getElementById('customerLedgerModal');
        if (event.target === modal) {
            closeCustomerLedger();
        }
    });
});