/**
 * Log Analyzer JavaScript
 */

document.addEventListener('DOMContentLoaded', function() {
    // Helper functions for log analysis

    /**
     * Format timestamp for better display
     * @param {string} timestamp - The timestamp to format
     * @returns {string} - Formatted timestamp
     */
    function formatTimestamp(timestamp) {
        if (!timestamp) return 'N/A';
        
        try {
            const date = new Date(timestamp);
            return date.toLocaleString();
        } catch (e) {
            return timestamp;
        }
    }

    /**
     * Add event listeners to copy button in entry details
     */
    function setupCopyButtons() {
        const copyButtons = document.querySelectorAll('.copy-btn');
        
        copyButtons.forEach(button => {
            button.addEventListener('click', function() {
                const textToCopy = this.getAttribute('data-content');
                
                navigator.clipboard.writeText(textToCopy).then(() => {
                    // Temporarily change button text to indicate successful copy
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="bi bi-check"></i> Copied';
                    
                    setTimeout(() => {
                        this.innerHTML = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Copy failed:', err);
                    alert('Failed to copy text. Please try again.');
                });
            });
        });
    }

    /**
     * Set up filtering for the entries table
     */
    function setupTableFilters() {
        const filterInput = document.getElementById('filterEntries');
        if (!filterInput) return;
        
        filterInput.addEventListener('input', function() {
            const filterValue = this.value.toLowerCase();
            const tableRows = document.querySelectorAll('#entriesTable tbody tr');
            
            tableRows.forEach(row => {
                const text = row.textContent.toLowerCase();
                if (text.includes(filterValue)) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });
        });
    }

    /**
     * Initialize event handlers for the application
     */
    function initEventHandlers() {
        // Format all timestamps on the page
        document.querySelectorAll('.format-timestamp').forEach(element => {
            element.textContent = formatTimestamp(element.textContent);
        });
        
        // Set up copy buttons if any
        setupCopyButtons();
        
        // Set up table filters if any
        setupTableFilters();
    }

    // Initialize the application
    initEventHandlers();
});