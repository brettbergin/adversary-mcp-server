// Dashboard JavaScript Functionality
document.addEventListener('DOMContentLoaded', function() {
    console.log('Adversary Dashboard loaded');

    // Auto-refresh functionality
    let refreshInterval = null;
    const autoRefreshToggle = document.getElementById('autoRefreshToggle');
    const refreshIntervalSelect = document.getElementById('refreshInterval');

    // Load saved preferences from localStorage
    const savedAutoRefresh = localStorage.getItem('autoRefresh');
    const savedInterval = localStorage.getItem('refreshInterval');

    if (savedAutoRefresh === 'true') {
        autoRefreshToggle.checked = true;
        refreshIntervalSelect.disabled = false;
        if (savedInterval) {
            refreshIntervalSelect.value = savedInterval;
        }
        startAutoRefresh();
    }

    // Toggle auto-refresh on/off
    autoRefreshToggle.addEventListener('change', function() {
        const isEnabled = this.checked;
        refreshIntervalSelect.disabled = !isEnabled;
        localStorage.setItem('autoRefresh', isEnabled.toString());

        if (isEnabled) {
            startAutoRefresh();
        } else {
            stopAutoRefresh();
        }
    });

    // Change refresh interval
    refreshIntervalSelect.addEventListener('change', function() {
        const interval = parseInt(this.value);
        localStorage.setItem('refreshInterval', interval.toString());

        if (autoRefreshToggle.checked) {
            stopAutoRefresh();
            startAutoRefresh();
        }
    });

    function startAutoRefresh() {
        const interval = parseInt(refreshIntervalSelect.value);
        refreshInterval = setInterval(() => {
            console.log(`Auto-refreshing dashboard every ${interval/1000} seconds`);
            location.reload();
        }, interval);
    }

    function stopAutoRefresh() {
        if (refreshInterval) {
            clearInterval(refreshInterval);
            refreshInterval = null;
        }
    }
});

function initializeScanPerformanceChart(data) {
    const ctx = document.getElementById('scanPerformanceChart');
    if (!ctx) return;

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Semgrep Analysis', 'LLM Analysis', 'Validation'],
            datasets: [{
                data: [data.semgrep || 0, data.llm || 0, data.validation || 0],
                backgroundColor: [
                    '#2563eb',
                    '#f59e0b',
                    '#22c55e'
                ],
                borderWidth: 2,
                borderColor: '#ffffff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        padding: 20,
                        usePointStyle: true
                    }
                },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const label = context.label || '';
                            const value = context.parsed || 0;
                            return `${label}: ${value.toFixed(1)}ms`;
                        }
                    }
                }
            }
        }
    });
}

// Utility functions for data formatting
function formatDuration(ms) {
    if (!ms || ms < 0) return 'N/A';
    if (ms < 1000) return `${ms.toFixed(1)}ms`;
    if (ms < 60000) return `${(ms/1000).toFixed(1)}s`;
    const minutes = Math.floor(ms / 60000);
    const seconds = ((ms % 60000) / 1000).toFixed(1);
    return `${minutes}m ${seconds}s`;
}

function formatSize(bytes) {
    if (!bytes || bytes < 0) return 'N/A';
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
        size /= 1024;
        unitIndex++;
    }

    return `${size.toFixed(1)} ${units[unitIndex]}`;
}

function formatPercentage(value) {
    if (value === null || value === undefined) return 'N/A';
    return `${(value * 100).toFixed(1)}%`;
}
