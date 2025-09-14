// NetAddr WASM Demo Application
import init, { NetaddrAPI } from './netaddr.js';

let netaddr = null;
let isLoading = true;

// Initialize the WASM module
async function initWasm() {
    try {
        await init();
        netaddr = new NetaddrAPI();

        // Update UI to show ready state
        document.getElementById('loadingStatus').classList.add('d-none');
        document.getElementById('readyStatus').classList.remove('d-none');
        isLoading = false;

        console.log('NetAddr WASM module loaded successfully');
    } catch (error) {
        console.error('Failed to load NetAddr WASM module:', error);
        document.getElementById('loadingStatus').classList.add('d-none');
        document.getElementById('errorStatus').classList.remove('d-none');
        showError('Failed to load WASM module: ' + error.message);
    }
}

// Utility functions
function showError(message, containerId = null) {
    const errorHtml = `
        <div class="error-message fade-in">
            <i class="bi bi-exclamation-triangle me-2"></i>
            <strong>Error:</strong> ${message}
        </div>
    `;

    if (containerId) {
        document.getElementById(containerId).innerHTML = errorHtml;
    } else {
        // Show in the current active tab
        const activeTab = document.querySelector('.tab-pane.active');
        if (activeTab) {
            const resultDiv = activeTab.querySelector('[id$="Result"]');
            if (resultDiv) {
                resultDiv.innerHTML = errorHtml;
            }
        }
    }
}

function showSuccess(message, containerId) {
    const successHtml = `
        <div class="success-message fade-in">
            <i class="bi bi-check-circle me-2"></i>
            <strong>Success:</strong> ${message}
        </div>
    `;
    document.getElementById(containerId).innerHTML = successHtml;
}

function checkWasmReady() {
    if (isLoading || !netaddr) {
        showError('WASM module is still loading. Please wait a moment and try again.');
        return false;
    }
    return true;
}

// IP Address Analysis
window.analyzeIP = function() {
    if (!checkWasmReady()) return;

    const input = document.getElementById('ipInput').value.trim();
    const resultDiv = document.getElementById('ipResult');

    if (!input) {
        showError('Please enter an IP address', 'ipResult');
        return;
    }

    try {
        const result = netaddr.getIPInfo(input);
        const data = JSON.parse(result);

        const html = `
            <div class="address-info fade-in">
                <div class="row mb-3">
                    <div class="col-md-6">
                        <h6 class="text-primary mb-3">
                            <i class="bi bi-info-circle me-2"></i>Address Information
                        </h6>
                    </div>
                    <div class="col-md-6 text-end">
                        <span class="badge badge-large ${data.version === 4 ? 'bg-primary' : 'bg-success'}">
                            IPv${data.version}
                        </span>
                    </div>
                </div>

                <div class="info-row">
                    <span class="info-label">Address:</span>
                    <span class="info-value">${data.address}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Hexadecimal:</span>
                    <span class="info-value hex-display">${data.hex}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Binary (bytes):</span>
                    <span class="info-value binary-display">[${data.binary.join(', ')}]</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Reverse DNS:</span>
                    <span class="info-value">${data.reverse_dns}</span>
                </div>

                <div class="row mt-3">
                    <div class="col-md-6">
                        <h6 class="text-secondary mb-2">Classification</h6>
                        <div class="d-flex flex-wrap gap-1">
                            ${data.is_private ? '<span class="badge bg-warning text-dark">Private</span>' : '<span class="badge bg-info">Public</span>'}
                            ${data.is_loopback ? '<span class="badge bg-secondary">Loopback</span>' : ''}
                            ${data.is_multicast ? '<span class="badge bg-primary">Multicast</span>' : ''}
                            ${data.is_link_local ? '<span class="badge bg-success">Link-Local</span>' : ''}
                            ${data.is_unspecified ? '<span class="badge bg-dark">Unspecified</span>' : ''}
                        </div>
                    </div>
                </div>
            </div>
        `;

        resultDiv.innerHTML = html;
    } catch (error) {
        showError(error.message || error, 'ipResult');
    }
};

// Network Analysis
window.analyzeNetwork = function() {
    if (!checkWasmReady()) return;

    const input = document.getElementById('networkInput').value.trim();
    const resultDiv = document.getElementById('networkResult');

    if (!input) {
        showError('Please enter a network in CIDR notation', 'networkResult');
        return;
    }

    try {
        const result = netaddr.parseNetwork(input);
        const data = JSON.parse(result);

        const html = `
            <div class="address-info fade-in">
                <div class="row mb-3">
                    <div class="col-md-8">
                        <h6 class="text-primary mb-0">
                            <i class="bi bi-diagram-2 me-2"></i>Network Information
                        </h6>
                    </div>
                    <div class="col-md-4 text-end">
                        <span class="badge badge-large bg-primary">/${data.prefix_len}</span>
                    </div>
                </div>

                <div class="info-row">
                    <span class="info-label">Network:</span>
                    <span class="info-value">${data.network}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Network Address:</span>
                    <span class="info-value">${data.network_address}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Broadcast Address:</span>
                    <span class="info-value">${data.broadcast_address}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Netmask:</span>
                    <span class="info-value">${data.netmask}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Host Count:</span>
                    <span class="info-value">${data.num_hosts}</span>
                </div>

                <div class="mt-3">
                    <small class="text-muted">${data.subnets}</small>
                </div>
            </div>
        `;

        resultDiv.innerHTML = html;
    } catch (error) {
        showError(error.message || error, 'networkResult');
    }
};

// MAC Address Analysis
window.analyzeMAC = function() {
    if (!checkWasmReady()) return;

    const input = document.getElementById('macInput').value.trim();
    const resultDiv = document.getElementById('macResult');

    if (!input) {
        showError('Please enter a MAC address', 'macResult');
        return;
    }

    try {
        const result = netaddr.parseMAC(input);
        const data = JSON.parse(result);

        const html = `
            <div class="address-info fade-in">
                <div class="row mb-3">
                    <div class="col-md-8">
                        <h6 class="text-primary mb-0">
                            <i class="bi bi-ethernet me-2"></i>MAC Address Information
                        </h6>
                    </div>
                    <div class="col-md-4 text-end">
                        <span class="badge badge-large bg-success">${data.type}</span>
                    </div>
                </div>

                <div class="info-row">
                    <span class="info-label">Address:</span>
                    <span class="info-value">${data.address}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">OUI (hex):</span>
                    <span class="info-value hex-display">${data.oui}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Length:</span>
                    <span class="info-value">${data.length} bytes</span>
                </div>

                <div class="info-row">
                    <span class="info-label">Binary (bytes):</span>
                    <span class="info-value binary-display">[${data.bytes.join(', ')}]</span>
                </div>

                <div class="row mt-3">
                    <div class="col-12">
                        <h6 class="text-secondary mb-2">Properties</h6>
                        <div class="d-flex flex-wrap gap-1">
                            ${data.is_unicast ? '<span class="badge bg-primary">Unicast</span>' : '<span class="badge bg-warning text-dark">Not Unicast</span>'}
                            ${data.is_multicast ? '<span class="badge bg-info">Multicast</span>' : ''}
                            ${data.is_universal ? '<span class="badge bg-success">Universal</span>' : '<span class="badge bg-secondary">Local</span>'}
                        </div>
                    </div>
                </div>
            </div>
        `;

        resultDiv.innerHTML = html;
    } catch (error) {
        showError(error.message || error, 'macResult');
    }
};

// IP Set Operations
window.createIPSet = function() {
    if (!checkWasmReady()) return;

    const input = document.getElementById('ipSetInput').value.trim();
    const resultDiv = document.getElementById('toolsResult');

    if (!input) {
        showError('Please enter IP addresses or networks separated by commas', 'toolsResult');
        return;
    }

    try {
        const result = netaddr.createIPSet(input);

        const html = `
            <div class="success-message fade-in">
                <i class="bi bi-collection me-2"></i>
                <strong>IP Set Created:</strong> ${result}
            </div>
            <div class="mt-3">
                <h6 class="text-secondary">Input addresses/networks:</h6>
                <div class="code-block">
                    ${input.split(',').map(addr => addr.trim()).join('\\n')}
                </div>
            </div>
        `;

        resultDiv.innerHTML = html;
    } catch (error) {
        showError(error.message || error, 'toolsResult');
    }
};

// Navigation between IP addresses
window.getNextIP = function() {
    if (!checkWasmReady()) return;

    const input = document.getElementById('ipInput').value.trim();
    if (!input) {
        showError('Please enter an IP address first', 'ipResult');
        return;
    }

    try {
        const nextIP = netaddr.getNextIP(input);
        document.getElementById('ipInput').value = nextIP;
        analyzeIP();
    } catch (error) {
        showError(error.message || error, 'ipResult');
    }
};

window.getPrevIP = function() {
    if (!checkWasmReady()) return;

    const input = document.getElementById('ipInput').value.trim();
    if (!input) {
        showError('Please enter an IP address first', 'ipResult');
        return;
    }

    try {
        const prevIP = netaddr.getPrevIP(input);
        document.getElementById('ipInput').value = prevIP;
        analyzeIP();
    } catch (error) {
        showError(error.message || error, 'ipResult');
    }
};

// Subnet operation
window.subnetNetwork = function() {
    if (!checkWasmReady()) return;

    const networkInput = document.getElementById('networkInput').value.trim();
    const prefixInput = document.getElementById('subnetPrefix').value;

    if (!networkInput) {
        showError('Please enter a network first', 'networkResult');
        return;
    }

    if (!prefixInput || isNaN(prefixInput)) {
        showError('Please enter a valid subnet prefix length', 'networkResult');
        return;
    }

    try {
        const result = netaddr.subnetNetwork(networkInput, parseInt(prefixInput));
        const data = JSON.parse(result);

        const html = `
            <div class="address-info fade-in">
                <h6 class="text-primary mb-3">
                    <i class="bi bi-diagram-3 me-2"></i>Subnet Operation Result
                </h6>

                <div class="info-row">
                    <span class="info-label">Original Network:</span>
                    <span class="info-value">${data.original}</span>
                </div>

                <div class="info-row">
                    <span class="info-label">New Prefix:</span>
                    <span class="info-value">/${data.new_prefix}</span>
                </div>

                <div class="mt-3">
                    <h6 class="text-secondary mb-2">Generated Subnets (showing first ${Math.min(data.subnets.length, 20)}):</h6>
                    <div class="row">
                        ${data.subnets.slice(0, 20).map(subnet => `
                            <div class="col-md-6 mb-2">
                                <div class="subnet-item" onclick="setNetworkExample('${subnet}')">${subnet}</div>
                            </div>
                        `).join('')}
                    </div>
                    ${data.subnets.length > 20 ? `<small class="text-muted">... and ${data.subnets.length - 20} more subnets</small>` : ''}
                </div>
            </div>
        `;

        document.getElementById('networkResult').innerHTML = html;
    } catch (error) {
        showError(error.message || error, 'networkResult');
    }
};

// Example setters
window.setExample = function(example) {
    document.getElementById('ipInput').value = example;
    analyzeIP();
};

window.setNetworkExample = function(example) {
    document.getElementById('networkInput').value = example;
    analyzeNetwork();
};

window.setMACExample = function(example) {
    document.getElementById('macInput').value = example;
    analyzeMAC();
};

window.setIPSetExample = function() {
    const example = '192.168.1.1,10.0.0.0/24,172.16.1.10,192.168.0.0/16';
    document.getElementById('ipSetInput').value = example;
    createIPSet();
};

// Add Enter key support for inputs
document.addEventListener('DOMContentLoaded', function() {
    document.getElementById('ipInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') analyzeIP();
    });

    document.getElementById('networkInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') analyzeNetwork();
    });

    document.getElementById('macInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') analyzeMAC();
    });

    document.getElementById('ipSetInput').addEventListener('keypress', function(e) {
        if (e.key === 'Enter') createIPSet();
    });
});

// Initialize the WASM module when the page loads
initWasm();