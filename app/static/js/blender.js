// app/static/js/blender.js

class BlenderAnalyzer {
    constructor() {
        this.bindElements();
        this.bindEvents();
        this.initialize();
    }

    bindElements() {
        this.scanButton = document.getElementById('startScan');
        this.resultsDiv = document.getElementById('scanResults');
        this.resultsTitle = document.getElementById('resultsTitle');
        this.scanActions = document.getElementById('scanActions');
        this.lastScanElement = document.getElementById('blenderLastScanTime');
    }

    bindEvents() {
        this.scanButton?.addEventListener('click', () => this.startSystemScan());
        document.addEventListener('DOMContentLoaded', () => {
            const currentView = document.querySelector('.nav-tab.active')?.id.replace('View', '');
            if (currentView === 'compare') {
                this.loadPayloadsForComparison();
            } else if (window.initialScanData) {
                this.updateResults({ processes: window.initialScanData });
            }
        });
    }

    initialize() {
        if (!window.initialScanData && !window.lastScanDate) {
            this.showError('No system scan found. Please run a system scan.');
        } else {
            if (window.initialScanData) {
                this.updateResults({ processes: window.initialScanData });
            }
            if (window.lastScanDate) {
                this.updateLastScanTime(window.lastScanDate);
            }
        }
    }

    switchView(view) {
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('text-red-400', 'border-red-400');
            tab.classList.add('text-gray-400', 'border-transparent');
        });

        document.getElementById(`${view}View`).classList.add('text-red-400', 'border-red-400');

        if (view === 'scan') {
            this.scanActions.classList.remove('hidden');
            this.resultsDiv.innerHTML = '';

            this.resultsTitle.textContent = 'System Scan Results';

            if (!window.initialScanData && !window.lastScanDate) {
                this.showError('No system scan found. Please run a system scan.');
            } else {
                this.updateResults({ processes: window.initialScanData });
            }
        } else {
            this.scanActions.classList.add('hidden');
            this.resultsTitle.textContent = 'Payload Comparison';
            this.loadPayloadsForComparison();
        }
    }

    async startSystemScan() {
        this.scanButton.disabled = true;
        this.scanButton.classList.add('opacity-50');
        this.showLoading('Creating new system scan...');

        try {
            const response = await fetch('/blender', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ operation: 'scan' })
            });
            
            const data = await response.json();
            
            if (data.status === 'success') {
                this.updateResults(data);
                const currentTime = new Date().toISOString();
                window.lastScanDate = currentTime;
                this.updateLastScanTime(currentTime);
            } else {
                this.showError(data.error || 'Operation failed');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to start system scan');
        } finally {
            this.scanButton.disabled = false;
            this.scanButton.classList.remove('opacity-50');
        }
    }

    updateResults(data) {
        const processes = typeof data.processes === 'string' 
            ? JSON.parse(data.processes) 
            : data.processes;

        if (!processes || processes.length === 0) {
            this.resultsDiv.innerHTML = `
                <div class="text-center text-gray-400">
                    <p>No issues detected in system scan</p>
                </div>
            `;
            return;
        }

        processes.sort((a, b) => b.iocs.length - a.iocs.length);
        this.displayProcessResults(processes);
    }

    displayProcessResults(processes) {
        let resultsHTML = this.generateProcessTableHeader();
        resultsHTML += this.generateProcessTableBody(processes);
        this.resultsDiv.innerHTML = resultsHTML;
    }

    generateProcessTableHeader() {
        return `
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">
                                Process Name
                            </th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">
                                PID
                            </th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">
                                Findings Count
                            </th>
                        </tr>
                    </thead>
                    <tbody class="bg-gray-900 divide-y divide-gray-700">
        `;
    }

    generateProcessTableBody(processes) {
        const rows = processes.map((process, index) => {
            const rowClass = index % 2 === 0 ? 'bg-gray-900' : 'bg-gray-800/50';
            const rowId = `process-${process.pid}`;
            
            return `
                <tr class="${rowClass} hover:bg-gray-700/50 transition-colors cursor-pointer" 
                    onclick="blenderAnalyzer.toggleProcessDetails('${rowId}')" 
                    data-pid="${process.pid}">
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-200">
                        <div class="flex items-center gap-2">
                            <svg class="w-4 h-4 transform transition-transform" id="arrow-${rowId}" 
                                 fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                      d="M9 5l7 7-7 7"/>
                            </svg>
                            ${process.process_name}
                        </div>
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                        ${process.pid}
                    </td>
                    <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                        ${process.iocs.length} findings
                    </td>
                </tr>
                <tr id="${rowId}" class="hidden">
                    <td colspan="3" class="px-6 py-4 bg-gray-800/30">
                        <div class="space-y-2">
                            ${process.iocs.map(ioc => this.formatIoc(ioc)).join('')}
                        </div>
                    </td>
                </tr>
            `;
        }).join('');

        return rows + `
                </tbody>
            </table>
        </div>
        `;
    }

    toggleProcessDetails(rowId) {
        const detailsRow = document.getElementById(rowId);
        const arrow = document.getElementById(`arrow-${rowId}`);
        
        if (detailsRow.classList.contains('hidden')) {
            detailsRow.classList.remove('hidden');
            arrow.classList.add('rotate-90');
        } else {
            detailsRow.classList.add('hidden');
            arrow.classList.remove('rotate-90');
        }
    }

    formatIoc(ioc) {
        if (ioc.type === 'HSB Detection' || (ioc.severity && !['HIGH', 'MEDIUM'].includes(ioc.severity))) {
            return this.formatHSBIoc(ioc);
        }
        if (ioc.severity && ['HIGH', 'MEDIUM'].includes(ioc.severity)) {
            return this.formatHollowsHunterIoc(ioc);
        }
        
        const parts = ioc.description.split('|').map(p => p.trim());
        return parts.length >= 2 ? this.formatMonetaIocWithAddress(ioc, parts) : this.formatSimpleIoc(ioc);
    }

    formatHSBIoc(ioc) {
        return `
            <div class="border-l-2 border-yellow-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-yellow-300 font-medium">${ioc.type}</span>
                        ${ioc.severity ? `<span class="text-xs text-gray-500">[${ioc.severity}]</span>` : ''}
                    </div>
                    <div class="text-gray-400 text-sm">
                        ${ioc.description}
                    </div>
                    ${ioc.thread_info ? `
                        <div class="text-gray-500 text-xs">
                            ${ioc.thread_info}
                        </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    formatHollowsHunterIoc(ioc) {
        return `
            <div class="border-l-2 border-blue-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-blue-300 font-medium">${ioc.type}</span>
                        <span class="text-xs text-gray-500">[${ioc.severity}]</span>
                    </div>
                    <div class="text-gray-400 text-sm">
                        ${ioc.description}
                    </div>
                </div>
            </div>
        `;
    }

    formatMonetaIocWithAddress(ioc, parts) {
        const addrInfo = parts[0].split(':').map(p => p.trim());
        const [address, size] = addrInfo;
        
        return `
            <div class="border-l-2 border-pink-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-pink-300 font-medium">${ioc.type}</span>
                    </div>
                    <div class="grid grid-cols-2 gap-4 text-sm">
                        <div class="text-gray-400">
                            <span class="text-gray-500">Address:</span> ${address}
                        </div>
                        <div class="text-gray-400">
                            <span class="text-gray-500">Size:</span> ${size}
                        </div>
                    </div>
                    ${parts.slice(1).map(part => `
                        <div class="text-gray-400 text-sm">
                            ${part}
                        </div>
                    `).join('')}
                </div>
            </div>
        `;
    }

    formatSimpleIoc(ioc) {
        return `
            <div class="border-l-2 border-pink-300 pl-4 py-2">
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2">
                        <span class="text-pink-300 font-medium">${ioc.type}</span>
                    </div>
                    <div class="text-gray-400 text-sm">
                        ${ioc.description}
                    </div>
                </div>
            </div>
        `;
    }

    async loadPayloadsForComparison() {
        this.showLoading('Loading available payloads...');

        try {
            const response = await fetch('/files');
            const data = await response.json();
            
            if (data.status === 'success') {
                this.displayPayloads(data.file_based.files);
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to load payloads');
        }
    }

    displayPayloads(files) {
        this.resultsDiv.innerHTML = `
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700">
                    <thead>
                        <tr>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">File name</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Risk factors</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Upload date</th>
                            <th class="px-6 py-3 bg-gray-800 text-left text-xs font-medium text-gray-300 tracking-wider">Action</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-800">
                        ${Object.entries(files).map(([id, file], index) => this.generatePayloadRow(file, index)).join('')}
                    </tbody>
                </table>
            </div>
        `;
    }

    generatePayloadRow(file, index) {
        const hasSystemScan = window.initialScanData !== undefined && window.initialScanData !== null;
        
        return `
            <tr class="${index % 2 === 0 ? 'bg-gray-900/30' : 'bg-gray-800/30'}">
                <td class="px-6 py-4">
                    <div class="flex flex-col">
                        <span class="text-gray-200">${file.filename}</span>
                        <span class="text-sm text-gray-500 font-mono">${file.md5}</span>
                    </div>
                </td>
                <td class="px-6 py-4 text-sm text-gray-400">
                    <div class="space-y-1">
                        ${file.risk_assessment.factors.map(factor => `
                            <div class="flex items-center gap-2">
                                <svg class="w-3 h-3 text-gray-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
                                </svg>
                                <span>${factor}</span>
                            </div>
                        `).join('')}
                    </div>
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-400">${file.upload_time}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    <button 
                        ${hasSystemScan ? `onclick="blenderAnalyzer.compareWithPayload('${file.md5}')"` : 'disabled'} 
                        class="px-3 py-1 ${hasSystemScan ? 'text-pink-400 border-pink-900/20 hover:bg-pink-500/10 cursor-pointer' : 'text-gray-500 border-gray-700 opacity-50 cursor-not-allowed'} border rounded-lg transition-colors"
                        ${!hasSystemScan ? 'title="Please run a system scan first"' : ''}>
                        Compare
                    </button>
                </td>
            </tr>
        `;
    }

    async compareWithPayload(hash) {
        this.showLoading('Comparing with payload...');
        try {
            const response = await fetch(`/blender?hash=${encodeURIComponent(hash)}`, {
                method: 'GET',
                headers: { 'Content-Type': 'application/json' }
            });
            
            const data = await response.json();
            
            if (data.error) {
                this.showError(data.error);
                return;
            }
            
            if (data.status === 'success' && data.result.matches?.length > 0) {
                this.displayComparisonResults(data, hash);
            } else {
                this.showError('No matching processes found above 50% confidence');
            }
        } catch (error) {
            console.error('Error:', error);
            this.showError('Failed to compare with payload');
        }
    }

    displayComparisonResults(data, hash) {
        const matches = data.result.matches[0].matches
            .filter(match => match.match_percentage >= 50)
            .sort((a, b) => b.match_percentage - a.match_percentage)

        const payloadIOCs = data.result.payload_processes[0].iocs;

        this.resultsDiv.innerHTML = `
            <div class="space-y-6">
                <div class="bg-gray-800/50 p-4 rounded-lg">
                    <h3 class="text-lg font-medium text-gray-200">Payload Analysis</h3>
                    <div class="text-sm text-gray-400 mb-4">Hash: ${hash}</div>
                    ${this.formatPayloadIOCs(payloadIOCs)}
                </div>

                <div class="bg-gray-800/50 p-4 rounded-lg">
                    <h3 class="text-lg font-medium text-gray-200">${matches.length} Matching Processes</h3>
                    <div class="space-y-4 mt-4">
                        ${matches.map(match => this.formatMatchResult(match, payloadIOCs)).join('')}
                    </div>
                </div>
            </div>
        `;
    }

    formatMatchResult(match, payloadIOCs) {
        return `
            <div class="border border-gray-700 rounded-lg p-4">
                <div class="flex items-center justify-between mb-4">
                    <div class="flex items-center gap-4">
                        <span class="text-2xl font-bold ${this.getMatchPercentageColor(match.match_percentage)}">
                            ${match.match_percentage}%
                        </span>
                        <div>
                            <h4 class="text-lg font-medium text-gray-200">${match.process_name}</h4>
                            <div class="text-sm text-gray-400">PID: ${match.pid}</div>
                        </div>
                    </div>
                </div>
                ${this.formatMatchedIOCs(match.matching_iocs, payloadIOCs)}
            </div>
        `;
    }

    getMatchPercentageColor(percentage) {
        if (percentage >= 90) return 'text-green-400';
        if (percentage >= 70) return 'text-yellow-400';
        return 'text-blue-400';
    }

    formatPayloadIOCs(iocs) {
        const groupedIOCs = this.groupIOCsByCategory(iocs);

        return `
            <div class="border-l-4 border-purple-500 pl-4">
                <div class="text-lg text-purple-400 mb-2">Original Payload IOCs</div>
                ${Object.entries(groupedIOCs).map(([category, categoryIOCs]) => this.formatIOCCategory(category, categoryIOCs)).join('')}
            </div>
        `;
    }

    formatIOCCategory(category, iocs) {
        return `
            <div class="mb-4">
                <h4 class="text-sm font-medium text-gray-300 mb-2">${category}</h4>
                <div class="space-y-2">
                    ${iocs.map(ioc => this.formatCategoryIOC(ioc)).join('')}
                </div>
            </div>
        `;
    }

    formatCategoryIOC(ioc) {
        return `
            <div class="bg-gray-800/30 rounded p-3">
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-sm font-medium ${this.getIOCSeverityColor(ioc.severity)}">
                        ${ioc.type}
                    </span>
                    ${ioc.severity ? 
                        `<span class="text-xs px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400">
                            ${ioc.severity}
                        </span>` 
                        : ''
                    }
                </div>
                <div class="text-sm text-gray-400 mt-1">
                    ${this.formatIOCDescription(ioc)}
                </div>
            </div>
        `;
    }

    formatMatchedIOCs(matchingIOCs, payloadIOCs) {
        const groupedMatchingIOCs = this.groupIOCsByCategory(matchingIOCs);
        const groupedPayloadIOCs = this.groupIOCsByCategory(payloadIOCs);
        const allCategories = new Set([...Object.keys(groupedMatchingIOCs), ...Object.keys(groupedPayloadIOCs)]);

        let html = '';
        allCategories.forEach(category => {
            const matchingCategoryIOCs = groupedMatchingIOCs[category] || [];
            const payloadCategoryIOCs = groupedPayloadIOCs[category] || [];

            html += this.formatMatchedIOCCategory(category, matchingCategoryIOCs, payloadCategoryIOCs);
        });
        return html;
    }

    formatMatchedIOCCategory(category, matchingIOCs, payloadIOCs) {
        return `
            <div class="mb-6">
                <h4 class="text-sm font-medium text-gray-300 mb-2">${category}</h4>
                <div class="grid grid-cols-2 gap-4">
                    ${this.formatIOCComparison(matchingIOCs, payloadIOCs)}
                </div>
            </div>
        `;
    }

    formatIOCComparison(matchingIOCs, payloadIOCs) {
        return `
            <div class="bg-blue-900/20 rounded-lg p-4">
                <div class="text-sm font-medium text-pink-400 mb-2">Process IOCs</div>
                <div class="space-y-2">
                    ${matchingIOCs.map(ioc => this.formatMatchingIOC(ioc)).join('')}
                </div>
            </div>
            <div class="bg-purple-900/20 rounded-lg p-4">
                <div class="text-sm font-medium text-purple-400 mb-2">Payload IOCs</div>
                <div class="space-y-2">
                    ${payloadIOCs.map(ioc => this.formatPayloadIOC(ioc)).join('')}
                </div>
            </div>
        `;
    }


    formatMatchingIOC(ioc) {
        return `
            <div class="bg-gray-800/30 rounded p-3">
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-sm font-medium ${this.getIOCSeverityColor(ioc.severity)}">${ioc.type}</span>
                    ${ioc.severity ? 
                        `<span class="text-xs px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400">
                            ${ioc.severity}
                        </span>` 
                        : ''
                    }
                </div>
                ${ioc.match_score < 1 ? 
                    `<div class="text-xs text-amber-400/70 mb-1">
                        Match confidence: ${Math.round(ioc.match_score * 100)}%
                    </div>` 
                    : ''
                }
                <div class="text-sm text-gray-400 mt-1">
                    ${this.formatIOCDescription(ioc)}
                </div>
            </div>
        `;
    }

    formatPayloadIOC(ioc) {
        return `
            <div class="bg-gray-800/30 rounded p-3">
                <div class="flex items-center gap-2 mb-1">
                    <span class="text-sm font-medium ${this.getIOCSeverityColor(ioc.severity)}">${ioc.type}</span>
                    ${ioc.severity ? 
                        `<span class="text-xs px-2 py-0.5 rounded-full bg-gray-700/50 text-gray-400">
                            ${ioc.severity}
                        </span>` 
                        : ''
                    }
                </div>
                <div class="text-sm text-gray-400 mt-1">
                    ${this.formatIOCDescription(ioc)}
                </div>
            </div>
        `;
    }

    getIOCSeverityColor(severity) {
        switch(severity) {
            case 'HIGH': return 'text-red-400';
            case 'MEDIUM':
            case 'MID': return 'text-yellow-400';
            default: return 'text-blue-400';
        }
    }

    formatIOCDescription(ioc) {
        const cleanDescription = ioc.system_description || ioc.description;
        let formattedDesc = cleanDescription.replace(/0x[0-9a-fA-F]+/g, '[addr]');
        
        return formattedDesc.replace(/([A-Z]:\\[^|]+\\)([^|]+)(\s*\||$)/g, (match, path, filename) => {
            return path.length > 30 ? `...\\${filename}${match.endsWith('|') ? ' |' : ''}` : match;
        });
    }

    groupIOCsByCategory(iocs) {
        return iocs.reduce((acc, ioc) => {
            const category = ioc.dll || 'Process Level';
            if (!acc[category]) {
                acc[category] = [];
            }
            acc[category].push(ioc);
            return acc;
        }, {});
    }

    showLoading(message) {
        this.resultsDiv.innerHTML = `
            <div class="flex items-center justify-center text-gray-400">
                <svg class="animate-spin h-5 w-5 mr-3" viewBox="0 0 24 24">
                    <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4" fill="none"></circle>
                    <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>${message}</span>
            </div>
        `;
    }

    showError(message) {
        this.resultsDiv.innerHTML = `
            <div class="flex items-center justify-center text-red-400">
                <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <span>${message}</span>
            </div>
        `;
    }

    updateLastScanTime(timestamp = null) {
        if (!this.lastScanElement) return;

        const date = timestamp ? new Date(timestamp) : new Date();
        const formattedDate = this.formatDateTime(date);
        
        this.lastScanElement.innerHTML = `
            <div class="flex items-center gap-2">
                <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                        d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"/>
                </svg>
                <span>Last scan: ${formattedDate}</span>
            </div>
        `;
    }

    formatDateTime(date) {
        const pad = (num) => String(num).padStart(2, '0');
        
        const year = date.getFullYear();
        const month = pad(date.getMonth() + 1);
        const day = pad(date.getDate());
        const hours = pad(date.getHours());
        const minutes = pad(date.getMinutes());
        const seconds = pad(date.getSeconds());
        
        return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
    }
}

// Initialize the analyzer
const blenderAnalyzer = new BlenderAnalyzer();

// Export for global access
window.blenderAnalyzer = blenderAnalyzer;