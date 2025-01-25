// app/static/js/upload.js

// Upload configurations
const UPLOAD_CONFIG = {
    maxFileSize: 16 * 1024 * 1024, // 16MB
    toastDuration: 3000,
    transitionDelay: 300,
    fadeDelay: 50
};

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    const elements = {
        dropZone: document.getElementById('dropZone'),
        fileInput: document.getElementById('fileInput'),
        uploadStatus: document.getElementById('uploadStatus'),
        uploadArea: document.getElementById('uploadArea'),
        fileAnalysisArea: document.getElementById('fileAnalysisArea'),
        fileName: document.getElementById('fileName'),
        fileSize: document.getElementById('fileSize'),
        fileType: document.getElementById('fileType'),
        fileFormat: document.getElementById('fileFormat'),
        fileCategory: document.getElementById('fileCategory'),
        fileEntropy: document.getElementById('fileEntropy'),
        uploadTime: document.getElementById('uploadTime'),
        md5Hash: document.getElementById('md5Hash'),
        sha256Hash: document.getElementById('sha256Hash'),
        fileSpecificInfo: document.getElementById('fileSpecificInfo'),
        step1Circle: document.getElementById('step1Circle'),
        step1Text: document.getElementById('step1Text'),
        step2Circle: document.getElementById('step2Circle'),
        step2Text: document.getElementById('step2Text'),
        progressLine: document.getElementById('progressLine'),
        toastContainer: document.getElementById('toastContainer'),
        entropyBar: document.getElementById('entropyBar'),
        entropyNotes: document.getElementById('entropyNotes'),
        detectionRisk: document.getElementById('detectionRisk'),
        peInfo: document.getElementById('peInfo'),
        sectionsList: document.getElementById('sectionsList'),
        detectionNotes: document.getElementById('detectionNotes'),
        officeInfo: document.getElementById('officeInfo'),
        macroStatus: document.getElementById('macroStatus'),
        checksumInfo: document.getElementById('checksumInfo'),
        checksumStatus: document.getElementById('checksumStatus'),
        storedChecksum: document.getElementById('storedChecksum'),
        calculatedChecksum: document.getElementById('calculatedChecksum'),
        checksumNotes: document.getElementById('checksumNotes'),
        // New suspicious imports elements
        suspiciousImports: document.getElementById('suspiciousImports'),
        suspiciousImportsList: document.getElementById('suspiciousImportsList'),
        suspiciousImportsCount: document.getElementById('suspiciousImportsCount'),
        suspiciousImportsSummary: document.getElementById('suspiciousImportsSummary')
        
    };

    let currentFileHash = null;
    let dragCounter = 0;

    // Event Listeners
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        elements.dropZone.addEventListener(eventName, preventDefaults, false);
        document.body.addEventListener(eventName, preventDefaults, false);
    });

    elements.dropZone.addEventListener('dragenter', () => {
        dragCounter++;
        if (dragCounter === 1) highlight();
    });

    elements.dropZone.addEventListener('dragleave', () => {
        dragCounter--;
        if (dragCounter === 0) unhighlight();
    });

    elements.dropZone.addEventListener('drop', (e) => {
        dragCounter = 0;
        unhighlight();
        handleDrop(e);
    });

    elements.fileInput.addEventListener('change', handleFiles);

    // Utility Functions
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight() {
        const label = elements.dropZone.querySelector('label');
        const icon = elements.dropZone.querySelector('.upload-icon');

        label.classList.add('scale-[1.02]', 'border-red-500/50');
        icon.classList.add('scale-110');
    }

    function updateEntropyAnalysis(fileInfo) {
        if (fileInfo.entropy_analysis) {
            const entropyPercentage = (fileInfo.entropy / 8) * 100;
            
            elements.entropyBar.style.width = `${entropyPercentage}%`;
            elements.entropyBar.className = `absolute h-full transition-all duration-300 ${
                fileInfo.entropy_analysis.detection_risk === 'High' ? 'bg-red-500' :
                fileInfo.entropy_analysis.detection_risk === 'Medium' ? 'bg-yellow-500' : 
                'bg-green-500'
            }`;

            elements.detectionRisk.className = `px-3 py-1 text-sm rounded-full ${
                fileInfo.entropy_analysis.detection_risk === 'High' ? 'bg-red-500/10 text-red-500' :
                fileInfo.entropy_analysis.detection_risk === 'Medium' ? 'bg-yellow-500/10 text-yellow-500' :
                'bg-green-500/10 text-green-500'
            }`;
            elements.detectionRisk.textContent = `${fileInfo.entropy_analysis.detection_risk} Detection Risk`;

            if (fileInfo.entropy_analysis.notes.length > 0) {
                elements.entropyNotes.innerHTML = fileInfo.entropy_analysis.notes.map(note => `
                    <div class="flex items-center space-x-2">
                        <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                  d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                        </svg>
                        <span>${note}</span>
                    </div>
                `).join('');
            }
        }
    }

    function unhighlight() {
        const label = elements.dropZone.querySelector('label');
        const icon = elements.dropZone.querySelector('.upload-icon');

        label.classList.remove('scale-[1.02]', 'border-red-500/50');
        icon.classList.remove('scale-110');
    }

    function showToast(message, type = 'success') {
        const toast = document.createElement('div');
        const colors = {
            success: 'border-green-900/20 bg-green-500/10 text-green-500',
            error: 'border-red-900/20 bg-red-500/10 text-red-500',
            info: 'border-blue-900/20 bg-blue-500/10 text-blue-500'
        };

        toast.className = `flex items-center space-x-2 p-4 rounded-lg border ${colors[type]} transform translate-y-2 opacity-0 transition-all duration-300 text-base`;
        toast.innerHTML = `
            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2"
                    d="${type === 'success' ? 'M5 13l4 4L19 7' : 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z'}"/>
            </svg>
            <span>${message}</span>
        `;

        elements.toastContainer.appendChild(toast);
        requestAnimationFrame(() => {
            toast.classList.remove('translate-y-2', 'opacity-0');
        });

        setTimeout(() => {
            toast.classList.add('translate-y-2', 'opacity-0');
            setTimeout(() => toast.remove(), UPLOAD_CONFIG.fadeDelay);
        }, UPLOAD_CONFIG.toastDuration);
    }

    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function formatTimestamp(timestamp) {
        return new Date(timestamp).toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    function updateProgress(step, completed = false) {
        const stepCircle = step === 1 ? elements.step1Circle : elements.step2Circle;
        const stepText = step === 1 ? elements.step1Text : elements.step2Text;

        if (completed && step === 1) {
            stepCircle.classList.remove('bg-red-500/10', 'border-red-500', 'bg-black/50', 'border-gray-700');
            stepCircle.classList.add('bg-green-500/10', 'border-green-500');

            stepText.innerHTML = `
                <svg class="w-5 h-5 text-green-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/>
                </svg>
            `;

            elements.progressLine.classList.remove('to-gray-800');
            elements.progressLine.classList.add('to-red-500/20');

            elements.step2Circle.classList.remove('bg-black/50', 'border-gray-700');
            elements.step2Circle.classList.add('bg-red-500/10', 'border-red-500');
            elements.step2Text.classList.remove('text-gray-500');
            elements.step2Text.classList.add('text-red-500');
        }
    }
    // Add this function after your existing utility functions
    function getDetectionRiskColor(risk) {
        const colors = {
            'High': 'bg-red-500/10 text-red-500',
            'Medium': 'bg-yellow-500/10 text-yellow-500',
            'Low': 'bg-green-500/10 text-green-500'
        };
        return colors[risk] || colors['Low'];
    }
    // File Info Functions
    // Modify your renderFileTypeSpecificInfo function
    function renderFileTypeSpecificInfo(fileInfo) {
        // Hide both specific info sections by default
        elements.peInfo.classList.add('hidden');
        elements.officeInfo.classList.add('hidden');
        elements.suspiciousImports.classList.add('hidden');
        
        // Update entropy analysis
        if (fileInfo.entropy_analysis) {
            const entropyPercentage = (fileInfo.entropy / 8) * 100;
            elements.entropyBar.style.width = `${entropyPercentage}%`;
            elements.entropyBar.className = `absolute h-full transition-all duration-300 ${
                fileInfo.entropy_analysis.detection_risk === 'High' ? 'bg-red-500' :
                fileInfo.entropy_analysis.detection_risk === 'Medium' ? 'bg-yellow-500' : 'bg-green-500'
            }`;

            elements.detectionRisk.className = `px-3 py-1 text-sm rounded-full ${
                getDetectionRiskColor(fileInfo.entropy_analysis.detection_risk)
            }`;
            elements.detectionRisk.textContent = `${fileInfo.entropy_analysis.detection_risk} Detection Risk`;

            elements.entropyNotes.innerHTML = fileInfo.entropy_analysis.notes.map(note => `
                <div class="flex items-center space-x-2">
                    <svg class="w-4 h-4 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                            d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
                    </svg>
                    <span>${note}</span>
                </div>
            `).join('');
        }

        // Render PE-specific information
        if (fileInfo.pe_info) {
            elements.peInfo.classList.remove('hidden');
            const pe = fileInfo.pe_info;

            // Handle suspicious imports
            if (pe.suspicious_imports && pe.suspicious_imports.length > 0) {
                elements.suspiciousImports.classList.remove('hidden');
                elements.suspiciousImportsCount.textContent = `${pe.suspicious_imports.length} Found`;
                
                elements.suspiciousImportsList.innerHTML = pe.suspicious_imports.map(imp => `
                    <div class="border-b border-gray-800 last:border-b-0 pb-3">
                        <div class="flex items-center justify-between mb-2">
                            <div class="flex items-center space-x-2">
                                <span class="text-red-500 font-mono">${imp.dll}</span>
                                <span class="text-gray-400">→</span>
                                <span class="text-gray-300 font-mono">${imp.function}</span>
                            </div>
                            <span class="text-xs text-gray-500">Hint: ${imp.hint}</span>
                        </div>
                        <div class="flex items-center space-x-2">
                            <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                            </svg>
                            <span class="text-sm text-gray-400">${imp.note}</span>
                        </div>
                    </div>
                `).join('');

                elements.suspiciousImportsSummary.textContent = 
                    `Found ${pe.suspicious_imports.length} potentially suspicious imports that may indicate malicious capabilities.`;
            }

            // Add checksum info display
            if (pe.checksum_info) {
                elements.checksumInfo.classList.remove('hidden');
                elements.storedChecksum.textContent = pe.checksum_info.stored_checksum;
                elements.calculatedChecksum.textContent = pe.checksum_info.calculated_checksum;
                
                // Set checksum status
                elements.checksumStatus.className = `px-3 py-1 text-sm rounded-full ${
                    pe.checksum_info.is_valid ? 'bg-green-500/10 text-green-500' : 'bg-red-500/10 text-red-500'
                }`;
                elements.checksumStatus.textContent = pe.checksum_info.is_valid ? 'Valid' : 'Invalid';
                
                // Add checksum notes if needed
                if (!pe.checksum_info.is_valid) {
                    elements.checksumNotes.innerHTML = `
                        <div class="flex items-center space-x-2">
                            <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                    d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                            </svg>
                            <span>Invalid checksum - Common in packed/modified payloads</span>
                        </div>
                    `;
                }
            } else {
                elements.checksumInfo.classList.add('hidden');
            }
            
            // Original PE info display
            html = `
                <div class="space-y-4">
                    <div class="flex items-center justify-between">
                        <h6 class="text-base font-medium text-gray-300">PE File Information</h6>
                        <span class="text-sm text-gray-400">File Type: ${pe.file_type}</span>
                        <span class="text-sm text-gray-400">Compile Time: ${pe.compile_time}</span>
                    </div>
                    <div class="grid grid-cols-3 gap-4">
                        <div>
                            <div class="text-base text-gray-400 mb-1">Machine Type</div>
                            <div class="text-base text-gray-300">${pe.machine_type}</div>
                        </div>
                        <div>
                            <div class="text-base text-gray-400 mb-1">Subsystem</div>
                            <div class="text-base text-gray-300">${pe.subsystem}</div>
                        </div>
                        <div>
                            <div class="text-base text-gray-400 mb-1">Entry Point</div>
                            <div class="text-base font-mono text-gray-300">${pe.entry_point}</div>
                        </div>
                    </div>
                    <div class="space-y-2">
                        <div class="flex items-center justify-between">
                            <span class="text-base text-gray-400">PE Sections</span>
                            <span class="text-sm text-gray-400">${pe.sections.length} sections</span>
                        </div>
                        <div class="flex flex-wrap gap-2">
                            ${pe.sections.map(section => {
                                const isStandardSection = ['.text', '.data', '.bss', '.rdata', '.edata', '.idata', '.pdata', '.reloc', '.rsrc', '.tls', '.debug'].includes(section.name);
                                return `
                                    <span class="px-2 py-1 text-sm ${isStandardSection ? 'bg-gray-900/50 text-gray-400' : 'bg-red-500/10 text-red-500'} rounded-lg border ${isStandardSection ? 'border-gray-800' : 'border-red-900/20'}">
                                        ${section.name}
                                    </span>
                                `;
                            }).join('')}
                        </div>
                    </div>
                    ${pe.imports && pe.imports.length > 0 ? `
                        <div class="space-y-2">
                            <div class="flex items-center justify-between">
                                <span class="text-base text-gray-400">Imported DLLs</span>
                                <span class="text-sm text-gray-400">${pe.imports.length} imports</span>
                            </div>
                            <div class="flex flex-wrap gap-2">
                                ${pe.imports.map(imp => `
                                    <span class="px-2 py-1 text-sm bg-gray-900/50 rounded-lg border border-gray-800 text-gray-400">
                                        ${imp}
                                    </span>
                                `).join('')}
                            </div>
                        </div>
                    ` : ''}
                </div>
            `;
            
            elements.fileSpecificInfo.innerHTML = html;
                    
            // New section analysis display
            elements.sectionsList.innerHTML = pe.sections.map(section => {
                const isStandardSection = ['.text', '.data', '.bss', '.rdata', '.edata', '.idata', '.pdata', '.reloc', '.rsrc', '.tls', '.debug'].includes(section.name);
                return `
                    <div class="border-b border-gray-800 pb-4 last:border-0">
                        <div class="flex items-center justify-between mb-2">
                            <div class="flex items-center space-x-3">
                                <span class="text-base ${isStandardSection ? 'text-gray-300' : 'text-red-500'}">${section.name}</span>
                                <span class="px-2 py-1 text-sm rounded ${
                                    section.entropy > 7.2 ? 'text-red-500 bg-red-500/10' :
                                    section.entropy > 6.8 ? 'text-yellow-500 bg-yellow-500/10' :
                                    'text-green-500 bg-green-500/10'
                                }">
                                    Entropy: ${section.entropy}
                                </span>
                            </div>
                            <span class="text-sm text-gray-400">${formatFileSize(section.size)}</span>
                        </div>
                        ${section.detection_notes.length > 0 ? `
                            <div class="text-sm text-gray-400">
                                ${section.detection_notes.map(note => `
                                    <div class="flex items-center space-x-2">
                                        <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                                        </svg>
                                        <span>${note}</span>
                                    </div>
                                `).join('')}
                            </div>
                        ` : ''}
                    </div>
                `;
            }).join('');

            // Render detection notes
            if (fileInfo.pe_info.detection_notes.length > 0) {
                elements.detectionNotes.innerHTML = fileInfo.pe_info.detection_notes.map(note => `
                    <div class="flex items-center space-x-2">
                        <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <span>${note}</span>
                    </div>
                `).join('');
            }
        } 
        // Render Office-specific information
        else if (fileInfo.office_info) {
            elements.officeInfo.classList.remove('hidden');
            const office = fileInfo.office_info;

            // Update macro status
            elements.macroStatus.className = `px-3 py-1 text-sm rounded-full ${
                office.has_macros ? 'bg-red-500/10 text-red-500' : 'bg-green-500/10 text-green-500'
            }`;
            elements.macroStatus.textContent = office.has_macros ? 'Macros Present' : 'No Macros';

            // Show detection notes if any
            if (office.detection_notes && office.detection_notes.length > 0) {
                elements.macroDetectionNotes.innerHTML = office.detection_notes.map(note => `
                    <div class="flex items-center space-x-2">
                        <svg class="w-4 h-4 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" 
                                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"/>
                        </svg>
                        <span>${note}</span>
                    </div>
                `).join('');
            }
        }
    }

    function updateFileInfo(fileInfo) {
        currentFileHash = fileInfo.md5;

        elements.fileName.textContent = fileInfo.original_name;
        elements.fileSize.textContent = formatFileSize(fileInfo.size);
        elements.fileType.textContent = fileInfo.extension.toUpperCase();
        elements.fileFormat.textContent = fileInfo.mime_type;
        elements.fileCategory.textContent = fileInfo.extension.toUpperCase();
        elements.fileEntropy.textContent = fileInfo.entropy;
        elements.uploadTime.textContent = formatTimestamp(fileInfo.upload_time);
        elements.md5Hash.textContent = fileInfo.md5;

        elements.sha256Hash.textContent = `${fileInfo.sha256.substring(0, 32)}...`;
        document.getElementById('sha256HashFull').textContent = fileInfo.sha256;

        renderFileTypeSpecificInfo(fileInfo);

        elements.uploadArea.classList.add('opacity-0', 'scale-95');
        setTimeout(() => {
            elements.uploadArea.classList.add('hidden');
            elements.fileAnalysisArea.classList.remove('hidden');
            setTimeout(() => {
                elements.fileAnalysisArea.classList.remove('opacity-0', 'scale-95');
            }, UPLOAD_CONFIG.fadeDelay);
        }, UPLOAD_CONFIG.transitionDelay);

        updateProgress(1, true);
    }

    // File Handling Functions
    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length > 1) {
            showToast('Please upload only one file at a time', 'error');
            return;
        }

        handleFiles({ target: { files } });
    }

    function handleFiles(e) {
        const file = e.target.files[0];
        if (!file) return;

        const extension = file.name.split('.').pop().toLowerCase();
        const allowedExtensions = Array.from(document.querySelectorAll('#dropZone .font-mono'))
            .map(el => el.textContent.trim().substring(1));

        if (!allowedExtensions.includes(extension)) {
            showToast(`Unsupported file type. Allowed types: ${allowedExtensions.join(', ')}`, 'error');
            return;
        }

        if (file.size > UPLOAD_CONFIG.maxFileSize) {
            showToast('File size exceeds 16MB limit', 'error');
            return;
        }

        uploadFile(file);
    }

    function uploadFile(file) {
        showToast('Uploading file...', 'info');

        const formData = new FormData();
        formData.append('file', file);

        fetch('/upload', {
            method: 'POST',
            body: formData
        })
        .then(response => response.json())
        .then(data => {
            if (data.error) throw new Error(data.error);

            showToast('File uploaded successfully', 'success');
            if (data.file_info) updateFileInfo(data.file_info);
        })
        .catch(error => {
            showToast(error.message, 'error');
        });
    }

    // Global Functions
    window.copyHash = function(elementId) {
        const hashType = elementId === 'md5Hash' ? 'md5' : 'sha256';
        const fullHash = document.getElementById(`${hashType}HashFull`).textContent;

        navigator.clipboard.writeText(fullHash).then(() => {
            showToast(`${hashType.toUpperCase()} hash copied to clipboard`, 'success');
        });
    }

    window.selectAnalysisType = function (type) {
        if (!currentFileHash) return;

        // Get the user-specified arguments
        const argsInput = document.getElementById('analysisArgs').value;
        const args = argsInput.split(' ').filter(arg => arg.trim() !== '');

        // Save the arguments to localStorage
        localStorage.setItem('analysisArgs', JSON.stringify(args));

        updateProgress(2, true);
        elements.fileAnalysisArea.classList.add('opacity-0', 'scale-95');

        setTimeout(() => {
            window.location.href = `/analyze/${type}/${currentFileHash}`;
        }, UPLOAD_CONFIG.transitionDelay);
    };

});