// File Role Logic for dynamic updates

const fileTrigger = document.getElementById('file-trigger');
const fileInput = document.getElementById('target-upload');
const targetDisplay = document.getElementById('target-display');
const actionBtn = document.getElementById('main-action-btn');
const systemStatus = document.getElementById('system-status');

// Matrix data rain background elements control
const matrixBg = document.querySelector('.matrix-background');

// Predefined security event stream
const scannerEvents = [
    { type: 'log', message: 'Core system active. Listening for snapshot stream...' },
    { type: 'log', message: 'Validating endpoint connections...' },
    { type: 'log', message: 'Waiting for target input.' }
];

let matrixStreamInterval = null;

// Matrix Data Rain logic: Start and stop the stream
function startMatrixStream() {
    console.log("Forensic Engine Active. Starting security data stream.");
    if (!matrixStreamInterval) {
        matrixBg.style.opacity = 0.6; // Turn on effect opacity
        matrixStreamInterval = setInterval(() => {
            if (scannerEvents.length > 0) {
                // Fetch event data and remove from list
                const event = scannerEvents.shift();
                
                // Add new dynamic character column with event data
                const charColumn = document.createElement('div');
                charColumn.className = 'matrix-column';
                charColumn.innerHTML = `<span class='log-prefix'>[ENG_LOG]</span> ${event.message}`;
                matrixBg.appendChild(charColumn);

                // Stop if we have events, otherwise keep streaming generic data
                if (scannerEvents.length < 2) {
                    console.log("No critical events remaining in initial buffer.");
                }

                // Scroll the interface context logs
                if (typeof scrollContextLogs === 'function') {
                    scrollContextLogs(event);
                }
            } else {
                clearInterval(matrixStreamInterval);
                matrixStreamInterval = null;
                console.log("Matrix initial stream complete.");
            }
        }, 1200); // Dynamic event speed
    }
}

// Stop the matrix stream and clean elements
function stopMatrixStream() {
    matrixBg.style.opacity = 0;
    matrixBg.innerHTML = ''; // Clean data columns
    if (matrixStreamInterval) {
        clearInterval(matrixStreamInterval);
        matrixStreamInterval = null;
    }
    console.log("Matrix stream halted.");
}

// Mapla, initial page load effect stop logic pathi sonnathai fix panniduvom
window.addEventListener('DOMContentLoaded', () => {
    // Current interface design assumes effect is off on load and starts with interaction.
    stopMatrixStream(); 
});

// File input integration logic
fileTrigger.addEventListener('click', () => {
    fileInput.click();
});

fileInput.addEventListener('change', function(event) {
    if (this.files.length > 0) {
        const file = this.files[0];
        const fileName = file.name;
        targetDisplay.textContent = fileName;
        targetDisplay.classList.add('selected');

        // Logic dynamic-a update panna system-ai activate panniduvom
        systemStatus.textContent = 'AWAITING INITIALIZATION';
        systemStatus.classList.remove('online');
        systemStatus.classList.add('ready');
        
        // Start dynamic security effects and scene updates
        startMatrixStream();
        updateScannerVibeForTarget(fileName);
        
        // Use external logic from main.js if available for animation
        if (typeof playButtonFeedback === 'function') {
            playButtonFeedback(actionBtn, 'Target locked. Ready to scan.');
        }

    } else {
        targetDisplay.textContent = "No target selected";
        targetDisplay.classList.remove('selected');
    }
});

// Update the interface dynamic vibe based on file role
function updateScannerVibeForTarget(filename) {
    const fileExtension = filename.split('.').pop().toLowerCase();
    
    // Core system logic match logic
    if (fileExtension === 'raw' || fileExtension === 'mem' || fileExtension === 'dump') {
        console.log("Target recognized as a memory snapshot. Full memory forensics enabled.");
        actionBtn.innerHTML = "<span class='action-icon'>🧠</span> INITIALIZE FULL MEMORY FORENSICS";
        actionBtn.classList.add('full-scan');
        addScannerEvent('info', `Target: ${filename}. Analyzing memory snapshot signatures.`);
        addScannerEvent('info', 'Activating kernel structures and process table reconstruction scans.');
    } else if (fileExtension === 'exe' || fileExtension === 'dll' || fileExtension === 'elf') {
        console.log("Target recognized as an executable artifact. Static and behavior analysis enabled.");
        actionBtn.innerHTML = "<span class='action-icon'>🔍</span> INITIALIZE EXECUTABLE SCAN";
        actionBtn.classList.remove('full-scan');
        addScannerEvent('warn', `Artifact: ${filename}. Launching PE header analysis and dynamic behavior checks.`);
        addScannerEvent('warn', 'Simulating sandbox environment for artifact detonation scan.');
    } else {
        console.log("Target is an unknown artifact type. Defaulting to standard IOC and pattern scanning.");
        actionBtn.innerHTML = "<span class='action-icon'>🚀</span> INITIALIZE ARTIFACT ANALYSIS";
        addScannerEvent('warn', `Artifact: ${filename}. Unknown type. Performing IOC extraction and pattern match scans.`);
    }
}

// Function to inject new events dynamically to the background stream
function addScannerEvent(type, message) {
    scannerEvents.push({ type, message });
    
    // If matrix is off, wake it up for new events
    if (matrixBg.style.opacity < 0.1) {
        startMatrixStream();
    }
}