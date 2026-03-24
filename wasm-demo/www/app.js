// Caliptra WASM Emulator - JavaScript glue
import init, { CaliptraEmulator } from "./caliptra_wasm_demo.js";

// DOM elements
const romFileInput = document.getElementById("rom-file");
const romInfo = document.getElementById("rom-info");
const fwFileInput = document.getElementById("fw-file");
const fwInfo = document.getElementById("fw-info");
const socManifestFileInput = document.getElementById("soc-manifest-file");
const socManifestInfo = document.getElementById("soc-manifest-info");
const vendorPkInput = document.getElementById("vendor-pk");
const ownerPkInput = document.getElementById("owner-pk");
const lifecycleSelect = document.getElementById("lifecycle");
const btnRun = document.getElementById("btn-run");
const btnStop = document.getElementById("btn-stop");
const btnReset = document.getElementById("btn-reset");
const statusEl = document.getElementById("status");
const statsEl = document.getElementById("stats");
const uartOutput = document.getElementById("uart-output");
const logOutput = document.getElementById("log-output");

// State
let emulator = null;
let running = false;
let animFrameId = null;
let defaultRom = null;
let customRom = null;
let defaultFw = null;
let customFw = null;
let customSocManifest = null;
let startTime = 0;

// Steps per animation frame — balance between speed and UI responsiveness
const STEPS_PER_FRAME = 50_000;

// Initialize WASM module and load defaults
async function startup() {
  try {
    await init();
    setStatus("Loading defaults...", "");

    // Load default ROM, FW, and hash defaults in parallel
    const [romResp, fwResp, defaultsResp] = await Promise.allSettled([
      fetch("default-rom.bin"),
      fetch("default-fw.bin"),
      fetch("defaults.json"),
    ]);

    if (romResp.status === "fulfilled" && romResp.value.ok) {
      defaultRom = new Uint8Array(await romResp.value.arrayBuffer());
      romInfo.textContent = `Default ROM loaded (${(defaultRom.length / 1024).toFixed(0)} KB)`;
    } else {
      romInfo.textContent = "No default ROM — please upload one";
    }

    if (fwResp.status === "fulfilled" && fwResp.value.ok) {
      defaultFw = new Uint8Array(await fwResp.value.arrayBuffer());
      fwInfo.textContent = `Default FW loaded (${(defaultFw.length / 1024).toFixed(0)} KB)`;
    } else {
      fwInfo.textContent = "(optional) No default FW";
    }

    if (defaultsResp.status === "fulfilled" && defaultsResp.value.ok) {
      const defaults = await defaultsResp.value.json();
      if (defaults.vendor_pk_hash) {
        vendorPkInput.value = defaults.vendor_pk_hash;
      }
      if (defaults.owner_pk_hash && defaults.owner_pk_hash !== "0".repeat(96)) {
        ownerPkInput.value = defaults.owner_pk_hash;
      }
    }

    setStatus("Ready", "");
    btnRun.disabled = false;
    btnReset.disabled = false;
  } catch (err) {
    setStatus(`WASM init failed: ${err}`, "exited");
    console.error("WASM init error:", err);
  }
}

// Handle custom ROM file upload
romFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customRom = new Uint8Array(reader.result);
    romInfo.textContent = `${file.name} (${(customRom.length / 1024).toFixed(0)} KB)`;
  };
  reader.readAsArrayBuffer(file);
});

// Handle custom FW file upload
fwFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customFw = new Uint8Array(reader.result);
    fwInfo.textContent = `${file.name} (${(customFw.length / 1024).toFixed(0)} KB)`;
  };
  reader.readAsArrayBuffer(file);
});

// Handle SoC manifest file upload
socManifestFileInput.addEventListener("change", (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    customSocManifest = new Uint8Array(reader.result);
    socManifestInfo.textContent = `${file.name} (${(customSocManifest.length / 1024).toFixed(0)} KB)`;
  };
  reader.readAsArrayBuffer(file);
});

// Get the ROM/FW to use (custom upload takes priority)
function getRom() {
  return customRom || defaultRom;
}
function getFw() {
  return customFw || defaultFw || null;
}
function getSocManifest() {
  return customSocManifest || null;
}

// Create emulator instance
function createEmulator() {
  const rom = getRom();
  if (!rom) {
    setStatus("No ROM loaded — upload a ROM file", "stopped");
    return false;
  }

  const vendorPk = vendorPkInput.value.trim();
  const ownerPk = ownerPkInput.value.trim();
  const fw = getFw();
  const socManifest = getSocManifest();
  const lifecycle = lifecycleSelect.value;

  try {
    // Free previous emulator if any
    if (emulator) {
      emulator.free();
      emulator = null;
    }
    emulator = new CaliptraEmulator(rom, vendorPk, ownerPk, fw, socManifest, lifecycle);

    // Check for boot error — show logs even if boot failed
    const bootErr = emulator.boot_error();
    if (bootErr) {
      uartOutput.textContent = bootErr;
      const log = emulator.get_log();
      if (log) logOutput.textContent = log;
    } else {
      uartOutput.textContent = "";
      logOutput.textContent = "";
    }
    statsEl.textContent = "";
    return true;
  } catch (err) {
    setStatus(`Error: ${err}`, "exited");
    console.error("Emulator creation error:", err);
    return false;
  }
}

// Run loop using requestAnimationFrame
function runLoop() {
  if (!running || !emulator) return;

  const stillRunning = emulator.step(STEPS_PER_FRAME);

  // Collect output
  const uart = emulator.get_uart_output();
  if (uart) {
    uartOutput.textContent += uart;
    uartOutput.scrollTop = uartOutput.scrollHeight;
  }

  const log = emulator.get_log();
  if (log) {
    logOutput.textContent += log;
    logOutput.scrollTop = logOutput.scrollHeight;
  }

  // Update stats
  const steps = Number(emulator.total_steps());
  const elapsed = (performance.now() - startTime) / 1000;
  const mhz = (steps / elapsed / 1_000_000).toFixed(2);
  statsEl.textContent = `${steps.toLocaleString()} cycles | ${elapsed.toFixed(1)}s | ${mhz} MHz effective`;

  if (!stillRunning) {
    running = false;
    const passed = emulator.passed();
    setStatus(
      passed ? "Exited — PASSED ✓" : "Exited — FAILED ✗",
      passed ? "passed" : "exited"
    );
    btnRun.disabled = true;
    btnStop.disabled = true;
    return;
  }

  animFrameId = requestAnimationFrame(runLoop);
}

// Button handlers
btnRun.addEventListener("click", () => {
  if (running) return;

  if (!emulator) {
    if (!createEmulator()) return;
  }

  running = true;
  startTime = performance.now();
  setStatus("Running...", "running");
  btnRun.disabled = true;
  btnStop.disabled = false;
  romFileInput.disabled = true;
  fwFileInput.disabled = true;
  socManifestFileInput.disabled = true;
  vendorPkInput.disabled = true;
  ownerPkInput.disabled = true;
  lifecycleSelect.disabled = true;

  animFrameId = requestAnimationFrame(runLoop);
});

btnStop.addEventListener("click", () => {
  running = false;
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  setStatus("Stopped", "stopped");
  btnRun.disabled = false;
  btnStop.disabled = true;
});

btnReset.addEventListener("click", () => {
  running = false;
  if (animFrameId) {
    cancelAnimationFrame(animFrameId);
    animFrameId = null;
  }
  if (emulator) {
    emulator.free();
    emulator = null;
  }
  uartOutput.textContent = "";
  logOutput.textContent = "";
  statsEl.textContent = "";
  setStatus("Ready", "");
  btnRun.disabled = false;
  btnStop.disabled = true;
  romFileInput.disabled = false;
  fwFileInput.disabled = false;
  socManifestFileInput.disabled = false;
  vendorPkInput.disabled = false;
  ownerPkInput.disabled = false;
  lifecycleSelect.disabled = false;
});

function setStatus(text, className) {
  statusEl.textContent = text;
  statusEl.className = "status" + (className ? " " + className : "");
}

// Start
startup();
