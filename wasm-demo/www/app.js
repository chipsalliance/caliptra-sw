// Caliptra WASM Emulator - JavaScript glue
import init, { CaliptraEmulator } from "./caliptra_wasm_demo.js";

// DOM elements
const romFileInput = document.getElementById("rom-file");
const romInfo = document.getElementById("rom-info");
const vendorPkInput = document.getElementById("vendor-pk");
const ownerPkInput = document.getElementById("owner-pk");
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
let startTime = 0;

// Steps per animation frame — balance between speed and UI responsiveness
const STEPS_PER_FRAME = 50_000;

// Initialize WASM module and load default ROM
async function startup() {
  try {
    await init();
    setStatus("Loading default ROM...", "");

    // Try to load the default ROM
    try {
      const resp = await fetch("default-rom.bin");
      if (resp.ok) {
        defaultRom = new Uint8Array(await resp.arrayBuffer());
        romInfo.textContent = `Default ROM loaded (${(defaultRom.length / 1024).toFixed(0)} KB)`;
      } else {
        romInfo.textContent = "No default ROM — please upload one";
      }
    } catch {
      romInfo.textContent = "No default ROM — please upload one";
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

// Get the ROM to use (custom upload takes priority)
function getRom() {
  return customRom || defaultRom;
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

  try {
    // Free previous emulator if any
    if (emulator) {
      emulator.free();
      emulator = null;
    }
    emulator = new CaliptraEmulator(rom, vendorPk, ownerPk);
    uartOutput.textContent = "";
    logOutput.textContent = "";
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
  vendorPkInput.disabled = true;
  ownerPkInput.disabled = true;

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
  vendorPkInput.disabled = false;
  ownerPkInput.disabled = false;
});

function setStatus(text, className) {
  statusEl.textContent = text;
  statusEl.className = "status" + (className ? " " + className : "");
}

// Start
startup();
