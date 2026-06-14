const canvas = document.querySelector("#matrixCanvas");
const context = canvas.getContext("2d");
const terminal = document.querySelector("#terminalLines");
const progressBar = document.querySelector("#progressBar");
const progressLabel = document.querySelector("#progressLabel");
const enterButton = document.querySelector("#enterButton");

const glyphs = "01AI漏洞扫描器SECURITYDASTSASTSQLXSSROOTTOKEN";
const bootLines = [
  "Loading scanner core...",
  "Loading vulnerability rules...",
  "Preparing AI advisor...",
  "Security console ready.",
];

let columns = [];
let fontSize = 12;

function resizeCanvas() {
  canvas.width = window.innerWidth * window.devicePixelRatio;
  canvas.height = window.innerHeight * window.devicePixelRatio;
  canvas.style.width = `${window.innerWidth}px`;
  canvas.style.height = `${window.innerHeight}px`;
  context.setTransform(window.devicePixelRatio, 0, 0, window.devicePixelRatio, 0, 0);

  const count = Math.ceil(window.innerWidth / fontSize) * 2;
  columns = Array.from({ length: count }, () => Math.random() * window.innerHeight);
}

function drawMatrix() {
  context.fillStyle = "rgba(2, 6, 4, 0.11)";
  context.fillRect(0, 0, window.innerWidth, window.innerHeight);
  context.font = `${fontSize}px Consolas, monospace`;

  columns.forEach((y, index) => {
    const char = glyphs[Math.floor(Math.random() * glyphs.length)];
    const x = (index * fontSize) / 2;
    context.fillStyle = Math.random() > 0.985 ? "#9df2bc" : "#00b765";
    context.fillText(char, x, y);

    columns[index] = y > window.innerHeight + Math.random() * 1000 ? 0 : y + fontSize;
  });

  requestAnimationFrame(drawMatrix);
}

function addBootLine(text) {
  const line = document.createElement("div");
  line.className = "terminal-line";
  line.textContent = text;
  terminal.appendChild(line);
}

function updateProgress(value) {
  progressBar.style.width = `${value}%`;
  progressLabel.textContent = `${value}%`;
}

function completeBoot() {
  updateProgress(100);
  progressBar.classList.add("complete");
  enterButton.classList.remove("disabled");
  enterButton.removeAttribute("aria-disabled");
}

function runBootSequence() {
  let index = 0;
  const startedAt = performance.now();
  const duration = 1500;

  function animateProgress(now) {
    const progress = Math.min(100, Math.round(((now - startedAt) / duration) * 100));
    updateProgress(progress);
    if (progress < 100) {
      requestAnimationFrame(animateProgress);
    } else {
      completeBoot();
    }
  }

  requestAnimationFrame(animateProgress);

  const timer = window.setInterval(() => {
    if (index < bootLines.length) {
      addBootLine(bootLines[index]);
      index += 1;
      return;
    }

    window.clearInterval(timer);
  }, 220);
}

window.addEventListener("resize", resizeCanvas);

resizeCanvas();
drawMatrix();
runBootSequence();
