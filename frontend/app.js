const API_BASE = window.location.protocol === "file:" ? "http://127.0.0.1:8000/api" : "/api";

const defaultTarget = {
  base_url: "http://127.0.0.1:5001",
  project_path: "./vulnerable_app",
};

let scanTarget = { ...defaultTarget };
let activeTaskId = "";
let statusPollTimer = null;
let latestReports = {};
let latestRisk = null;
let backendConnected = false;
let currentProgress = 0;
let currentScanTitle = "等待扫描";
let currentScanSubtitle = "点击开始扫描后，会从后端同步真实扫描进度。";
let taskRecords = [];
let reportRecords = [];
let assetRecords = [];
let currentScanPage = 1;
let scanPageSize = 10;
let selectedVulnerabilityIds = new Set();
let aiSettings = {
  key_configured: false,
  provider: "",
  runtime_provider: "",
};

let modules = [
  { name: "连接目标" },
  { name: "SQL 注入测试" },
  { name: "XSS 测试" },
  { name: "越权访问测试" },
  { name: "静态源码扫描" },
  { name: "AI 修复建议" },
  { name: "生成报告" },
];

let scanSteps = [
  { name: "连接目标", time: "等待中", status: "pending" },
  { name: "SQL 注入测试", time: "等待中", status: "pending" },
  { name: "XSS 测试", time: "等待中", status: "pending" },
  { name: "越权访问测试", time: "等待中", status: "pending" },
  { name: "静态源码扫描", time: "等待中", status: "pending" },
  { name: "AI 修复建议", time: "等待中", status: "pending" },
  { name: "生成报告", time: "等待中", status: "pending" },
];

const initialEvents = [];

let events = [];

let vulnerabilities = [];

let selectedVulnerabilityId = vulnerabilities[0]?.id ?? "";
let currentFilter = "全部";
let currentStatus = "全部状态";
let drawerOpen = true;
let initialWorkspaceTemplate = "";

const riskClass = (risk) => String(risk || "low").toLowerCase();
const statusClass = (status) => {
  if (status === "已修复") {
    return "status-fixed";
  }
  if (status === "修复中") {
    return "status-progress";
  }
  if (status === "已忽略" || status === "误报") {
    return "status-muted";
  }
  return "status-unfixed";
};
const selectedItem = () =>
  vulnerabilities.find((vulnerability) => vulnerability.id === selectedVulnerabilityId) ??
  vulnerabilities[0] ??
  null;

function currentTime() {
  return new Date().toLocaleTimeString("zh-CN", { hour12: false });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function apiUrl(path) {
  if (/^https?:\/\//i.test(path)) {
    return path;
  }
  if (path.startsWith("/api/")) {
    return API_BASE.startsWith("http") ? `${API_BASE.replace(/\/api$/, "")}${path}` : path;
  }
  return `${API_BASE}${path.startsWith("/") ? path : `/${path}`}`;
}

async function apiRequest(path, options = {}) {
  const response = await fetch(apiUrl(path), {
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
    ...options,
  });

  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("application/json") ? await response.json() : await response.text();
  if (!response.ok) {
    const message = typeof data === "object" ? data.error || data.message : data;
    throw new Error(message || `HTTP ${response.status}`);
  }
  return data;
}

function normalizeStepStatus(status) {
  if (status === "running") {
    return "active";
  }
  return status || "pending";
}

function mapApiVulnerability(item) {
  const discoveredAt = item.discovered_at || "";
  return {
    id: item.id || "VULN-UNKNOWN",
    type: item.type || "Unknown Vulnerability",
    category: item.category || "General",
    risk: item.risk || "Low",
    score: item.score ?? 0,
    location: item.location || "unknown",
    method: item.method || "UNKNOWN",
    evidence: item.evidence_count ?? (item.evidence ? 1 : 0),
    evidenceText: item.evidence || "",
    confidence: item.confidence || "Medium",
    fingerprint: item.fingerprint || "",
    status: item.status || "未修复",
    time: discoveredAt.split(" ").pop() || currentTime(),
    discoveredAt: discoveredAt || `今天 ${currentTime()}`,
    description: item.description || item.evidence || "扫描器发现了一个需要人工复核的安全风险。",
    component: item.component || "unknown",
    advice: item.ai_advice || item.suggestion || "建议根据漏洞证据定位代码路径并补充回归测试。",
    adviceSource: item.ai_advice_source || "unknown",
    requestMethod: item.request_method || item.method || "UNKNOWN",
    payload: item.payload || "",
    scannerRule: item.scanner_rule || "",
    remediationPriority: item.remediation_priority || "P3",
  };
}

function statusLabel(status) {
  const labels = {
    running: "运行中",
    completed: "已完成",
    failed: "失败",
    pending: "等待中",
    cancelling: "取消中",
    cancelled: "已取消",
  };
  return labels[status] || status || "未知";
}

function safeRiskBadge(risk) {
  return `<span class="badge ${riskClass(risk)}">${escapeHtml(risk || "Low")}</span>`;
}

function latestTask() {
  return taskRecords[0] || null;
}

function updateBackendStatusPanel() {
  const latest = latestTask();
  const latestReport = reportRecords[0];
  const statusBadge = document.querySelector("#backendStatusBadge");
  const apiState = document.querySelector("#backendApiState");
  const taskCount = document.querySelector("#backendTaskCount");
  const reportCount = document.querySelector("#backendReportCount");
  const assetCount = document.querySelector("#backendAssetCount");
  const latestTaskNode = document.querySelector("#backendLatestTask");
  const latestRisk = document.querySelector("#backendLatestRisk");

  if (statusBadge) {
    statusBadge.textContent = backendConnected ? "已连接" : "离线";
  }
  if (apiState) {
    apiState.textContent = backendConnected ? "正常" : "未连接";
  }
  if (taskCount) {
    taskCount.textContent = String(taskRecords.length);
  }
  if (reportCount) {
    reportCount.textContent = String(reportRecords.length);
  }
  if (assetCount) {
    assetCount.textContent = String(assetRecords.length);
  }
  if (latestTaskNode) {
    latestTaskNode.textContent = latest ? statusLabel(latest.status) : "-";
  }
  if (latestRisk) {
    latestRisk.textContent = latestReport?.risk?.overall_risk || "-";
  }
}

async function loadPlatformData() {
  if (!backendConnected) {
    updateBackendStatusPanel();
    return;
  }
  try {
    const [tasksData, reportsData, assetsData] = await Promise.all([
      apiRequest("/tasks"),
      apiRequest("/reports"),
      apiRequest("/assets"),
    ]);
    taskRecords = tasksData.tasks || [];
    reportRecords = reportsData.reports || [];
    assetRecords = assetsData.assets || [];
    updateBackendStatusPanel();
  } catch (error) {
    addEvent("WARN", `平台数据同步失败：${error.message}`);
    updateBackendStatusPanel();
  }
}

function renderTargetInfo() {
  document.querySelector("#targetBaseUrl")?.replaceChildren(document.createTextNode(scanTarget.base_url));
  document.querySelector("#targetScanType")?.replaceChildren(document.createTextNode("深度扫描 (DAST + SAST)"));
  const startTime = activeTaskId ? latestRisk?.started_at || "扫描已启动" : "等待启动";
  document.querySelector("#targetStartTime")?.replaceChildren(document.createTextNode(startTime));
  document.querySelector("#targetDuration")?.replaceChildren(
    document.createTextNode(activeTaskId ? "实时状态轮询中" : "按目标响应决定"),
  );
}

function updateProgress(progress = 0, title = "等待扫描", subtitle = "启动后会从后端扫描任务同步状态。") {
  const value = Math.max(0, Math.min(100, Number(progress) || 0));
  currentProgress = value;
  currentScanTitle = title;
  currentScanSubtitle = subtitle;
  const progressValue = document.querySelector("#progressValue");
  if (progressValue) {
    progressValue.innerHTML = `${value}<span>%</span>`;
  }
  document.querySelector(".radar")?.setAttribute("aria-label", `扫描进度 ${value}%`);
  const heading = document.querySelector(".scan-heading h1");
  const copy = document.querySelector(".scan-heading p");
  if (heading) {
    heading.textContent = title;
  }
  if (copy) {
    copy.textContent = subtitle;
  }
}

function renderAllScanData() {
  renderTargetInfo();
  renderModules();
  renderSteps();
  renderEvents();
  renderSummary();
  renderRows();
  renderDetail();
}

function resetScanWorkspace() {
  activeTaskId = "";
  latestReports = {};
  latestRisk = null;
  vulnerabilities = [];
  selectedVulnerabilityIds.clear();
  selectedVulnerabilityId = "";
  events = [];
  modules = modules.map((module) => ({ name: module.name }));
  scanSteps = scanSteps.map((step) => ({ name: step.name, time: "等待中", status: "pending" }));
  updateProgress(0, "等待扫描", "点击开始扫描后，会从后端同步真实扫描进度。");
}

function syncStatus(status) {
  activeTaskId = status.task_id || activeTaskId;
  scanTarget = status.target || scanTarget;
  scanSteps = (status.steps || scanSteps).map((step) => ({
    name: step.name,
    time: step.duration || step.time || "等待中",
    status: normalizeStepStatus(step.status),
  }));
  events = (status.events || []).map((event) => ({
    time: event.time || currentTime(),
    level: event.level || "INFO",
    text: event.message || event.text || "",
  }));
  const runningModule = status.current_step || "扫描任务";
  modules = modules.map((module) => ({
    ...module,
    state: module.name.includes(runningModule) || runningModule.includes(module.name) ? "进行中" : undefined,
  }));
  updateProgress(
    status.progress,
    status.status === "completed" ? "扫描完成" : "扫描进行中",
    status.current_step ? `当前阶段：${status.current_step}` : "后端扫描任务正在运行。",
  );
  renderAllScanData();
}

async function syncResult(result) {
  latestRisk = { ...(result.risk || {}), started_at: result.created_at };
  latestReports = result.reports || {};
  scanTarget = result.target || scanTarget;
  vulnerabilities = (result.vulnerabilities || []).map(mapApiVulnerability);
  selectedVulnerabilityId = vulnerabilities[0]?.id ?? "";
  if (result.errors?.length) {
    result.errors.forEach((error) => addEvent("WARN", error));
  }
  await loadPlatformData();
  renderAllScanData();
}

async function fetchScanResult() {
  if (!activeTaskId) {
    return;
  }
  const result = await apiRequest(`/scan/result/${activeTaskId}`);
  await syncResult(result);
}

async function pollScanStatus() {
  if (!activeTaskId) {
    return;
  }
  try {
    const status = await apiRequest(`/scan/status/${activeTaskId}`);
    syncStatus(status);
    if (status.status === "completed" || status.status === "failed" || status.status === "cancelled") {
      window.clearInterval(statusPollTimer);
      statusPollTimer = null;
      if (status.status === "completed") {
        await fetchScanResult();
        showToast("后端扫描结果已同步");
      } else if (status.status === "cancelled") {
        showToast("扫描任务已取消");
      } else {
        showToast("扫描任务失败，请查看事件流");
      }
    }
  } catch (error) {
    window.clearInterval(statusPollTimer);
    statusPollTimer = null;
    addEvent("ERROR", `扫描状态同步失败：${error.message}`);
    showToast("扫描状态同步失败");
  }
}

async function startBackendScan() {
  const button = document.querySelector("#startScanButton");
  button?.setAttribute("disabled", "true");
  try {
    resetScanWorkspace();
    events = [{ time: currentTime(), level: "INFO", text: "正在向后端提交扫描任务" }];
    scanSteps = scanSteps.map((step) => ({ ...step, status: "pending", time: "等待中" }));
    updateProgress(3, "扫描准备中", "正在提交扫描任务。");
    renderAllScanData();

    const data = await apiRequest("/scan/start", {
      method: "POST",
      body: JSON.stringify({
        base_url: scanTarget.base_url,
        project_path: scanTarget.project_path,
        scan_mode: "full",
        modules: [
          "sql_injection",
          "xss",
          "broken_access_control",
          "hardcoded_secret",
          "weak_password_storage",
          "ai_advice",
        ],
      }),
    });
    activeTaskId = data.task_id;
    backendConnected = true;
    showToast(`扫描任务已启动：${activeTaskId}`);
    await pollScanStatus();
    statusPollTimer = window.setInterval(pollScanStatus, 1500);
  } catch (error) {
    addEvent("ERROR", `启动后端扫描失败：${error.message}`);
    showToast("后端未连接，保留本地兜底状态");
  } finally {
    button?.removeAttribute("disabled");
  }
}

async function loadBackendSettings() {
  try {
    const settings = await apiRequest("/settings");
    backendConnected = true;
    scanTarget = {
      base_url: settings.default_base_url || scanTarget.base_url,
      project_path: settings.default_project_path || scanTarget.project_path,
    };
    aiSettings = {
      key_configured: Boolean(settings.ai_key_configured),
      provider: settings.ai_provider || "",
      runtime_provider: settings.runtime_ai_provider || "",
    };
    addEvent("INFO", `已连接后端 API：${settings.api_base_url || API_BASE}`);
    await loadPlatformData();
    const latestBackendTask = taskRecords[0];
    if (latestBackendTask && !activeTaskId) {
      activeTaskId = latestBackendTask.task_id;
      syncStatus(latestBackendTask);
      if (latestBackendTask.status === "completed") {
        await fetchScanResult();
      } else if (latestBackendTask.status === "running" || latestBackendTask.status === "cancelling") {
        statusPollTimer = window.setInterval(pollScanStatus, 1500);
      }
    } else if (!activeTaskId) {
      resetScanWorkspace();
      renderAllScanData();
    }
    renderTargetInfo();
  } catch {
    backendConnected = false;
    addEvent("WARN", "未连接后端 API，可运行 python serve_app.py 后刷新页面");
  }
}

async function saveBackendSettings(baseUrl, projectPath) {
  const settings = await apiRequest("/settings", {
    method: "PATCH",
    body: JSON.stringify({
      default_base_url: baseUrl,
      default_project_path: projectPath,
    }),
  });
  backendConnected = true;
  scanTarget = {
    base_url: settings.default_base_url || baseUrl,
    project_path: settings.default_project_path || projectPath,
  };
  renderTargetInfo();
  updateBackendStatusPanel();
  addEvent("INFO", `默认扫描目标已更新：${scanTarget.base_url}`);
  return settings;
}

async function saveAiKey(provider, apiKey) {
  const settings = await apiRequest("/settings/ai-key", {
    method: "PATCH",
    body: JSON.stringify({
      provider,
      api_key: apiKey,
    }),
  });
  aiSettings = {
    key_configured: Boolean(settings.ai_key_configured),
    provider: settings.ai_provider || provider,
    runtime_provider: settings.runtime_ai_provider || provider,
  };
  addEvent("INFO", `AI 修复建议已配置为 ${provider.toUpperCase()} 接口`);
  return settings;
}

function addEvent(level, text) {
  events = [...events, { time: currentTime(), level, text }].slice(-14);
  renderEvents();
}

function showToast(message) {
  const toastArea = document.querySelector("#toastArea");
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  toastArea.appendChild(toast);
  window.setTimeout(() => toast.classList.add("show"), 20);
  window.setTimeout(() => {
    toast.classList.remove("show");
    window.setTimeout(() => toast.remove(), 220);
  }, 2200);
}

function showModal(title, html) {
  document.querySelector("#modalTitle").textContent = title;
  document.querySelector("#modalBody").innerHTML = html;
  document.querySelector("#modalBackdrop").hidden = false;
}

function closeModal() {
  document.querySelector("#modalBackdrop").hidden = true;
}

function renderModules() {
  const list = document.querySelector("#moduleList");
  if (!list) {
    return;
  }
  list.innerHTML = modules
    .map(
      (item) => `
        <li>
          <span class="check-dot"></span>
          <span>${item.name}</span>
          ${item.state ? `<span class="running">${item.state}</span>` : ""}
        </li>
      `,
    )
    .join("");
}

function renderSteps() {
  const list = document.querySelector("#scanSteps");
  if (!list) {
    return;
  }
  list.innerHTML = scanSteps
    .map(
      (step, index) => `
        <li class="${step.status}">
          <span class="step-index">${index + 1}</span>
          <strong>${step.name}</strong>
          <span>${step.time}</span>
        </li>
      `,
    )
    .join("");
}

function renderEvents() {
  const list = document.querySelector("#eventList");
  if (!list) {
    return;
  }
  if (!events.length) {
    list.innerHTML = `<div class="empty-state">暂无扫描事件。启动一次后端扫描后，这里会显示真实事件流。</div>`;
    return;
  }

  list.innerHTML = events
    .map(
      (event) => `
        <div class="event-item">
          <time>${event.time}</time>
          <span class="event-level ${event.level.toLowerCase()}">${event.level}</span>
          <span>${event.text}</span>
        </div>
      `,
    )
    .join("");
}

function renderSummary() {
  const grid = document.querySelector("#summaryGrid");
  if (!grid) {
    return;
  }
  const counts = vulnerabilities.reduce(
    (acc, item) => {
      const risk = riskClass(item.risk);
      acc.total += 1;
      if (risk in acc) {
        acc[risk] += 1;
      }
      return acc;
    },
    { total: 0, critical: 0, high: 0, medium: 0, low: 0 },
  );

  const cards = [
    { key: "total", label: "总漏洞数", value: counts.total },
    { key: "critical", label: "Critical", value: counts.critical },
    { key: "high", label: "High", value: counts.high },
    { key: "medium", label: "Medium", value: counts.medium },
    { key: "low", label: "Low", value: counts.low },
  ];

  grid.innerHTML = cards
    .map(
      (card) => `
        <article class="summary-card ${card.key}">
          <div>
            <span>${card.label}</span>
            <strong>${card.value}</strong>
          </div>
          <span class="summary-icon">${card.key === "total" ? "T" : "!"}</span>
        </article>
      `,
    )
    .join("");
  const total = latestRisk?.total ?? counts.total;
  document.querySelector("#vulnerabilityTotal")?.replaceChildren(document.createTextNode(`共 ${total} 条`));
}

function renderPagination(totalRows) {
  const totalPages = Math.max(1, Math.ceil(totalRows / scanPageSize));
  currentScanPage = Math.min(Math.max(1, currentScanPage), totalPages);
  document.querySelector("#vulnerabilityTotal")?.replaceChildren(
    document.createTextNode(`共 ${totalRows} 条，当前第 ${currentScanPage} / ${totalPages} 页`),
  );

  const pagination = document.querySelector("#vulnerabilityPagination");
  if (!pagination) {
    return;
  }
  pagination.innerHTML = `
    <button class="page-button" data-page-action="prev" ${currentScanPage <= 1 ? "disabled" : ""}>‹</button>
    ${Array.from({ length: totalPages }, (_, index) => {
      const page = index + 1;
      return `<button class="page-button ${page === currentScanPage ? "active" : ""}" data-page="${page}">${page}</button>`;
    }).join("")}
    <button class="page-button" data-page-action="next" ${currentScanPage >= totalPages ? "disabled" : ""}>›</button>
    <select id="scanPageSize" aria-label="每页条数">
      ${[5, 10, 20].map((size) => `<option value="${size}" ${size === scanPageSize ? "selected" : ""}>${size} 条 / 页</option>`).join("")}
    </select>
  `;

  pagination.querySelectorAll("[data-page]").forEach((button) => {
    button.addEventListener("click", () => {
      currentScanPage = Number(button.dataset.page) || 1;
      renderRows();
    });
  });
  pagination.querySelector("[data-page-action='prev']")?.addEventListener("click", () => {
    currentScanPage -= 1;
    renderRows();
  });
  pagination.querySelector("[data-page-action='next']")?.addEventListener("click", () => {
    currentScanPage += 1;
    renderRows();
  });
  pagination.querySelector("#scanPageSize")?.addEventListener("change", (event) => {
    scanPageSize = Number(event.target.value) || 10;
    currentScanPage = 1;
    renderRows();
  });
}

function filteredVulnerabilities() {
  return vulnerabilities.filter((item) => {
    const methodMatch = currentFilter === "全部" || item.method === currentFilter;
    const statusMatch = currentStatus === "全部状态" || item.status === currentStatus;
    return methodMatch && statusMatch;
  });
}

function currentPageVulnerabilities() {
  const rows = filteredVulnerabilities();
  return rows.slice((currentScanPage - 1) * scanPageSize, currentScanPage * scanPageSize);
}

function renderRows() {
  const tbody = document.querySelector("#vulnerabilityRows");
  if (!tbody) {
    return;
  }
  const rows = filteredVulnerabilities();
  renderPagination(rows.length);
  const pageRows = currentPageVulnerabilities();

  if (!pageRows.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="10">
          <div class="empty-state">当前筛选条件下没有漏洞记录。</div>
        </td>
      </tr>
    `;
    updateBulkSelectionUi();
    return;
  }

  tbody.innerHTML = pageRows
    .map(
      (item, index) => `
        <tr class="${item.id === selectedVulnerabilityId ? "selected" : ""}" data-id="${escapeHtml(item.id)}">
          <td><input type="checkbox" data-row-select="${escapeHtml(item.id)}" ${selectedVulnerabilityIds.has(item.id) ? "checked" : ""} aria-label="选择 ${escapeHtml(item.id)}" /></td>
          <td>${escapeHtml(item.id)}</td>
          <td>
            <span class="vuln-type">
              <span class="type-icon">${escapeHtml(item.method)}</span>
              ${escapeHtml(item.type)}
            </span>
          </td>
          <td><span class="badge ${riskClass(item.risk)}">${escapeHtml(item.risk)}</span></td>
          <td>${escapeHtml(item.location)}</td>
          <td><span class="method">${escapeHtml(item.method)}</span></td>
          <td title="${escapeHtml(item.evidenceText || "")}">&lt;/&gt; ${escapeHtml(item.evidence)}</td>
          <td><span class="${statusClass(item.status)}">● ${item.status}</span></td>
          <td>${escapeHtml(item.time)}</td>
          <td>
            <span class="action-cell">
              <button class="mini-action" data-action="view" data-id="${escapeHtml(item.id)}" aria-label="查看 ${escapeHtml(item.id)}">⌕</button>
              <button class="mini-action" data-action="more" data-id="${escapeHtml(item.id)}" aria-label="更多 ${escapeHtml(item.id)}">⋮</button>
            </span>
          </td>
        </tr>
      `,
    )
    .join("");

  tbody.querySelectorAll("tr[data-id]").forEach((row) => {
    row.addEventListener("click", () => selectVulnerability(row.dataset.id));
  });

  tbody.querySelectorAll("[data-row-select]").forEach((checkbox) => {
    checkbox.addEventListener("click", (event) => {
      event.stopPropagation();
      const id = checkbox.dataset.rowSelect;
      if (checkbox.checked) {
        selectedVulnerabilityIds.add(id);
      } else {
        selectedVulnerabilityIds.delete(id);
      }
      updateBulkSelectionUi();
    });
  });

  tbody.querySelectorAll("[data-action='view']").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      selectVulnerability(button.dataset.id);
      showVulnerabilityModal();
    });
  });

  tbody.querySelectorAll("[data-action='more']").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      selectVulnerability(button.dataset.id);
      showModal(
        "更多操作",
        `<div class="modal-actions">
          <button data-modal-action="advice">生成修复建议</button>
          <button data-modal-action="export">预览报告</button>
          <button data-modal-action="fixed">标记为已修复</button>
        </div>`,
      );
    });
  });
  updateBulkSelectionUi();
}

function updateBulkSelectionUi() {
  const selectAll = document.querySelector("#selectAllVulnerabilities");
  const pageRows = currentPageVulnerabilities();
  if (selectAll) {
    const selectedOnPage = pageRows.filter((item) => selectedVulnerabilityIds.has(item.id)).length;
    selectAll.checked = pageRows.length > 0 && selectedOnPage === pageRows.length;
    selectAll.indeterminate = selectedOnPage > 0 && selectedOnPage < pageRows.length;
  }
  const totalNode = document.querySelector("#vulnerabilityTotal");
  if (totalNode) {
    const total = filteredVulnerabilities().length;
    totalNode.textContent = selectedVulnerabilityIds.size ? `共 ${total} 条，已选 ${selectedVulnerabilityIds.size} 条` : `共 ${total} 条`;
  }
  document.querySelector("#bulkInProgressButton")?.toggleAttribute("disabled", selectedVulnerabilityIds.size === 0);
  document.querySelector("#bulkFixedButton")?.toggleAttribute("disabled", selectedVulnerabilityIds.size === 0);
}

function selectVulnerability(id) {
  selectedVulnerabilityId = id;
  drawerOpen = true;
  document.querySelector(".detail-drawer").classList.remove("drawer-closed");
  renderRows();
  renderDetail();
}

function openAiFixForVulnerability(id) {
  selectedVulnerabilityId = id;
  setActiveNavigation("ai-fix");
  history.replaceState(null, "", "#ai-fix");
  renderFeaturePage("ai-fix");
  showToast(`已打开 ${selectedVulnerabilityId} 的 AI 修复详情`);
}

function renderDetail() {
  const item = selectedItem();
  const detail = document.querySelector("#detailContent");
  if (!detail) {
    return;
  }
  if (!item) {
    detail.innerHTML = `
      <section class="detail-card">
        <h4>暂无漏洞</h4>
        <p class="detail-copy">当前扫描结果没有漏洞记录。启动一次后端扫描后，这里会展示真实漏洞详情。</p>
      </section>
    `;
    return;
  }

  detail.innerHTML = `
    <section class="detail-hero">
      <div class="threat-icon">!</div>
      <div>
        <span class="badge ${riskClass(item.risk)}">${escapeHtml(item.risk)}</span>
        <span class="muted-id">${escapeHtml(item.id)}</span>
        <h3>${escapeHtml(item.type)}</h3>
        <p class="${statusClass(item.status)}">● ${escapeHtml(item.status)}</p>
      </div>
    </section>

    <section class="detail-card">
      <h4>快速摘要</h4>
      <dl class="detail-list">
        <div><dt>位置</dt><dd>${escapeHtml(item.location)}</dd></div>
        <div><dt>检测方式</dt><dd><span class="method">${escapeHtml(item.method)}</span></dd></div>
        <div><dt>请求方法</dt><dd>${escapeHtml(item.requestMethod || "-")}</dd></div>
        <div><dt>风险等级</dt><dd><span class="badge ${riskClass(item.risk)}">${escapeHtml(item.risk)}</span></dd></div>
        <div><dt>修复优先级</dt><dd>${escapeHtml(item.remediationPriority || "P3")}</dd></div>
        <div><dt>首次发现</dt><dd>${escapeHtml(item.discoveredAt || item.time)}</dd></div>
        <div><dt>最后更新</dt><dd>${escapeHtml(item.discoveredAt || item.time)}</dd></div>
      </dl>
    </section>

    <section class="detail-card">
      <h4>漏洞描述</h4>
      <p class="detail-copy">${escapeHtml(item.description)}</p>
    </section>

    <section class="detail-card">
      <h4>受影响组件</h4>
      <dl class="detail-list">
        <div><dt>组件</dt><dd>${escapeHtml(item.component)}</dd></div>
        <div><dt>扫描规则</dt><dd>${escapeHtml(item.scannerRule || "-")}</dd></div>
        <div><dt>证据数量</dt><dd>${escapeHtml(item.evidence)}</dd></div>
        <div><dt>状态</dt><dd><span class="${statusClass(item.status)}">● ${escapeHtml(item.status)}</span></dd></div>
      </dl>
    </section>

    ${item.payload ? `
    <section class="detail-card">
      <h4>测试输入</h4>
      <p class="detail-copy">${escapeHtml(item.payload)}</p>
    </section>
    ` : ""}

    <div class="drawer-actions">
      <button class="drawer-action primary" data-detail-action="view">查看详情</button>
      <button class="drawer-action warning" data-detail-action="advice">生成修复建议</button>
      <button class="drawer-action info" data-detail-action="export">预览报告</button>
      <button class="drawer-action muted" data-detail-action="status:修复中">修复中</button>
      <button class="drawer-action muted" data-detail-action="status:已修复">已修复</button>
      <button class="drawer-action muted" data-detail-action="status:已忽略">已忽略</button>
      <button class="drawer-action muted" data-detail-action="status:误报">误报</button>
    </div>
  `;

  detail.querySelectorAll("[data-detail-action]").forEach((button) => {
    button.addEventListener("click", () => runDetailAction(button.dataset.detailAction));
  });
}

function showVulnerabilityModal() {
  const item = selectedItem();
  if (!item) {
    showModal("漏洞详情", `<p class="modal-copy">当前没有可查看的漏洞记录。</p>`);
    return;
  }
  showModal(
    `${escapeHtml(item.id)} 漏洞详情`,
    `<dl class="modal-detail">
      <div><dt>漏洞类型</dt><dd>${escapeHtml(item.type)}</dd></div>
      <div><dt>风险等级</dt><dd>${escapeHtml(item.risk)}</dd></div>
      <div><dt>检测位置</dt><dd>${escapeHtml(item.location)}</dd></div>
      <div><dt>检测方式</dt><dd>${escapeHtml(item.method)}</dd></div>
      <div><dt>请求方法</dt><dd>${escapeHtml(item.requestMethod || "-")}</dd></div>
      <div><dt>扫描规则</dt><dd>${escapeHtml(item.scannerRule || "-")}</dd></div>
      <div><dt>修复优先级</dt><dd>${escapeHtml(item.remediationPriority || "P3")}</dd></div>
      <div><dt>当前状态</dt><dd>${escapeHtml(item.status)}</dd></div>
      <div><dt>证据数量</dt><dd>${escapeHtml(item.evidence)}</dd></div>
    </dl>
    <p class="modal-copy">${escapeHtml(item.description)}</p>
    ${item.payload ? `<div class="code-suggestion"><strong>测试输入</strong><span>${escapeHtml(item.payload)}</span></div>` : ""}
    ${item.evidenceText ? `<div class="code-suggestion"><strong>检测证据</strong><span>${escapeHtml(item.evidenceText)}</span></div>` : ""}`,
  );
}

async function showAdviceModal() {
  const item = selectedItem();
  if (!item) {
    showModal("AI 修复建议", `<p class="modal-copy">当前没有可生成建议的漏洞记录。</p>`);
    return;
  }
  if (activeTaskId) {
    try {
      const data = await apiRequest(`/vulnerability/${item.id}/ai-advice`, {
        method: "POST",
        body: JSON.stringify({ task_id: activeTaskId }),
      });
      item.advice = data.ai_advice || item.advice;
      item.adviceSource = data.ai_advice_source || item.adviceSource;
    } catch (error) {
      addEvent("WARN", `AI 建议接口调用失败，使用当前建议：${error.message}`);
    }
  }
  addEvent("INFO", `已为 ${item.id} 生成 AI 修复建议`);
  showModal(
    "AI 修复建议",
    `<p class="modal-copy">${escapeHtml(item.advice)}</p>
    <div class="code-suggestion">
      <strong>调用路径</strong>
      <span>后端接口 /api/vulnerability/${escapeHtml(item.id)}/ai-advice</span>
    </div>
    <div class="code-suggestion">
      <strong>实际来源</strong>
      <span>${escapeHtml(item.adviceSource || "unknown")}${item.adviceSource === "local-template" ? "（未配置可用 API Key 时自动兜底）" : ""}</span>
    </div>
    <div class="code-suggestion">
      <strong>建议优先级</strong>
      <span>${escapeHtml(item.risk === "Critical" ? "立即修复" : "本轮迭代修复")}</span>
    </div>`,
  );
  showToast("AI 修复建议已生成");
}

function exportReport() {
  const item = selectedItem();
  if (activeTaskId && (latestReports.html_url || latestReports.markdown_url)) {
    const url = latestReports.html_url || latestReports.markdown_url;
    window.open(apiUrl(url), "_blank", "noopener");
    addEvent("INFO", `已打开 ${activeTaskId} 的后端 HTML 报告`);
    showToast("已打开渲染后的 HTML 报告");
    return;
  }
  if (!item) {
    showModal("预览报告", `<p class="modal-copy">当前没有可预览的扫描报告。</p>`);
    return;
  }
  const report = `# 安全扫描报告

## 漏洞摘要

- 编号：${item.id}
- 类型：${item.type}
- 风险等级：${item.risk}
- 位置：${item.location}
- 检测方式：${item.method}
- 请求方法：${item.requestMethod || "-"}
- 扫描规则：${item.scannerRule || "-"}
- 测试输入：${item.payload || "-"}
- 修复优先级：${item.remediationPriority || "P3"}
- 状态：${item.status}

## 漏洞描述

${item.description}

## AI 修复建议

建议来源：${item.adviceSource || "unknown"}

${item.advice}
`;

  const blob = new Blob([report], { type: "text/markdown;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = `${item.id}-security-report.md`;
  link.click();
  URL.revokeObjectURL(url);
  addEvent("INFO", `已导出 ${item.id} 的 Markdown 报告`);
  showToast("漏洞摘要已下载为 Markdown");
}

async function updateSelectedStatus(status) {
  const item = selectedItem();
  if (!item) {
    showToast("当前没有可标记的漏洞");
    return;
  }
  if (activeTaskId) {
    try {
      await apiRequest(`/vulnerability/${item.id}/status`, {
        method: "PATCH",
        body: JSON.stringify({ task_id: activeTaskId, status }),
      });
    } catch (error) {
      addEvent("WARN", `后端状态更新失败，仅更新前端状态：${error.message}`);
    }
  }
  item.status = status;
  addEvent("INFO", `${item.id} 状态已更新为 ${status}`);
  renderSummary();
  renderRows();
  renderDetail();
  showToast(`${item.id} 状态已更新为 ${status}`);
}

async function updateBulkStatus(status) {
  const ids = [...selectedVulnerabilityIds];
  if (!ids.length) {
    showToast("请先选择漏洞");
    return;
  }
  for (const id of ids) {
    const item = vulnerabilities.find((vulnerability) => vulnerability.id === id);
    if (!item) {
      continue;
    }
    if (activeTaskId) {
      try {
        await apiRequest(`/vulnerability/${id}/status`, {
          method: "PATCH",
          body: JSON.stringify({ task_id: activeTaskId, status }),
        });
      } catch (error) {
        addEvent("WARN", `${id} 后端状态更新失败：${error.message}`);
      }
    }
    item.status = status;
  }
  addEvent("INFO", `已将 ${ids.length} 个漏洞批量标记为 ${status}`);
  selectedVulnerabilityIds.clear();
  renderSummary();
  renderRows();
  renderDetail();
  showToast(`已批量标记为 ${status}`);
}

function runDetailAction(action) {
  if (action?.startsWith("status:")) {
    updateSelectedStatus(action.slice("status:".length));
    return;
  }
  const actions = {
    view: showVulnerabilityModal,
    advice: showAdviceModal,
    export: exportReport,
  };
  actions[action]?.();
}

function bindScanPageControls() {
  document.querySelector("#editTargetButton")?.addEventListener("click", () => {
    showModal(
      "编辑扫描目标",
      `<form class="mock-form">
        <label>目标地址<input id="targetBaseUrlInput" value="${escapeHtml(scanTarget.base_url)}" /></label>
        <label>源码路径<input id="targetProjectPathInput" value="${escapeHtml(scanTarget.project_path)}" /></label>
        <label>扫描类型<input value="深度扫描 (DAST + SAST)" disabled /></label>
        <button type="button" id="saveMockTarget">保存配置</button>
      </form>`,
    );
    document.querySelector("#saveMockTarget")?.addEventListener("click", () => {
      const baseUrl = document.querySelector("#targetBaseUrlInput")?.value.trim() || defaultTarget.base_url;
      const projectPath = document.querySelector("#targetProjectPathInput")?.value.trim() || defaultTarget.project_path;
      saveBackendSettings(baseUrl, projectPath)
        .catch(() => {
          scanTarget = { base_url: baseUrl, project_path: projectPath };
          renderTargetInfo();
        })
        .finally(() => {
          closeModal();
          showToast("扫描目标已保存");
        });
    });
  });

  document.querySelector("#startScanButton")?.addEventListener("click", startBackendScan);

  document.querySelector("#clearEventsButton")?.addEventListener("click", () => {
    events = [];
    renderEvents();
    showToast("实时事件流已清空");
  });

  document.querySelector("#refreshButton")?.addEventListener("click", async () => {
    if (activeTaskId) {
      await pollScanStatus();
    } else {
      resetScanWorkspace();
      renderAllScanData();
      addEvent("INFO", backendConnected ? "已连接后端，当前没有扫描任务" : "后端未连接，当前没有扫描任务");
    }
    showToast("扫描状态已刷新");
  });

  document.querySelectorAll(".filter-button").forEach((button) => {
    button.addEventListener("click", () => {
      currentFilter = button.dataset.filter;
      currentScanPage = 1;
      document.querySelectorAll(".filter-button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      renderRows();
      showToast(`已筛选 ${currentFilter} 漏洞`);
    });
  });

  document.querySelector("#statusFilter")?.addEventListener("change", (event) => {
    currentStatus = event.target.value;
    currentScanPage = 1;
    renderRows();
    showToast(`状态筛选：${currentStatus}`);
  });

  document.querySelector("#bulkInProgressButton")?.addEventListener("click", () => updateBulkStatus("修复中"));
  document.querySelector("#bulkFixedButton")?.addEventListener("click", () => updateBulkStatus("已修复"));

  document.querySelector("#selectAllVulnerabilities")?.addEventListener("change", (event) => {
    const checked = event.target.checked;
    currentPageVulnerabilities().forEach((item) => {
      if (checked) {
        selectedVulnerabilityIds.add(item.id);
      } else {
        selectedVulnerabilityIds.delete(item.id);
      }
    });
    renderRows();
    showToast(checked ? "已选择当前页漏洞" : "已取消当前页选择");
  });

}

function renderScanPage() {
  document.querySelector(".workspace").innerHTML = initialWorkspaceTemplate;
  document.querySelector(".drawer-header h2").textContent = "漏洞详情";
  document.querySelector(".detail-drawer").classList.remove("drawer-closed");
  renderTargetInfo();
  updateProgress(currentProgress, currentScanTitle, currentScanSubtitle);
  renderModules();
  renderSteps();
  renderEvents();
  renderSummary();
  renderRows();
  renderDetail();
  bindScanPageControls();
}

function metricCard(label, value, tone = "total") {
  return `
    <article class="summary-card ${tone}">
      <div>
        <span>${label}</span>
        <strong>${value}</strong>
      </div>
      <span class="summary-icon">!</span>
    </article>
  `;
}

function featureTable(headers, rows, rowOptions = {}) {
  if (!rows.length) {
    return `<div class="empty-state">暂无真实后端数据。请先在“扫描管理”启动一次扫描。</div>`;
  }
  return `
    <div class="feature-table">
      <table>
        <thead>
          <tr>${headers.map((header) => `<th>${header}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${rows.map((row) => {
            const rowId = rowOptions.getRowId?.(row) || "";
            const selectedClass = rowId && rowId === selectedVulnerabilityId ? " class=\"selected\"" : "";
            const rowAttr = rowId ? ` data-vuln-row-id="${escapeHtml(rowId)}"` : "";
            return `<tr${selectedClass}${rowAttr}>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`;
          }).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function pageTemplate(page) {
  const vulnerabilityRows = vulnerabilities.map((item) => [
    escapeHtml(item.id),
    `<button class="mini-text-button" data-view-fix-vuln-id="${escapeHtml(item.id)}">详情</button>`,
    escapeHtml(item.type),
    escapeHtml(item.remediationPriority || "P3"),
    safeRiskBadge(item.risk),
    escapeHtml(item.location),
    `<span class="method">${escapeHtml(item.method)}</span>`,
    `<span class="${statusClass(item.status)}">● ${item.status}</span>`,
  ]);
  const assetRows = assetRecords.map((item) => [
    escapeHtml(item.name),
    escapeHtml(item.address),
    escapeHtml(item.type),
    escapeHtml(item.task_id || "-"),
    safeRiskBadge(item.risk),
    `${escapeHtml(item.last_scan_at || "-")}<br><button class="mini-text-button" data-asset-scan="${escapeHtml(item.id)}">扫描</button><button class="mini-text-button" data-asset-delete="${escapeHtml(item.id)}">删除</button>`,
  ]);
  const reportRows = reportRecords.map((item) => [
    escapeHtml(item.name),
    escapeHtml(item.target?.base_url || item.target?.project_path || "-"),
    safeRiskBadge(item.risk?.overall_risk),
    "HTML / MD",
    escapeHtml(item.generated_at || "-"),
    `<button class="mini-text-button" data-report-url="${escapeHtml(item.html_url)}">预览 HTML</button><button class="mini-text-button" data-report-url="${escapeHtml(item.markdown_url)}">打开 MD</button><button class="mini-text-button" data-report-rename="${escapeHtml(item.task_id)}">重命名</button><button class="mini-text-button" data-report-delete="${escapeHtml(item.task_id)}">删除</button>`,
  ]);
  const taskRows = taskRecords.map((item) => {
    const canCancel = item.status === "running" || item.status === "cancelling";
    return [
      escapeHtml(item.task_id),
      escapeHtml(item.target?.base_url || "-"),
      "Full",
      escapeHtml(item.created_at || "-"),
      statusLabel(item.status),
      `${escapeHtml(item.progress ?? 0)}%<br><button class="mini-text-button" data-task-rerun="${escapeHtml(item.task_id)}">重跑</button>${canCancel ? `<button class="mini-text-button" data-task-cancel="${escapeHtml(item.task_id)}">取消</button>` : ""}<button class="mini-text-button" data-task-delete="${escapeHtml(item.task_id)}">删除</button>`,
    ];
  });
  const currentTask = latestTask();
  const currentFixItem = selectedItem() || vulnerabilities[0] || null;

  const templates = {
    vulnerabilities: {
      title: "漏洞管理",
      subtitle: "集中查看、筛选、分派和跟踪所有扫描发现的安全漏洞。",
      metrics: [
        metricCard("总漏洞数", vulnerabilities.length),
        metricCard("严重漏洞", vulnerabilities.filter((item) => item.risk === "Critical").length, "critical"),
        metricCard("高危漏洞", vulnerabilities.filter((item) => item.risk === "High").length, "high"),
        metricCard("待修复", vulnerabilities.filter((item) => item.status === "未修复").length, "medium"),
      ].join(""),
      body: featureTable(["编号", "操作", "漏洞类型", "优先级", "风险等级", "位置", "检测方式", "状态"], vulnerabilityRows, {
        getRowId: (row) => row[0],
      }),
      drawer:
        `当前共有 ${vulnerabilities.length} 个漏洞，未修复 ${vulnerabilities.filter((item) => item.status === "未修复").length} 个，修复中 ${vulnerabilities.filter((item) => item.status === "修复中").length} 个，已修复 ${vulnerabilities.filter((item) => item.status === "已修复").length} 个。`,
    },
    assets: {
      title: "资产管理",
      subtitle: "根据真实扫描任务自动汇总目标 URL 和源码目录。",
      metrics: [
        metricCard("资产数", assetRecords.length),
        metricCard("Web 应用", assetRecords.filter((item) => item.type === "Web 应用").length, "low"),
        metricCard("高风险资产", assetRecords.filter((item) => ["High", "Critical"].includes(item.risk)).length, "critical"),
        metricCard("最近扫描", assetRecords[0]?.last_scan_at?.split(" ").pop() || "-"),
      ].join(""),
      body: featureTable(["资产名称", "地址", "类型", "来源任务", "风险", "最近扫描"], assetRows),
      drawer:
        `当前资产库有 ${assetRecords.length} 条记录，可新增资产、删除资产，并从资产直接发起扫描。`,
    },
    reports: {
      title: "报告中心",
      subtitle: "统一管理后端扫描任务生成的 Markdown 和 HTML 报告。",
      metrics: [
        metricCard("报告总数", reportRecords.length),
        metricCard("已完成任务", taskRecords.filter((item) => item.status === "completed").length, "low"),
        metricCard("Critical 报告", reportRecords.filter((item) => item.risk?.overall_risk === "Critical").length, "critical"),
        metricCard("可导出格式", "2"),
      ].join(""),
      body: featureTable(["报告名称", "目标", "风险等级", "格式", "生成时间", "操作"], reportRows),
      drawer:
        `当前报告中心有 ${reportRecords.length} 份报告。预览会打开 HTML 渲染报告，打开 MD 会显示 Markdown 原文。`,
    },
    "ai-fix": {
      title: "AI 修复",
      subtitle: "基于真实扫描漏洞展示中文解释、证据和修复建议。",
      metrics: [
        metricCard("漏洞数", vulnerabilities.length),
        metricCard("已有建议", vulnerabilities.filter((item) => item.advice).length, "low"),
        metricCard("高优先级", vulnerabilities.filter((item) => ["Critical", "High"].includes(item.risk)).length, "critical"),
        metricCard("建议来源", activeTaskId ? "后端" : "本地"),
      ].join(""),
      body: vulnerabilities.length
        ? `
        <div class="ai-layout">
          <section class="detail-card">
            <h4>选择漏洞</h4>
            <div class="fix-list">
              ${vulnerabilities.map((item) => `
                <button class="${item.id === currentFixItem?.id ? "active" : ""}" data-fix-vuln-id="${escapeHtml(item.id)}">
                  <span>${escapeHtml(item.id)}</span>
                  <strong>${escapeHtml(item.type)}</strong>
                  <em>${escapeHtml(item.remediationPriority || item.risk)}</em>
                </button>
              `).join("")}
            </div>
          </section>
          <section class="detail-card">
            <h4>${escapeHtml(currentFixItem?.id || "")} 修复建议</h4>
            <p class="detail-copy">建议来源：${escapeHtml(currentFixItem?.adviceSource || "unknown")}</p>
            <p class="detail-copy">${escapeHtml(currentFixItem?.advice || "暂无建议，可点击下方按钮生成。")}</p>
            <div class="code-compare">
              <div>
                <strong>检测证据</strong>
                <code>${escapeHtml(currentFixItem?.evidenceText || currentFixItem?.description || "-")}</code>
              </div>
              <div>
                <strong>扫描规则</strong>
                <code>${escapeHtml(currentFixItem?.scannerRule || "-")}</code>
              </div>
              <div>
                <strong>测试输入</strong>
                <code>${escapeHtml(currentFixItem?.payload || "-")}</code>
              </div>
              <div>
                <strong>影响位置</strong>
                <code>${escapeHtml(currentFixItem?.location || "-")}</code>
              </div>
            </div>
            <button class="drawer-action warning ai-generate-button" data-ai-action="generate">调用后端 AI 接口生成建议</button>
          </section>
        </div>
      `
        : `<div class="empty-state">暂无真实漏洞记录。请先在“扫描管理”启动一次扫描。</div>`,
      drawer:
        `当前选中 ${currentFixItem?.id || "无"}。建议来源会显示为模型 provider 或 local-template，生成后的建议会保存到后端。`,
    },
    schedule: {
      title: "任务调度",
      subtitle: "查看后端扫描任务队列和执行历史。",
      metrics: [
        metricCard("任务总数", taskRecords.length),
        metricCard("运行中", taskRecords.filter((item) => item.status === "running").length, "low"),
        metricCard("失败任务", taskRecords.filter((item) => item.status === "failed").length, "critical"),
        metricCard("最近进度", currentTask ? `${currentTask.progress}%` : "-"),
      ].join(""),
      body: featureTable(["任务 ID", "目标", "扫描模式", "创建时间", "状态", "进度"], taskRows),
      drawer:
        `当前任务历史 ${taskRecords.length} 条，运行中 ${taskRecords.filter((item) => item.status === "running").length} 条，失败 ${taskRecords.filter((item) => item.status === "failed").length} 条。`,
    },
    settings: {
      title: "系统设置",
      subtitle: "配置扫描目标、源码路径和 AI 修复建议接口。",
      metrics: [
        metricCard("API 地址", backendConnected ? "已连接" : "未连接"),
        metricCard("任务数", taskRecords.length, "low"),
        metricCard("默认目标", scanTarget.base_url.replace(/^https?:\/\//, ""), "medium"),
        metricCard("AI Key", aiSettings.key_configured ? "已配置" : "未配置", aiSettings.key_configured ? "low" : "high"),
      ].join(""),
      body: `
        <form class="settings-grid">
          <label>后端 API 地址<input value="${escapeHtml(API_BASE)}" disabled /></label>
          <label>默认目标地址<input id="settingsBaseUrl" value="${escapeHtml(scanTarget.base_url)}" /></label>
          <label>默认源码路径<input id="settingsProjectPath" value="${escapeHtml(scanTarget.project_path)}" /></label>
          <label>任务存储方式<input value="SQLite 本地持久化" disabled /></label>
          <button type="button" class="drawer-action info" id="saveSettingsButton">应用到下一次扫描</button>
        </form>
        <form class="settings-grid ai-key-grid">
          <label>大模型服务
            <select id="settingsAiProvider">
              <option value="qwen" ${aiSettings.provider === "qwen" || !aiSettings.provider ? "selected" : ""}>千问 Qwen</option>
              <option value="deepseek" ${aiSettings.provider === "deepseek" ? "selected" : ""}>DeepSeek</option>
              <option value="openai" ${aiSettings.provider === "openai" ? "selected" : ""}>OpenAI</option>
            </select>
          </label>
          <label>API Key<input id="settingsAiKey" type="password" autocomplete="off" placeholder="${aiSettings.key_configured ? "已配置，重新输入可覆盖" : "输入 API Key 后保存"}" /></label>
          <label>当前 AI 状态<input value="${aiSettings.key_configured ? `已配置 ${aiSettings.provider || "AI"} 密钥` : "未配置，使用本地模板兜底"}" disabled /></label>
          <button type="button" class="drawer-action info" id="saveAiKeyButton">保存 AI Key</button>
          <button type="button" class="drawer-action muted" id="testAiKeyButton">测试 AI 连接</button>
        </form>
      `,
      drawer:
        "默认目标和源码路径会写入 SQLite。API Key 不写入数据库，当前输入只保存到后端进程；长期使用请写入本地 .env。",
    },
  };

  return templates[page];
}

function featureStatusCopy(page) {
  if (!backendConnected) {
    return "后端未连接。请确认 vulnerable_app 和 serve_app.py 已启动。";
  }
  const latest = latestTask();
  const copies = {
    vulnerabilities: `数据来自最近扫描任务 ${activeTaskId || latest?.task_id || "-"}，当前筛选条件下显示 ${filteredVulnerabilities().length} 条漏洞。`,
    assets: `资产数据已持久化到 SQLite，刷新页面或重启服务后不会丢失。`,
    reports: `报告内容来自后端生成的 HTML/Markdown，已持久化到 SQLite。`,
    "ai-fix": aiSettings.key_configured
      ? `AI 接口已配置：${aiSettings.provider || aiSettings.runtime_provider || "unknown"}。`
      : "未配置 API Key 时会使用本地中文模板兜底生成修复建议。",
    schedule: latest ? `最近任务 ${latest.task_id}：${statusLabel(latest.status)}，进度 ${latest.progress}%。` : "当前没有任务历史。",
    settings: `当前默认目标：${scanTarget.base_url}；源码路径：${scanTarget.project_path}。`,
  };
  return copies[page] || "已连接后端 API。";
}

async function renderFeaturePage(page) {
  if (page === "scan") {
    renderScanPage();
    return;
  }

  await loadPlatformData();
  const template = pageTemplate(page);
  document.querySelector(".workspace").innerHTML = `
    <section class="feature-page panel">
      <div class="feature-header">
        <div>
          <h1>${template.title}</h1>
          <p>${template.subtitle}</p>
        </div>
        <div class="feature-actions">
          ${page === "assets" ? `<button class="ghost-button" data-feature-action="add-asset">新增资产</button>` : ""}
          ${page === "schedule" ? `<button class="ghost-button" data-feature-action="clear-tasks">清空任务</button>` : ""}
          <button class="ghost-button" data-feature-action="refresh">刷新</button>
        </div>
      </div>
      <div class="summary-grid">${template.metrics}</div>
      <div class="feature-body">${template.body}</div>
    </section>
  `;

  document.querySelector(".drawer-header h2").textContent = template.title;
  document.querySelector(".detail-drawer").classList.remove("drawer-closed");
  document.querySelector("#detailContent").innerHTML = `
    <section class="detail-card">
      <h4>数据摘要</h4>
      <p class="detail-copy">${template.drawer}</p>
    </section>
    <section class="detail-card">
      <h4>当前状态</h4>
      <p class="detail-copy">${featureStatusCopy(page)}</p>
    </section>
  `;

  document.querySelector("#saveSettingsButton")?.addEventListener("click", async () => {
    const button = document.querySelector("#saveSettingsButton");
    const baseUrl = document.querySelector("#settingsBaseUrl")?.value.trim();
    const projectPath = document.querySelector("#settingsProjectPath")?.value.trim();
    if (!baseUrl || !projectPath) {
      showToast("默认目标地址和源码路径不能为空");
      return;
    }
    button?.setAttribute("disabled", "true");
    try {
      await saveBackendSettings(baseUrl, projectPath);
      await loadBackendSettings();
      await renderFeaturePage("settings");
      showToast("系统设置已保存到后端");
    } catch (error) {
      showToast(`系统设置保存失败：${error.message}`);
    } finally {
      button?.removeAttribute("disabled");
    }
  });

  document.querySelector("#saveAiKeyButton")?.addEventListener("click", async () => {
    const button = document.querySelector("#saveAiKeyButton");
    const provider = document.querySelector("#settingsAiProvider")?.value || "qwen";
    const apiKey = document.querySelector("#settingsAiKey")?.value.trim();
    if (!apiKey) {
      showToast("请输入 API Key");
      return;
    }
    button?.setAttribute("disabled", "true");
    try {
      await saveAiKey(provider, apiKey);
      await loadBackendSettings();
      await renderFeaturePage("settings");
      showToast("AI Key 已保存到后端进程");
    } catch (error) {
      showToast(`AI Key 保存失败：${error.message}`);
    } finally {
      button?.removeAttribute("disabled");
    }
  });

  document.querySelector("#testAiKeyButton")?.addEventListener("click", async () => {
    const button = document.querySelector("#testAiKeyButton");
    const provider = document.querySelector("#settingsAiProvider")?.value || "qwen";
    button?.setAttribute("disabled", "true");
    try {
      const result = await apiRequest("/settings/ai-test", {
        method: "PATCH",
        body: JSON.stringify({ provider }),
      });
      showModal(
        "AI 连接测试",
        `<p class="modal-copy">连接成功：${escapeHtml(result.message || "")}</p>
        <div class="code-suggestion"><strong>来源</strong><span>${escapeHtml(result.source || provider)}</span></div>`,
      );
    } catch (error) {
      showModal(
        "AI 连接测试",
        `<p class="modal-copy">连接失败：${escapeHtml(error.message)}</p>
        <div class="code-suggestion"><strong>当前状态</strong><span>将使用本地模板兜底</span></div>`,
      );
    } finally {
      button?.removeAttribute("disabled");
    }
  });

  document.querySelectorAll("[data-feature-action]").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.featureAction === "add-asset") {
        showModal(
          "新增资产",
          `<form class="mock-form">
            <label>资产名称<input id="assetNameInput" value="本地靶场" /></label>
            <label>资产地址<input id="assetAddressInput" value="${escapeHtml(scanTarget.base_url)}" /></label>
            <label>源码路径<input id="assetProjectPathInput" value="${escapeHtml(scanTarget.project_path)}" /></label>
            <label>资产类型<select id="assetTypeInput"><option>Web 应用</option><option>Codebase</option></select></label>
            <label>负责人<input id="assetOwnerInput" placeholder="owner" /></label>
            <label>标签<input id="assetTagsInput" placeholder="local, lab" /></label>
            <button type="button" id="saveAssetButton">保存资产</button>
          </form>`,
        );
        document.querySelector("#saveAssetButton")?.addEventListener("click", async () => {
          const address = document.querySelector("#assetAddressInput")?.value.trim();
          if (!address) {
            showToast("资产地址不能为空");
            return;
          }
          await apiRequest("/assets", {
            method: "POST",
            body: JSON.stringify({
              name: document.querySelector("#assetNameInput")?.value.trim(),
              address,
              project_path: document.querySelector("#assetProjectPathInput")?.value.trim(),
              type: document.querySelector("#assetTypeInput")?.value,
              owner: document.querySelector("#assetOwnerInput")?.value.trim(),
              tags: document.querySelector("#assetTagsInput")?.value.trim(),
            }),
          });
          closeModal();
          await loadPlatformData();
          renderFeaturePage("assets");
          showToast("资产已保存");
        });
        return;
      }
      if (button.dataset.featureAction === "clear-tasks") {
        if (!window.confirm("确定清空全部任务历史吗？报告和资产不会被删除。")) {
          return;
        }
        await apiRequest("/tasks", { method: "DELETE" });
        await loadPlatformData();
        renderFeaturePage("schedule");
        showToast("任务历史已清空");
        return;
      }
      await loadPlatformData();
      renderFeaturePage(page);
      showToast(`${template.title}已刷新`);
    });
  });

  document.querySelectorAll("[data-fix-vuln-id]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedVulnerabilityId = button.dataset.fixVulnId;
      renderFeaturePage("ai-fix");
    });
  });

  document.querySelector("[data-ai-action='generate']")?.addEventListener("click", async () => {
    await showAdviceModal();
    renderFeaturePage("ai-fix");
  });

  document.querySelectorAll(".feature-body button").forEach((button) => {
    button.addEventListener("click", async () => {
      if (button.dataset.fixVulnId || button.dataset.viewFixVulnId || button.dataset.aiAction) {
        return;
      }
      const reportUrl = button.dataset.reportUrl;
      if (reportUrl) {
        window.open(apiUrl(reportUrl), "_blank", "noopener");
        showToast("已打开后端报告");
        return;
      }
      if (button.dataset.assetScan) {
        const data = await apiRequest(`/assets/${button.dataset.assetScan}/scan`, { method: "POST" });
        activeTaskId = data.task_id;
        await loadPlatformData();
        showToast(`资产扫描已启动：${activeTaskId}`);
        return;
      }
      if (button.dataset.assetDelete) {
        if (!window.confirm("确定删除这个资产吗？")) {
          return;
        }
        await apiRequest(`/assets/${button.dataset.assetDelete}`, { method: "DELETE" });
        await loadPlatformData();
        renderFeaturePage(page);
        showToast("资产已删除");
        return;
      }
      if (button.dataset.taskRerun) {
        const data = await apiRequest(`/scan/${button.dataset.taskRerun}/rerun`, { method: "POST" });
        activeTaskId = data.task_id;
        await loadPlatformData();
        renderFeaturePage(page);
        showToast(`任务已重跑：${activeTaskId}`);
        return;
      }
      if (button.dataset.taskCancel) {
        await apiRequest(`/scan/${button.dataset.taskCancel}/cancel`, { method: "POST" });
        await loadPlatformData();
        renderFeaturePage(page);
        showToast("已请求取消任务");
        return;
      }
      if (button.dataset.taskDelete) {
        if (!window.confirm("确定删除这个扫描任务吗？关联报告记录会保留。")) {
          return;
        }
        await apiRequest(`/scan/${button.dataset.taskDelete}`, { method: "DELETE" });
        await loadPlatformData();
        renderFeaturePage(page);
        showToast("任务已删除");
        return;
      }
      if (button.dataset.reportDelete) {
        if (!window.confirm("确定删除这份报告记录吗？")) {
          return;
        }
        await apiRequest(`/report/${button.dataset.reportDelete}`, { method: "DELETE" });
        await loadPlatformData();
        renderFeaturePage(page);
        showToast("报告已删除");
        return;
      }
      if (button.dataset.reportRename) {
        const current = reportRecords.find((item) => item.task_id === button.dataset.reportRename);
        const name = window.prompt("输入新的报告名称", current?.name || "");
        if (name?.trim()) {
          await apiRequest(`/report/${button.dataset.reportRename}`, {
            method: "PATCH",
            body: JSON.stringify({ name: name.trim() }),
          });
          await loadPlatformData();
          renderFeaturePage(page);
          showToast("报告已重命名");
        }
      }
    });
  });

  document.querySelectorAll(".feature-table tbody tr").forEach((row) => {
    if (row.dataset.vulnRowId) {
      return;
    }
    row.addEventListener("click", () => showToast("已选中一条记录，右侧详情可展示完整信息"));
  });
}

function setActiveNavigation(page) {
  document.querySelectorAll(".side-item").forEach((item) => {
    item.classList.toggle("active", item.dataset.page === page);
  });

  const sideLabel = document.querySelector(`.side-item[data-page="${page}"]`)?.textContent.trim();
  document.querySelectorAll(".topnav-item").forEach((item) => {
    item.classList.toggle("active", item.textContent.trim() === sideLabel);
  });
}

async function showRecentScanEvents() {
  if (backendConnected) {
    await loadPlatformData();
  }
  const taskEvents = taskRecords.flatMap((task) =>
    (task.events || []).map((event) => ({
      taskId: task.task_id,
      time: event.time || task.created_at || "-",
      level: event.level || "INFO",
      text: event.message || event.text || "",
    })),
  );
  const localEvents = events.map((event) => ({
    taskId: activeTaskId || "当前页面",
    time: event.time || "-",
    level: event.level || "INFO",
    text: event.text || "",
  }));
  const recentEvents = [...taskEvents, ...localEvents].slice(-12).reverse();

  showModal(
    "最近扫描事件",
    recentEvents.length
      ? `<div class="notification-list">
          ${recentEvents.map((event) => `
            <div class="notification-item">
              <div>
                <strong>${escapeHtml(event.level)}</strong>
                <span>${escapeHtml(event.taskId)}</span>
              </div>
              <p>${escapeHtml(event.text)}</p>
              <time>${escapeHtml(event.time)}</time>
            </div>
          `).join("")}
        </div>`
      : `<p class="modal-copy">暂无扫描事件。启动一次扫描后，这里会显示后端返回的最近事件。</p>`,
  );
}

function bindChromeInteractions() {
  const navPageMap = {
    扫描管理: "scan",
    漏洞管理: "vulnerabilities",
    资产管理: "assets",
    报告中心: "reports",
    "AI 修复": "ai-fix",
    系统设置: "settings",
  };

  document.addEventListener("click", (event) => {
    const detailButton = event.target.closest("[data-view-fix-vuln-id]");
    if (detailButton) {
      event.stopPropagation();
      openAiFixForVulnerability(detailButton.dataset.viewFixVulnId);
      return;
    }

    const vulnRow = event.target.closest("[data-vuln-row-id]");
    if (vulnRow && !event.target.closest("button")) {
      selectedVulnerabilityId = vulnRow.dataset.vulnRowId;
      renderFeaturePage(location.hash.replace("#", "") || "vulnerabilities");
      showToast(`已选中 ${selectedVulnerabilityId}`);
    }
  });

  document.querySelectorAll(".topnav-item").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".topnav-item").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      const page = navPageMap[button.textContent.trim()];
      if (page) {
        setActiveNavigation(page);
        history.replaceState(null, "", `#${page}`);
        renderFeaturePage(page);
      }
      showToast(`已切换到「${button.textContent.trim()}」`);
    });
  });

  document.querySelectorAll(".side-item").forEach((button) => {
    button.addEventListener("click", () => {
      document.querySelectorAll(".side-item").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      setActiveNavigation(button.dataset.page);
      history.replaceState(null, "", `#${button.dataset.page}`);
      renderFeaturePage(button.dataset.page);
      showToast(`当前菜单：${button.textContent.trim()}`);
    });
  });

  document.querySelector("[data-action='notifications']").addEventListener("click", async () => {
    try {
      await showRecentScanEvents();
    } catch (error) {
      showModal("最近扫描事件", `<p class="modal-copy">扫描事件读取失败：${escapeHtml(error.message)}</p>`);
    }
  });

  document.querySelector("[data-action='help']").addEventListener("click", () => {
    showModal(
      "帮助",
      `<p class="modal-copy">扫描管理、漏洞管理、资产管理、报告中心和任务调度已经接入本地后端 API。系统状态展示后端任务、报告和资产统计。</p>`,
    );
  });

  document.querySelector("#closeDrawerButton").addEventListener("click", () => {
    drawerOpen = false;
    document.querySelector(".detail-drawer").classList.add("drawer-closed");
    showToast("漏洞详情已收起，点击表格行可重新打开");
  });

  document.querySelector("#modalCloseButton").addEventListener("click", closeModal);
  document.querySelector("#modalBackdrop").addEventListener("click", (event) => {
    if (event.target.id === "modalBackdrop") {
      closeModal();
    }
  });

  document.addEventListener("click", (event) => {
    const actionButton = event.target.closest("[data-modal-action]");
    if (!actionButton) {
      return;
    }
    closeModal();
    runDetailAction(actionButton.dataset.modalAction);
  });

  window.addEventListener("hashchange", () => {
    const page = location.hash.replace("#", "");
    if (page && document.querySelector(`.side-item[data-page="${page}"]`)) {
      setActiveNavigation(page);
      renderFeaturePage(page);
    }
  });
}

async function boot() {
  initialWorkspaceTemplate = document.querySelector(".workspace").innerHTML;
  renderTargetInfo();
  renderModules();
  renderSteps();
  renderEvents();
  renderSummary();
  renderRows();
  renderDetail();
  bindScanPageControls();
  bindChromeInteractions();
  await loadBackendSettings();

  const initialPage = location.hash.replace("#", "");
  if (initialPage && document.querySelector(`.side-item[data-page="${initialPage}"]`)) {
    setActiveNavigation(initialPage);
    renderFeaturePage(initialPage);
  }
}

boot();
