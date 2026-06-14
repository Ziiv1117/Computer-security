const modules = [
  { name: "连接目标", state: "进行中" },
  { name: "SQL 注入测试" },
  { name: "XSS 测试" },
  { name: "越权访问测试" },
  { name: "弱密码分析" },
  { name: "AI 修复建议" },
];

const scanSteps = [
  { name: "连接目标", time: "00:00:08", status: "done" },
  { name: "SQL 注入测试", time: "00:02:15", status: "active" },
  { name: "XSS 测试", time: "00:01:43", status: "done" },
  { name: "越权访问测试", time: "00:01:29", status: "done" },
  { name: "弱密码分析", time: "00:01:27", status: "done" },
  { name: "AI 修复建议", time: "等待中", status: "pending" },
];

const initialEvents = [
  { time: "14:32:30", level: "INFO", text: "成功连接目标 https://target.example.com" },
  { time: "14:32:31", level: "INFO", text: "目标响应正常，状态码：200" },
  { time: "14:32:32", level: "INFO", text: "检测到 Web 服务器：Nginx/1.18.0" },
  { time: "14:32:34", level: "INFO", text: "开始 SQL 注入测试模块" },
  { time: "14:32:35", level: "INFO", text: "发现参数：id (GET)" },
  { time: "14:32:36", level: "WARN", text: "参数 id 存在 SQL 注入风险" },
  { time: "14:32:37", level: "RISK", text: "检测到 SQL 注入漏洞 (id)" },
  { time: "14:32:38", level: "INFO", text: "尝试数据库类型：MySQL" },
  { time: "14:32:39", level: "INFO", text: "尝试注入语句：UNION SELECT" },
  { time: "14:32:41", level: "RISK", text: "确认存在 SQL 注入漏洞" },
  { time: "14:32:42", level: "INFO", text: "扫描进度：SQL 注入测试 67%" },
  { time: "14:32:44", level: "INFO", text: "正在分析响应内容..." },
];

let events = [...initialEvents];

const vulnerabilities = [
  {
    id: "VULN-2024-0001",
    type: "SQL Injection",
    risk: "Critical",
    location: "/login",
    method: "DAST",
    evidence: 2,
    status: "未修复",
    time: "14:32:37",
    description:
      "攻击者可通过构造恶意 SQL 语句绕过身份验证，读取、修改或删除数据库中的敏感数据。",
    component: "web-app",
    advice:
      "建议将登录查询改为参数化查询或 ORM 绑定参数，禁止字符串拼接 SQL；同时统一登录失败提示，并为登录接口补充回归测试。",
  },
  {
    id: "VULN-2024-0002",
    type: "Cross-Site Scripting",
    risk: "High",
    location: "/comments",
    method: "DAST",
    evidence: 1,
    status: "未修复",
    time: "14:28:15",
    description:
      "评论内容未进行 HTML 转义，脚本标签可能被原样渲染并在浏览器中执行。",
    component: "comments",
    advice:
      "建议在模板输出层默认开启 HTML 转义；如果允许富文本，使用白名单过滤库，并补充 Content-Security-Policy。",
  },
  {
    id: "VULN-2024-0003",
    type: "Broken Access Control",
    risk: "High",
    location: "/admin",
    method: "DAST",
    evidence: 3,
    status: "未修复",
    time: "14:25:48",
    description:
      "普通用户可访问管理员页面，说明敏感路由缺少服务端权限校验。",
    component: "admin",
    advice:
      "建议在服务端为管理路由添加角色校验，所有敏感资源都要校验当前用户权限，不能只依赖前端隐藏入口。",
  },
  {
    id: "VULN-2024-0004",
    type: "Hardcoded Secret",
    risk: "High",
    location: "app.py:8",
    method: "SAST",
    evidence: 1,
    status: "未修复",
    time: "14:20:31",
    description:
      "源码中疑似包含硬编码密钥，代码泄露后可能导致凭据暴露。",
    component: "source-code",
    advice:
      "建议将密钥迁移到环境变量或密钥管理服务，提交 `.env.example` 而不是 `.env`，并检查 Git 历史中是否泄露过真实凭据。",
  },
  {
    id: "VULN-2024-0005",
    type: "Weak Password Storage",
    risk: "Medium",
    location: "models.py:42",
    method: "SAST",
    evidence: 1,
    status: "未修复",
    time: "14:18:02",
    description:
      "系统疑似使用弱哈希或明文方式处理密码，泄露后容易被离线破解。",
    component: "user-model",
    advice:
      "建议使用 bcrypt、argon2 或 werkzeug.security.generate_password_hash 存储密码，并为每个密码使用独立 salt。",
  },
];

let selectedVulnerabilityId = vulnerabilities[0].id;
let currentFilter = "全部";
let currentStatus = "全部状态";
let drawerOpen = true;
let initialWorkspaceTemplate = "";

const riskClass = (risk) => risk.toLowerCase();
const selectedItem = () =>
  vulnerabilities.find((vulnerability) => vulnerability.id === selectedVulnerabilityId) ??
  vulnerabilities[0];

function currentTime() {
  return new Date().toLocaleTimeString("zh-CN", { hour12: false });
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
  if (!events.length) {
    list.innerHTML = `<div class="empty-state">事件流已清空，点击“刷新”可重新拉取模拟扫描状态。</div>`;
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
  const counts = vulnerabilities.reduce(
    (acc, item) => {
      acc.total += 1;
      acc[item.risk.toLowerCase()] += 1;
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

  document.querySelector("#summaryGrid").innerHTML = cards
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
}

function filteredVulnerabilities() {
  return vulnerabilities.filter((item) => {
    const methodMatch = currentFilter === "全部" || item.method === currentFilter;
    const statusMatch = currentStatus === "全部状态" || item.status === currentStatus;
    return methodMatch && statusMatch;
  });
}

function renderRows() {
  const tbody = document.querySelector("#vulnerabilityRows");
  const rows = filteredVulnerabilities();

  if (!rows.length) {
    tbody.innerHTML = `
      <tr>
        <td colspan="10">
          <div class="empty-state">当前筛选条件下没有漏洞记录。</div>
        </td>
      </tr>
    `;
    return;
  }

  tbody.innerHTML = rows
    .map(
      (item, index) => `
        <tr class="${item.id === selectedVulnerabilityId ? "selected" : ""}" data-id="${item.id}">
          <td><input type="checkbox" ${index === 0 ? "checked" : ""} aria-label="选择 ${item.id}" /></td>
          <td>${item.id}</td>
          <td>
            <span class="vuln-type">
              <span class="type-icon">${item.method}</span>
              ${item.type}
            </span>
          </td>
          <td><span class="badge ${riskClass(item.risk)}">${item.risk}</span></td>
          <td>${item.location}</td>
          <td><span class="method">${item.method}</span></td>
          <td>&lt;/&gt; ${item.evidence}</td>
          <td><span class="${item.status === "已修复" ? "status-fixed" : "status-unfixed"}">● ${item.status}</span></td>
          <td>${item.time}</td>
          <td>
            <span class="action-cell">
              <button class="mini-action" data-action="view" data-id="${item.id}" aria-label="查看 ${item.id}">⌕</button>
              <button class="mini-action" data-action="more" data-id="${item.id}" aria-label="更多 ${item.id}">⋮</button>
            </span>
          </td>
        </tr>
      `,
    )
    .join("");

  tbody.querySelectorAll("tr[data-id]").forEach((row) => {
    row.addEventListener("click", () => selectVulnerability(row.dataset.id));
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
          <button data-modal-action="export">导出报告</button>
          <button data-modal-action="fixed">标记为已修复</button>
        </div>`,
      );
    });
  });
}

function selectVulnerability(id) {
  selectedVulnerabilityId = id;
  drawerOpen = true;
  document.querySelector(".detail-drawer").classList.remove("drawer-closed");
  renderRows();
  renderDetail();
}

function renderDetail() {
  const item = selectedItem();
  const detail = document.querySelector("#detailContent");

  detail.innerHTML = `
    <section class="detail-hero">
      <div class="threat-icon">!</div>
      <div>
        <span class="badge ${riskClass(item.risk)}">${item.risk}</span>
        <span class="muted-id">${item.id}</span>
        <h3>${item.type}</h3>
        <p class="${item.status === "已修复" ? "status-fixed" : "status-line"}">● ${item.status}</p>
      </div>
    </section>

    <section class="detail-card">
      <h4>快速摘要</h4>
      <dl class="detail-list">
        <div><dt>位置</dt><dd>${item.location}</dd></div>
        <div><dt>检测方式</dt><dd><span class="method">${item.method}</span></dd></div>
        <div><dt>风险等级</dt><dd><span class="badge ${riskClass(item.risk)}">${item.risk}</span></dd></div>
        <div><dt>首次发现</dt><dd>2024-06-01 ${item.time}</dd></div>
        <div><dt>最后更新</dt><dd>2024-06-01 ${item.time}</dd></div>
      </dl>
    </section>

    <section class="detail-card">
      <h4>漏洞描述</h4>
      <p class="detail-copy">${item.description}</p>
    </section>

    <section class="detail-card">
      <h4>受影响组件</h4>
      <dl class="detail-list">
        <div><dt>组件</dt><dd>${item.component}</dd></div>
        <div><dt>证据数量</dt><dd>${item.evidence}</dd></div>
        <div><dt>状态</dt><dd><span class="${item.status === "已修复" ? "status-fixed" : "status-unfixed"}">● ${item.status}</span></dd></div>
      </dl>
    </section>

    <div class="drawer-actions">
      <button class="drawer-action primary" data-detail-action="view">查看详情</button>
      <button class="drawer-action warning" data-detail-action="advice">生成修复建议</button>
      <button class="drawer-action info" data-detail-action="export">导出报告</button>
      <button class="drawer-action muted" data-detail-action="fixed">标记为已修复</button>
    </div>
  `;

  detail.querySelectorAll("[data-detail-action]").forEach((button) => {
    button.addEventListener("click", () => runDetailAction(button.dataset.detailAction));
  });
}

function showVulnerabilityModal() {
  const item = selectedItem();
  showModal(
    `${item.id} 漏洞详情`,
    `<dl class="modal-detail">
      <div><dt>漏洞类型</dt><dd>${item.type}</dd></div>
      <div><dt>风险等级</dt><dd>${item.risk}</dd></div>
      <div><dt>检测位置</dt><dd>${item.location}</dd></div>
      <div><dt>检测方式</dt><dd>${item.method}</dd></div>
      <div><dt>证据数量</dt><dd>${item.evidence}</dd></div>
    </dl>
    <p class="modal-copy">${item.description}</p>`,
  );
}

function showAdviceModal() {
  const item = selectedItem();
  addEvent("INFO", `已为 ${item.id} 生成 AI 修复建议`);
  showModal(
    "AI 修复建议",
    `<p class="modal-copy">${item.advice}</p>
    <div class="code-suggestion">
      <strong>建议优先级</strong>
      <span>${item.risk === "Critical" ? "立即修复" : "本轮迭代修复"}</span>
    </div>`,
  );
  showToast("AI 修复建议已生成");
}

function exportReport() {
  const item = selectedItem();
  const report = `# 安全扫描报告

## 漏洞摘要

- 编号：${item.id}
- 类型：${item.type}
- 风险等级：${item.risk}
- 位置：${item.location}
- 检测方式：${item.method}
- 状态：${item.status}

## 漏洞描述

${item.description}

## AI 修复建议

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
  showToast("报告已导出为 Markdown 文件");
}

function markSelectedAsFixed() {
  const item = selectedItem();
  item.status = "已修复";
  addEvent("INFO", `${item.id} 已标记为已修复`);
  renderSummary();
  renderRows();
  renderDetail();
  showToast(`${item.id} 已标记为已修复`);
}

function runDetailAction(action) {
  const actions = {
    view: showVulnerabilityModal,
    advice: showAdviceModal,
    export: exportReport,
    fixed: markSelectedAsFixed,
  };
  actions[action]?.();
}

function bindScanPageControls() {
  document.querySelector("#editTargetButton")?.addEventListener("click", () => {
    showModal(
      "编辑扫描目标",
      `<form class="mock-form">
        <label>目标地址<input value="https://target.example.com" /></label>
        <label>扫描类型<input value="深度扫描 (DAST + SAST)" /></label>
        <button type="button" id="saveMockTarget">保存配置</button>
      </form>`,
    );
  });

  document.querySelector("#clearEventsButton")?.addEventListener("click", () => {
    events = [];
    renderEvents();
    showToast("实时事件流已清空");
  });

  document.querySelector("#refreshButton")?.addEventListener("click", () => {
    if (!events.length) {
      events = [...initialEvents];
    }
    addEvent("INFO", "已刷新扫描任务状态");
    showToast("扫描状态已刷新");
  });

  document.querySelectorAll(".filter-button").forEach((button) => {
    button.addEventListener("click", () => {
      currentFilter = button.dataset.filter;
      document.querySelectorAll(".filter-button").forEach((item) => item.classList.remove("active"));
      button.classList.add("active");
      renderRows();
      showToast(`已筛选 ${currentFilter} 漏洞`);
    });
  });

  document.querySelector("#statusFilter")?.addEventListener("change", (event) => {
    currentStatus = event.target.value;
    renderRows();
    showToast(`状态筛选：${currentStatus}`);
  });

  document.querySelectorAll(".page-button").forEach((button) => {
    button.addEventListener("click", () => showToast("当前演示数据只有 1 页"));
  });
}

function renderScanPage() {
  document.querySelector(".workspace").innerHTML = initialWorkspaceTemplate;
  document.querySelector(".drawer-header h2").textContent = "漏洞详情";
  document.querySelector(".detail-drawer").classList.remove("drawer-closed");
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

function featureTable(headers, rows) {
  return `
    <div class="feature-table">
      <table>
        <thead>
          <tr>${headers.map((header) => `<th>${header}</th>`).join("")}</tr>
        </thead>
        <tbody>
          ${rows.map((row) => `<tr>${row.map((cell) => `<td>${cell}</td>`).join("")}</tr>`).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function pageTemplate(page) {
  const vulnerabilityRows = vulnerabilities.map((item) => [
    item.id,
    item.type,
    `<span class="badge ${riskClass(item.risk)}">${item.risk}</span>`,
    item.location,
    `<span class="method">${item.method}</span>`,
    `<span class="${item.status === "已修复" ? "status-fixed" : "status-unfixed"}">● ${item.status}</span>`,
  ]);

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
      body: featureTable(["编号", "漏洞类型", "风险等级", "位置", "检测方式", "状态"], vulnerabilityRows),
      drawer:
        "这里负责漏洞闭环：筛选漏洞、查看证据、分派修复人、跟踪未修复/已修复状态。",
    },
    assets: {
      title: "资产管理",
      subtitle: "维护被扫描系统、源码目录、端口服务和负责人信息。",
      metrics: [
        metricCard("Web 应用", 3),
        metricCard("开放端口", 8, "low"),
        metricCard("高风险资产", 1, "critical"),
        metricCard("最近扫描", "2 分钟"),
      ].join(""),
      body: featureTable(
        ["资产名称", "地址", "类型", "负责人", "风险", "最近扫描"],
        [
          ["本地靶场", "http://127.0.0.1:5001", "Web 应用", "SecOps Team", `<span class="badge critical">Critical</span>`, "14:32"],
          ["源码目录", "./vulnerable_app", "Codebase", "Frontend Team", `<span class="badge high">High</span>`, "14:30"],
          ["测试 API", "http://127.0.0.1:8000", "API", "Backend Team", `<span class="badge medium">Medium</span>`, "昨天"],
        ],
      ),
      drawer:
        "这里用于管理扫描对象。后端接入后，扫描任务会从资产库选择目标，而不是每次手动输入 URL。",
    },
    reports: {
      title: "报告中心",
      subtitle: "统一管理 Markdown、HTML 和课堂展示用扫描报告。",
      metrics: [
        metricCard("报告总数", 12),
        metricCard("本周生成", 4, "low"),
        metricCard("Critical 报告", 2, "critical"),
        metricCard("可导出格式", "2"),
      ].join(""),
      body: featureTable(
        ["报告名称", "目标", "风险等级", "格式", "生成时间", "操作"],
        [
          [
            "本地靶场安全扫描报告",
            "127.0.0.1:5001",
            `<span class="badge critical">Critical</span>`,
            "HTML / MD",
            "14:35",
            `<button class="mini-text-button">预览</button><button class="mini-text-button">下载 HTML</button><button class="mini-text-button">下载 MD</button>`,
          ],
          [
            "源码静态扫描报告",
            "./vulnerable_app",
            `<span class="badge high">High</span>`,
            "Markdown",
            "14:20",
            `<button class="mini-text-button">预览</button><button class="mini-text-button">下载 MD</button>`,
          ],
          [
            "周报汇总",
            "全部资产",
            `<span class="badge medium">Medium</span>`,
            "HTML",
            "昨天",
            `<button class="mini-text-button">预览</button><button class="mini-text-button">下载 HTML</button>`,
          ],
        ],
      ),
      drawer:
        "这里是最终交付页面。课程展示时可以从这里打开 HTML 报告，也可以下载 Markdown 报告。",
    },
    "ai-fix": {
      title: "AI 修复",
      subtitle: "根据漏洞证据生成中文解释、修复建议和安全编码清单。",
      metrics: [
        metricCard("待生成建议", 5),
        metricCard("已生成", 8, "low"),
        metricCard("高优先级", 2, "critical"),
        metricCard("模型状态", "在线"),
      ].join(""),
      body: `
        <div class="ai-layout">
          <section class="detail-card">
            <h4>选择漏洞</h4>
            <div class="fix-list">
              ${vulnerabilities.slice(0, 4).map((item, index) => `
                <button class="${index === 0 ? "active" : ""}">
                  <span>${item.id}</span>
                  <strong>${item.type}</strong>
                  <em>${item.risk}</em>
                </button>
              `).join("")}
            </div>
          </section>
          <section class="detail-card">
            <h4>AI 修复建议</h4>
            <p class="detail-copy">使用参数化查询或 ORM 绑定参数，禁止字符串拼接 SQL；统一登录失败提示，并增加回归测试。</p>
            <div class="code-compare">
              <div>
                <strong>修复前</strong>
                <code>sql = "SELECT * FROM users WHERE name='" + username + "'"</code>
              </div>
              <div>
                <strong>修复后</strong>
                <code>cursor.execute("SELECT * FROM users WHERE name=?", (username,))</code>
              </div>
            </div>
          </section>
        </div>
      `,
      drawer:
        "这里不负责攻击，只负责防御性解释和修复建议。后续可以接 OpenAI、DeepSeek 或 Qwen API。",
    },
    schedule: {
      title: "任务调度",
      subtitle: "创建一次性或周期性扫描任务，查看队列和执行历史。",
      metrics: [
        metricCard("运行中", 1, "low"),
        metricCard("等待中", 3, "medium"),
        metricCard("失败任务", 0),
        metricCard("周期任务", 2),
      ].join(""),
      body: featureTable(
        ["任务名", "目标", "扫描模式", "计划时间", "状态", "操作"],
        [
          ["每日靶场扫描", "127.0.0.1:5001", "Full", "每天 20:00", "运行中", "暂停"],
          ["提交前源码检查", "./vulnerable_app", "SAST", "手动触发", "等待中", "启动"],
          ["报告回归扫描", "全部资产", "DAST", "每周五", "等待中", "编辑"],
        ],
      ),
      drawer:
        "任务调度页让扫描器看起来像真实平台：不是只能手动点一次，而是能管理扫描计划。",
    },
    plugins: {
      title: "插件中心",
      subtitle: "管理扫描规则插件、报告模板插件和 AI 建议插件。",
      metrics: [
        metricCard("已安装", 6),
        metricCard("可更新", 2, "medium"),
        metricCard("启用中", 5, "low"),
        metricCard("规则库", "最新"),
      ].join(""),
      body: `
        <div class="plugin-grid">
          ${["SQL 注入检测", "XSS 检测", "越权访问检测", "硬编码密钥扫描", "弱密码存储扫描", "AI 修复建议"].map(
            (plugin) => `
              <article class="plugin-card">
                <strong>${plugin}</strong>
                <span>已启用</span>
                <button class="ghost-button">配置</button>
              </article>
            `,
          ).join("")}
        </div>
      `,
      drawer:
        "插件中心适合表现扩展性。虽然现在规则写在 Python 里，前端可以先把它展示成可管理模块。",
    },
    settings: {
      title: "系统设置",
      subtitle: "配置 API 地址、报告路径、主题偏好和 AI Key 状态。",
      metrics: [
        metricCard("API 地址", "本地"),
        metricCard("主题", "深色", "low"),
        metricCard("AI Key", "未配置", "medium"),
        metricCard("报告格式", "HTML/MD"),
      ].join(""),
      body: `
        <form class="settings-grid">
          <label>后端 API 地址<input value="http://127.0.0.1:5000/api" /></label>
          <label>默认目标地址<input value="http://127.0.0.1:5001" /></label>
          <label>默认源码路径<input value="./vulnerable_app" /></label>
          <label>报告输出目录<input value="./reports" /></label>
          <button type="button" class="drawer-action info">保存设置</button>
        </form>
      `,
      drawer:
        "系统设置页后续会和真实后端对接，比如保存 API 地址、默认扫描参数和报告目录。",
    },
  };

  return templates[page];
}

function renderFeaturePage(page) {
  if (page === "scan") {
    renderScanPage();
    return;
  }

  const template = pageTemplate(page);
  document.querySelector(".workspace").innerHTML = `
    <section class="feature-page panel">
      <div class="feature-header">
        <div>
          <h1>${template.title}</h1>
          <p>${template.subtitle}</p>
        </div>
        <div class="feature-actions">
          <button class="ghost-button" data-feature-action="refresh">刷新</button>
          <button class="drawer-action info" data-feature-action="create">新建</button>
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
      <h4>页面职责</h4>
      <p class="detail-copy">${template.drawer}</p>
    </section>
    <section class="detail-card">
      <h4>当前状态</h4>
      <p class="detail-copy">这是前端演示数据。接口接入后，这里会展示真实后端返回的状态和操作结果。</p>
    </section>
  `;

  document.querySelectorAll("[data-feature-action]").forEach((button) => {
    button.addEventListener("click", () => showToast(`${template.title}：${button.textContent.trim()}操作已触发`));
  });

  document.querySelectorAll(".feature-body button").forEach((button) => {
    button.addEventListener("click", () => showToast(`${button.textContent.trim()}操作已触发`));
  });

  document.querySelectorAll(".feature-table tbody tr").forEach((row) => {
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

function bindChromeInteractions() {
  const navPageMap = {
    扫描管理: "scan",
    漏洞管理: "vulnerabilities",
    资产管理: "assets",
    报告中心: "reports",
    "AI 修复": "ai-fix",
    系统设置: "settings",
  };

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

  document.querySelector("[data-action='notifications']").addEventListener("click", () => {
    showModal("通知中心", `<p class="modal-copy">当前有 12 条扫描提醒，其中 2 条为高风险漏洞提醒。</p>`);
  });

  document.querySelector("[data-action='help']").addEventListener("click", () => {
    showModal(
      "帮助",
      `<p class="modal-copy">这是扫描器前端演示版：当前使用 mock 数据，后续可替换为后端扫描接口返回的数据。</p>`,
    );
  });

  document.querySelector("[data-action='settings']").addEventListener("click", () => {
    showModal("系统设置", `<p class="modal-copy">可在后续版本接入主题、API 地址、报告保存路径等配置。</p>`);
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
}

function boot() {
  initialWorkspaceTemplate = document.querySelector(".workspace").innerHTML;
  renderModules();
  renderSteps();
  renderEvents();
  renderSummary();
  renderRows();
  renderDetail();
  bindScanPageControls();
  bindChromeInteractions();

  const initialPage = location.hash.replace("#", "");
  if (initialPage && document.querySelector(`.side-item[data-page="${initialPage}"]`)) {
    setActiveNavigation(initialPage);
    renderFeaturePage(initialPage);
  }
}

boot();
