(() => {
  "use strict";

  const HTTP_METHODS = new Set(["get", "post", "put", "patch", "delete", "options", "head", "trace"]);
  const WRITE_METHODS = new Set(["post", "put", "patch", "delete"]);
  const SENSITIVE_PATTERN = /(password|passwd|secret|token|api.?key|ssn|passport|card|cvv|iban|bank|payment|email|phone|address|birth|inn|tax.?id|personal|customer|client|account|credential)/i;
  const MAX_FILE_SIZE = 1024 * 1024;

  const SAMPLES = {
    risk: {
      openapi: "3.0.3",
      info: { title: "Synthetic Shop API", version: "1.0.0" },
      servers: [{ url: "http://demo.invalid/api" }],
      paths: {
        "/catalog": {
          get: { summary: "Public catalog", responses: { 200: { description: "OK" } }, security: [] }
        },
        "/customers/{id}": {
          get: {
            summary: "Customer profile",
            parameters: [{ name: "id", in: "path", required: true, schema: { type: "string" } }],
            responses: { 200: { description: "Profile", content: { "application/json": { schema: { type: "object", properties: { email: { type: "string" }, phone: { type: "string" } } } } } } }
          }
        },
        "/payments": {
          post: {
            summary: "Create payment",
            requestBody: { required: true, content: { "application/json": { schema: { type: "object", properties: { cardNumber: { type: "string" }, cvv: { type: "string" }, amount: { type: "number" } } } } } },
            responses: { 200: { description: "Created" } }
          }
        },
        "/admin/export": {
          get: { responses: { 200: { description: "CSV export" } }, security: [{ queryKey: [] }] }
        }
      },
      components: { securitySchemes: { queryKey: { type: "apiKey", in: "query", name: "key" } } }
    },
    partial: {
      openapi: "3.0.3",
      info: { title: "Delivery API — draft", version: "0.8.0" },
      servers: [{ url: "https://sandbox.invalid/api" }],
      security: [{ bearerAuth: [] }],
      paths: {
        "/orders": {
          get: { operationId: "listOrders", summary: "List orders", responses: { 200: { description: "OK" }, 401: { description: "Unauthorized" } } },
          post: { summary: "Create order", requestBody: { content: { "application/json": { schema: { type: "object", properties: { customerEmail: { type: "string", format: "email" }, address: { type: "string" } } } } } }, responses: { 201: { description: "Created" } } }
        },
        "/health": { get: { operationId: "health", summary: "Health", security: [], responses: { 200: { description: "OK" } } } }
      },
      components: { securitySchemes: { bearerAuth: { type: "http", scheme: "bearer", bearerFormat: "JWT" } } }
    },
    ready: {
      openapi: "3.1.0",
      info: { title: "Orders API — release candidate", version: "1.0.0", description: "Synthetic release example" },
      servers: [{ url: "https://api.invalid/v1" }],
      security: [{ oauth2: ["orders:read"] }],
      paths: {
        "/orders": {
          get: { operationId: "listOrders", summary: "List orders", tags: ["Orders"], responses: { 200: { description: "OK" }, 401: { description: "Unauthorized" }, 403: { description: "Forbidden" } } },
          post: { operationId: "createOrder", summary: "Create order", tags: ["Orders"], security: [{ oauth2: ["orders:write"] }], requestBody: { required: true, content: { "application/json": { schema: { type: "object", required: ["customerId"], properties: { customerId: { type: "string", minLength: 8 }, total: { type: "number", minimum: 0 } } } } } }, responses: { 201: { description: "Created" }, 401: { description: "Unauthorized" }, 403: { description: "Forbidden" } } }
        },
        "/health": { get: { operationId: "health", summary: "Service health", tags: ["Service"], security: [], responses: { 200: { description: "OK" } } } }
      },
      components: { securitySchemes: { oauth2: { type: "oauth2", flows: { clientCredentials: { tokenUrl: "https://auth.invalid/token", scopes: { "orders:read": "Read orders", "orders:write": "Create orders" } } } } } }
    }
  };

  function addFinding(findings, severity, title, detail, location, remediation, code) {
    findings.push({ id: `F-${String(findings.length + 1).padStart(3, "0")}`, severity, title, detail, location, remediation, code });
  }

  function collectFieldNames(node, names = new Set(), depth = 0, seen = new Set()) {
    if (!node || typeof node !== "object" || depth > 8 || seen.has(node)) return names;
    seen.add(node);
    if (node.properties && typeof node.properties === "object") {
      Object.entries(node.properties).forEach(([name, value]) => {
        names.add(name);
        collectFieldNames(value, names, depth + 1, seen);
      });
    }
    ["items", "schema"].forEach((key) => collectFieldNames(node[key], names, depth + 1, seen));
    ["allOf", "oneOf", "anyOf"].forEach((key) => {
      if (Array.isArray(node[key])) node[key].forEach((item) => collectFieldNames(item, names, depth + 1, seen));
    });
    if (node.content && typeof node.content === "object") Object.values(node.content).forEach((value) => collectFieldNames(value, names, depth + 1, seen));
    if (node.responses && typeof node.responses === "object") Object.values(node.responses).forEach((value) => collectFieldNames(value, names, depth + 1, seen));
    if (node.requestBody) collectFieldNames(node.requestBody, names, depth + 1, seen);
    return names;
  }

  function securityState(operation, globalSecurity, schemes) {
    const declared = Object.prototype.hasOwnProperty.call(operation, "security") ? operation.security : globalSecurity;
    if (!Array.isArray(declared)) return { kind: "missing", names: [] };
    if (declared.length === 0) return { kind: "public", names: [] };
    const names = [...new Set(declared.flatMap((requirement) => requirement && typeof requirement === "object" ? Object.keys(requirement) : []))];
    const undefinedNames = names.filter((name) => !schemes[name]);
    if (names.length === 0) return { kind: "public", names: [] };
    if (undefinedNames.length) return { kind: "undefined", names, undefinedNames };
    return { kind: "protected", names };
  }

  function auditSpec(spec) {
    if (!spec || typeof spec !== "object" || Array.isArray(spec)) throw new Error("Корневой элемент должен быть JSON-объектом.");
    if (typeof spec.openapi !== "string" || !/^3\.(0|1)(\.|$)/.test(spec.openapi)) throw new Error("Поддерживаются OpenAPI 3.0 и 3.1. Проверьте поле openapi.");
    if (!spec.paths || typeof spec.paths !== "object" || Array.isArray(spec.paths)) throw new Error("В контракте отсутствует объект paths.");

    const findings = [];
    const schemes = spec.components?.securitySchemes || {};
    const globalSecurity = spec.security;
    const operations = [];

    (spec.servers || []).forEach((server, index) => {
      if (typeof server?.url === "string" && /^http:\/\//i.test(server.url)) {
        addFinding(findings, "high", "Сервер заявлен без TLS", "Контракт содержит HTTP URL. Токены и данные могут передаваться по незащищённому каналу.", `servers[${index}]`, "Используйте HTTPS и перенаправляйте HTTP на HTTPS.", "TRANSPORT_HTTP");
      }
    });

    Object.entries(schemes).forEach(([name, scheme]) => {
      if (scheme?.type === "apiKey" && scheme?.in === "query") {
        addFinding(findings, "high", "API-ключ передаётся в query", "Query-параметры часто попадают в журналы, историю браузера и аналитику.", `components.securitySchemes.${name}`, "Передавайте ключ в заголовке Authorization или отдельном header-параметре.", "AUTH_QUERY_KEY");
      }
      if (scheme?.type === "http" && String(scheme.scheme).toLowerCase() === "basic") {
        addFinding(findings, "medium", "Используется Basic Auth", "Схема зависит от TLS и не даёт короткоживущих токенов или точных scope.", `components.securitySchemes.${name}`, "Для внешнего или чувствительного API рассмотрите OAuth 2.0/OIDC или короткоживущие bearer-токены.", "AUTH_BASIC");
      }
    });

    Object.entries(spec.paths).forEach(([path, pathItem]) => {
      if (!pathItem || typeof pathItem !== "object") return;
      Object.entries(pathItem).forEach(([method, operation]) => {
        if (!HTTP_METHODS.has(method.toLowerCase()) || !operation || typeof operation !== "object") return;
        const normalizedMethod = method.toLowerCase();
        const location = `${normalizedMethod.toUpperCase()} ${path}`;
        const fields = [...collectFieldNames(operation)];
        const sensitiveFields = fields.filter((name) => SENSITIVE_PATTERN.test(name));
        const security = securityState(operation, globalSecurity, schemes);
        const isWrite = WRITE_METHODS.has(normalizedMethod);
        const responses = operation.responses && typeof operation.responses === "object" ? operation.responses : {};
        const statusCodes = Object.keys(responses);
        operations.push({ method: normalizedMethod, path, security: security.kind, sensitive: sensitiveFields.length > 0 });

        if (security.kind === "undefined") {
          addFinding(findings, "high", "Ссылка на неопределённую схему защиты", `Операция требует ${security.undefinedNames.join(", ")}, но такой схемы нет в components.securitySchemes.`, location, "Добавьте схему в components.securitySchemes или исправьте имя в security.", "AUTH_UNDEFINED");
        } else if ((security.kind === "missing" || security.kind === "public") && (isWrite || sensitiveFields.length)) {
          const reason = sensitiveFields.length ? `Обнаружены поля: ${sensitiveFields.slice(0, 5).join(", ")}.` : "Операция изменяет данные.";
          addFinding(findings, "high", "Чувствительная операция без заявленной защиты", reason, location, "Добавьте и примените подходящую security scheme; публичность отмечайте только осознанно.", "AUTH_MISSING_SENSITIVE");
        } else if (security.kind === "missing") {
          addFinding(findings, "medium", "Защита операции не определена", "Нет ни глобального, ни локального поля security — непонятно, является ли endpoint публичным намеренно.", location, "Задайте security глобально или явно укажите security: [] для публичной операции.", "AUTH_AMBIGUOUS");
        }

        if (security.kind === "protected") {
          const missingAuthResponses = ["401", "403"].filter((code) => !statusCodes.includes(code));
          if (missingAuthResponses.length) addFinding(findings, "medium", "Не описаны ответы авторизации", `В responses отсутствуют ${missingAuthResponses.join(" и ")}.`, location, "Опишите 401 и 403, чтобы клиент различал отсутствие и недостаточность прав.", "RESPONSES_AUTH");
        }
        if (!statusCodes.some((code) => /^2\d\d$/.test(code))) {
          addFinding(findings, "medium", "Не описан успешный ответ", "В responses нет явного 2xx-кода.", location, "Добавьте ожидаемый 2xx-ответ и схему его данных.", "RESPONSES_SUCCESS");
        }
        if (!operation.operationId) addFinding(findings, "low", "Нет operationId", "Стабильный идентификатор упрощает генерацию клиентов и трассировку изменений.", location, "Добавьте уникальный operationId в формате действия и сущности.", "DOC_OPERATION_ID");
        if (!operation.summary && !operation.description) addFinding(findings, "low", "Нет краткого назначения операции", "Контракт не объясняет сценарий использования endpoint.", location, "Добавьте summary или description с ожидаемым действием и ограничениями.", "DOC_SUMMARY");
      });
    });

    if (!operations.length) addFinding(findings, "medium", "В контракте нет операций", "Объект paths не содержит поддерживаемых HTTP-методов.", "paths", "Добавьте хотя бы одну OpenAPI operation и повторите аудит.", "NO_OPERATIONS");

    const counts = findings.reduce((acc, finding) => ({ ...acc, [finding.severity]: acc[finding.severity] + 1 }), { high: 0, medium: 0, low: 0 });
    const uniqueCodes = new Set();
    let penalty = 0;
    findings.forEach((finding) => {
      const factor = uniqueCodes.has(finding.code) ? 0.55 : 1;
      penalty += ({ high: 18, medium: 8, low: 3 }[finding.severity] || 0) * factor;
      uniqueCodes.add(finding.code);
    });
    const score = Math.max(0, Math.round(100 - penalty));
    const protectedCount = operations.filter((operation) => operation.security === "protected").length;
    const protectedPercent = operations.length ? Math.round((protectedCount / operations.length) * 100) : 0;
    const risk = counts.high > 0 || score < 50 ? "high" : counts.medium > 1 || score < 80 ? "medium" : "low";
    const topFixes = [...findings]
      .sort((a, b) => ({ high: 0, medium: 1, low: 2 }[a.severity] - ({ high: 0, medium: 1, low: 2 }[b.severity])))
      .filter((finding, index, array) => array.findIndex((item) => item.code === finding.code) === index)
      .slice(0, 3)
      .map((finding) => finding.remediation);

    return {
      generatedAt: new Date().toISOString(),
      engine: "API Passport 1.0",
      title: spec.info?.title || "OpenAPI без названия",
      version: spec.info?.version || "не указана",
      openapi: spec.openapi,
      score,
      risk,
      counts,
      metrics: { endpoints: operations.length, protectedCount, protectedPercent, sensitiveOperations: operations.filter((operation) => operation.sensitive).length },
      findings,
      topFixes,
      limitations: ["Статический анализ JSON-контракта", "Без сетевых запросов", "Не заменяет пентест и проверку runtime-политик"]
    };
  }

  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const elements = {
    input: $("#spec-input"), file: $("#file-input"), fileName: $("#file-name"), dropzone: $("#dropzone"), error: $("#input-error"),
    analyze: $("#analyze-button"), resultCard: $("#result-card"), empty: $("#result-empty"), content: $("#result-content"), findingsPanel: $("#findings-panel"), findingsList: $("#findings-list"), fixPlan: $("#fix-plan")
  };
  let currentReport = null;

  function setInput(value, filename = "Вставленный JSON") {
    elements.input.value = typeof value === "string" ? value : JSON.stringify(value, null, 2);
    elements.fileName.textContent = filename;
    elements.error.textContent = "";
  }

  function loadSample(name, autoRun = false) {
    if (!SAMPLES[name]) return;
    setInput(SAMPLES[name], `Синтетический пример: ${name}`);
    if (autoRun) runAudit();
  }

  function handleFile(file) {
    elements.error.textContent = "";
    if (!file) return;
    if (file.size > MAX_FILE_SIZE) {
      elements.error.textContent = "Файл больше 1 МБ. Используйте сокращённый синтетический контракт.";
      return;
    }
    if (!/\.json$/i.test(file.name) && file.type !== "application/json") {
      elements.error.textContent = "Поддерживается только JSON-файл.";
      return;
    }
    const reader = new FileReader();
    reader.onload = () => setInput(String(reader.result), file.name);
    reader.onerror = () => { elements.error.textContent = "Не удалось прочитать файл локально."; };
    reader.readAsText(file);
  }

  function riskCopy(report) {
    if (report.risk === "high") return ["Высокий риск", "status-danger", "Есть критичные пробелы. Исправьте их до интеграционного тестирования."];
    if (report.risk === "medium") return ["Нужна доработка", "status-warning", "Основная защита заявлена, но контракт не полностью воспроизводим."];
    return ["Низкий риск", "status-good", "Критичных пробелов в заявленном контракте не найдено."];
  }

  function createFindingCard(finding) {
    const article = document.createElement("article");
    article.className = "finding";
    article.dataset.severity = finding.severity;
    const dot = document.createElement("span");
    dot.className = `severity-dot ${finding.severity}`;
    const body = document.createElement("div");
    const title = document.createElement("h4");
    title.textContent = finding.title;
    const detail = document.createElement("p");
    detail.textContent = `${finding.detail} Исправление: ${finding.remediation}`;
    const location = document.createElement("code");
    location.textContent = finding.location;
    body.append(title, detail, location);
    const label = document.createElement("span");
    label.className = `severity-label ${finding.severity}`;
    label.textContent = ({ high: "высокий", medium: "средний", low: "низкий" })[finding.severity];
    article.append(dot, body, label);
    return article;
  }

  function renderReport(report) {
    currentReport = report;
    elements.resultCard.classList.remove("empty");
    elements.empty.hidden = true;
    elements.content.hidden = false;
    elements.findingsPanel.hidden = false;
    $("#api-title").textContent = `${report.title} · ${report.version}`;
    $("#score-value").textContent = report.score;
    $("#score-ring").style.setProperty("--score", report.score);
    $("#metric-endpoints").textContent = report.metrics.endpoints;
    $("#metric-high").textContent = report.counts.high;
    $("#metric-medium").textContent = report.counts.medium;
    $("#metric-protected").textContent = `${report.metrics.protectedPercent}%`;
    const [statusText, statusClass, explanation] = riskCopy(report);
    const status = $("#risk-status");
    status.textContent = statusText;
    status.className = `status ${statusClass}`;
    $("#score-explanation").textContent = explanation;

    elements.findingsList.replaceChildren();
    if (!report.findings.length) {
      const empty = document.createElement("p");
      empty.className = "no-findings";
      empty.textContent = "В пределах правил MVP находок нет. Проведите runtime-тестирование перед релизом.";
      elements.findingsList.append(empty);
    } else report.findings.forEach((finding) => elements.findingsList.append(createFindingCard(finding)));

    elements.fixPlan.replaceChildren();
    const fixes = report.topFixes.length ? report.topFixes : ["Зафиксируйте результат и перейдите к runtime-тестированию на разрешённом стенде."];
    fixes.forEach((fix) => { const item = document.createElement("li"); item.textContent = fix; elements.fixPlan.append(item); });
    $$(".filter").forEach((button) => button.classList.toggle("active", button.dataset.filter === "all"));
  }

  function runAudit() {
    elements.error.textContent = "";
    const raw = elements.input.value.trim();
    if (!raw) { elements.error.textContent = "Вставьте OpenAPI JSON или выберите синтетический пример."; return; }
    if (new Blob([raw]).size > MAX_FILE_SIZE) { elements.error.textContent = "JSON больше 1 МБ. Сократите контракт для учебного демо."; return; }
    try {
      renderReport(auditSpec(JSON.parse(raw)));
    } catch (error) {
      elements.error.textContent = error instanceof SyntaxError ? "JSON содержит синтаксическую ошибку. Проверьте кавычки и запятые." : error.message;
    }
  }

  function downloadReport() {
    if (!currentReport) return;
    const blob = new Blob([JSON.stringify(currentReport, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "api-passport-report.json";
    link.click();
    URL.revokeObjectURL(url);
  }

  elements.file?.addEventListener("change", (event) => handleFile(event.target.files[0]));
  ["dragenter", "dragover"].forEach((type) => elements.dropzone?.addEventListener(type, (event) => { event.preventDefault(); elements.dropzone.classList.add("dragover"); }));
  ["dragleave", "drop"].forEach((type) => elements.dropzone?.addEventListener(type, (event) => { event.preventDefault(); elements.dropzone.classList.remove("dragover"); }));
  elements.dropzone?.addEventListener("drop", (event) => handleFile(event.dataTransfer.files[0]));
  elements.analyze?.addEventListener("click", runAudit);
  $("#clear-input")?.addEventListener("click", () => { setInput("", "Файл не выбран"); elements.file.value = ""; });
  $$("[data-sample]").forEach((button) => button.addEventListener("click", () => loadSample(button.dataset.sample)));
  $("#hero-demo")?.addEventListener("click", () => { loadSample("risk", true); $("#audit").scrollIntoView({ behavior: "smooth" }); });
  $("#download-report")?.addEventListener("click", downloadReport);
  $("#print-report")?.addEventListener("click", () => window.print());
  $$(".filter").forEach((button) => button.addEventListener("click", () => {
    $$(".filter").forEach((candidate) => candidate.classList.toggle("active", candidate === button));
    $$(".finding").forEach((finding) => { finding.hidden = button.dataset.filter !== "all" && finding.dataset.severity !== button.dataset.filter; });
  }));

  const demoParams = new URLSearchParams(window.location.search);
  const demoSample = demoParams.get("demo");
  const shotMode = demoParams.get("shot");
  if (shotMode === "audit" || shotMode === "findings") document.body.classList.add(`shot-${shotMode}`);
  if (demoSample && SAMPLES[demoSample]) {
    loadSample(demoSample, true);
    if (demoParams.get("view") === "findings") requestAnimationFrame(() => elements.findingsPanel.scrollIntoView());
    else requestAnimationFrame(() => $("#audit").scrollIntoView());
  }

  window.ApiPassport = { auditSpec, samples: SAMPLES };
})();
