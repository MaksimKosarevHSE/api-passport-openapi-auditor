(() => {
  "use strict";
  const { auditSpec, samples } = window.ApiPassport;
  const tests = [
    ["Рискованный пример даёт высокий риск", () => auditSpec(samples.risk).risk === "high"],
    ["Рискованный пример находит HTTP", () => auditSpec(samples.risk).findings.some((f) => f.code === "TRANSPORT_HTTP")],
    ["Рискованный пример находит query API key", () => auditSpec(samples.risk).findings.some((f) => f.code === "AUTH_QUERY_KEY")],
    ["Рискованный пример находит открытую оплату", () => auditSpec(samples.risk).findings.some((f) => f.location === "POST /payments" && f.severity === "high")],
    ["Готовый пример без высокого риска", () => auditSpec(samples.ready).counts.high === 0],
    ["Готовый пример считает 3 endpoints", () => auditSpec(samples.ready).metrics.endpoints === 3],
    ["Явно публичный health не считается ошибкой", () => !auditSpec(samples.ready).findings.some((f) => f.location === "GET /health" && f.code.startsWith("AUTH_"))],
    ["Неизвестная security scheme обнаруживается", () => auditSpec({ openapi: "3.0.3", info: { title: "x", version: "1" }, paths: { "/x": { get: { security: [{ nope: [] }], responses: { 200: { description: "ok" } } } } } }).findings.some((f) => f.code === "AUTH_UNDEFINED")],
    ["Пустой paths даёт находку, а не падение", () => auditSpec({ openapi: "3.0.3", info: { title: "x", version: "1" }, paths: {} }).findings.some((f) => f.code === "NO_OPERATIONS")],
    ["OpenAPI 2 отклоняется", () => { try { auditSpec({ swagger: "2.0", paths: {} }); return false; } catch (e) { return /OpenAPI 3/.test(e.message); } }],
    ["Массив вместо объекта отклоняется", () => { try { auditSpec([]); return false; } catch (e) { return /JSON-объектом/.test(e.message); } }],
    ["Данные не мутируются", () => { const value = JSON.parse(JSON.stringify(samples.partial)); const before = JSON.stringify(value); auditSpec(value); return JSON.stringify(value) === before; }]
  ];
  const host = document.querySelector("#test-results");
  let passed = 0;
  tests.forEach(([name, fn]) => {
    const item = document.createElement("article");
    let ok = false; let error = "";
    try { ok = Boolean(fn()); } catch (caught) { error = caught.message; }
    if (ok) passed += 1;
    item.className = `test-case ${ok ? "pass" : "fail"}`;
    const title = document.createElement("strong"); title.textContent = `${ok ? "✓" : "✕"} ${name}`;
    item.append(title);
    if (error) { const details = document.createElement("pre"); details.textContent = error; item.append(details); }
    host.append(item);
  });
  const summary = document.createElement("section");
  summary.className = `test-summary ${passed === tests.length ? "pass" : "fail"}`;
  summary.innerHTML = `<strong>${passed}/${tests.length} тестов пройдено</strong>`;
  host.prepend(summary);
  document.title = `${passed === tests.length ? "PASS" : "FAIL"} · API Passport tests`;
})();
