/* SENTINEL — front-end controller: drag-drop, scan request, render results. */
(() => {
  "use strict";

  const $ = (id) => document.getElementById(id);
  const dropzone = $("dropzone");
  const fileInput = $("file-input");
  const uploadSection = $("upload-section");
  const resultsSection = $("results-section");
  const errorBox = $("error-box");

  // ── Drag & drop wiring ────────────────────────────────────────────────
  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => {
    if (fileInput.files.length) handleFile(fileInput.files[0]);
  });

  ["dragenter", "dragover"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.add("drag");
    })
  );
  ["dragleave", "drop"].forEach((evt) =>
    dropzone.addEventListener(evt, (e) => {
      e.preventDefault();
      dropzone.classList.remove("drag");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    const f = e.dataTransfer.files[0];
    if (f) handleFile(f);
  });

  $("reset-btn").addEventListener("click", () => {
    resultsSection.classList.add("hidden");
    uploadSection.classList.remove("hidden");
    errorBox.classList.add("hidden");
    fileInput.value = "";
  });

  // ── Scan request ──────────────────────────────────────────────────────
  async function handleFile(file) {
    if (!/\.csv$/i.test(file.name)) {
      return showError("Please upload a .csv file.");
    }
    errorBox.classList.add("hidden");
    dropzone.classList.add("loading");

    const fd = new FormData();
    fd.append("file", file);

    try {
      const res = await fetch("/scan", { method: "POST", body: fd });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Scan failed.");
      render(data);
    } catch (err) {
      showError(err.message);
    } finally {
      dropzone.classList.remove("loading");
    }
  }

  function showError(msg) {
    errorBox.textContent = "⚠ " + msg;
    errorBox.classList.remove("hidden");
  }

  // ── Render ────────────────────────────────────────────────────────────
  function fmtTime(ms) {
    return ms >= 1000 ? `${(ms / 1000).toFixed(1)} s` : `${Math.round(ms)} ms`;
  }

  function buildBanner(status, data) {
    const m = data.ai_meta || {};
    const dep = m.deployment ? ` · ${m.deployment}` : "";
    const effort = m.reasoning_effort ? ` · reasoning: ${m.reasoning_effort}` : "";
    if (status === "ai") {
      return {
        cls: "ai-on",
        text: `🧠 AI JUDGE ACTIVE — ${m.provider || "Azure OpenAI"}${dep}${effort} · `
            + `re-ranked ${data.candidate_pool} candidates → ${data.results.length} `
            + `in ${fmtTime(data.ai_ms)} (engine scan: ${data.engine_ms} ms).`,
      };
    }
    if (status === "fallback") {
      return {
        cls: "ai-warn",
        text: `🟡 AI JUDGE UNAVAILABLE (API error)${dep} — safely fell back to the `
            + `rule engine's top ${data.results.length} by score.`,
      };
    }
    return {
      cls: "ai-off",
      text: "⚪ AI JUDGE OFFLINE — showing the rule engine's top 20 by score. "
          + "Configure Azure OpenAI in .env to enable the AI layer.",
    };
  }

  function render(data) {
    const results = data.results || [];
    const status = data.ai_status || "disabled";

    $("stat-rows").textContent = (data.total_rows || 0).toLocaleString();
    $("stat-flagged").textContent = results.length;
    $("stat-engine").textContent = `${data.engine_ms} ms`;
    $("stat-ai").textContent = status === "ai" ? fmtTime(data.ai_ms)
      : (status === "fallback" ? "FALLBACK" : "OFF");

    const banner = buildBanner(status, data);
    const bannerEl = $("ai-banner");
    bannerEl.className = `ai-banner ${banner.cls}`;
    bannerEl.textContent = banner.text;

    renderThreats(results);

    uploadSection.classList.add("hidden");
    resultsSection.classList.remove("hidden");
    resultsSection.scrollIntoView({ behavior: "smooth" });
  }

  function renderThreats(results) {
    const list = $("threat-list");
    list.innerHTML = "";

    results.forEach((r, i) => {
      const el = document.createElement("div");
      el.className = `threat sev-${r.severity}`;
      el.style.animationDelay = `${i * 35}ms`;

      // Evidence chips: rule TYPES only (no numeric weights — scores are hidden).
      const positive = (r.triggers || []).filter((t) => t.weight > 0);
      const seen = new Set();
      const tags = positive
        .filter((t) => !seen.has(t.type) && seen.add(t.type))
        .map((t) => `<span class="rule-tag plus">${tagLabel(t.type)}</span>`)
        .join("");

      // Always-visible one-line AI verdict on the card itself.
      const aiLine = r.ai_reason
        ? `<div class="threat-ai">🧠 <span>${esc(r.ai_reason)}</span></div>`
        : "";
      const aiBlock = r.ai_reason
        ? `<div class="tb-label">AI ANALYST VERDICT</div>
           <div class="tb-ai">${esc(r.ai_reason)}</div>`
        : "";

      el.innerHTML = `
        <div class="threat-top">
          <div class="rank">${String(r.rank).padStart(2, "0")}</div>
          <div class="proc">${esc(r.process_name || "—")}<br><span class="sev-tag">${r.severity.toUpperCase()}</span></div>
          <div class="cmd-preview">${esc(r.command_preview || "")}</div>
          <div class="risk-pill sev-pill">⚠</div>
        </div>
        ${aiLine}
        <div class="threat-body">
          <div class="tb-inner">
            ${aiBlock}
            <div class="tb-label">WHY IT WAS FLAGGED</div>
            <div class="tb-explain">${esc(r.explanation || "")}</div>
            <div class="tb-label">COMMAND LINE</div>
            <div class="tb-cmd">
              <code>${esc(r.command_line || "")}</code>
              <button class="copy-btn">COPY</button>
            </div>
            <div class="tag-row">${tags}</div>
          </div>
        </div>`;

      el.querySelector(".threat-top").addEventListener("click", () => el.classList.toggle("open"));
      el.querySelector(".copy-btn").addEventListener("click", (e) => {
        e.stopPropagation();
        navigator.clipboard.writeText(r.command_line || "");
        e.target.textContent = "COPIED";
        setTimeout(() => (e.target.textContent = "COPY"), 1200);
      });
      list.appendChild(el);
    });
  }

  function tagLabel(type) {
    const map = {
      lolbin: "LOLBIN/GTFO", sigma: "SIGMA RULE", mitre: "MITRE ATT&CK",
      heuristic_length: "LENGTH", heuristic_escape: "ESCAPING",
      heuristic_density: "OBFUSCATION", fp_path: "SYSTEM PATH", fp_benign: "BENIGN USE",
    };
    return map[type] || type.toUpperCase();
  }

  function esc(s) {
    return String(s).replace(/[&<>"']/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
    );
  }

  // Exposed for offline snapshots/screenshots (render with a captured payload).
  window.__SENTINEL_render = render;
})();
