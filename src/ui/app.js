document.addEventListener("DOMContentLoaded", () => {
    const $ = (id) => document.getElementById(id);

    const form = $("scan-form");
    const urlInput = $("url-input");
    const btnScan = $("btn-scan");
    const btnIcon = $("btn-icon");
    const btnLabel = $("btn-label");
    const loading = $("loading");
    const loadingStep = $("loading-step");
    const progressFill = $("progress-fill");
    const errorBox = $("error");
    const errorMessage = $("error-message");
    const results = $("results");
    const examples = document.querySelectorAll(".link-btn");

    const STEPS = [
        "Abriendo el sitio en un navegador sin interfaz...",
        "Registrando las peticiones que hace la página...",
        "Revisando cookies y almacenamiento local antes del consentimiento...",
        "Buscando la política de privacidad en el pie de página...",
        "Buscando canales para ejercer derechos ARCO...",
        "Preparando el informe...",
    ];

    const PILARES = [
        { key: "politica_privacidad", name: "Política de privacidad", icon: "i-file" },
        { key: "canales_arco", name: "Derechos ARCO", icon: "i-mail" },
        { key: "consentimiento_cookies", name: "Consentimiento y cookies", icon: "i-cookie" },
    ];

    const TONE_ICON = { ok: "i-check", warn: "i-alert", fail: "i-x", info: "i-info" };
    const FINDING_TONE = { OK: "ok", WARNING: "warn", FAIL: "fail" };

    let progressTimer = null;
    let scanning = false;

    /* ---------- Utilidades ---------- */

    function esc(text) {
        const div = document.createElement("div");
        div.textContent = text == null ? "" : String(text);
        return div.innerHTML;
    }

    function icon(id, size = 20) {
        return `<svg class="icon" width="${size}" height="${size}" aria-hidden="true"><use href="#${id}"/></svg>`;
    }

    function toneOf(value) {
        const v = String(value || "").toLowerCase();
        if (v.includes("aprob") || v.includes("cumple") || v === "ok") return "ok";
        if (v.includes("rech") || v.includes("falla") || v.includes("fail")) return "fail";
        return "warn";
    }

    function pilarName(raw) {
        const found = PILARES.find((p) => p.key === String(raw || "").toLowerCase());
        return found ? found.name : prettify(raw);
    }

    function prettify(text) {
        const t = String(text || "").replace(/_/g, " ").toLowerCase();
        return t.charAt(0).toUpperCase() + t.slice(1);
    }

    /* ---------- Estados de la interfaz ---------- */

    function setBusy(busy) {
        scanning = busy;
        btnIcon.innerHTML = `<use href="#${busy ? "i-loader" : "i-search"}"/>`;
        btnIcon.classList.toggle("spin", busy);
        btnLabel.textContent = busy ? "Revisando" : "Revisar sitio";
        examples.forEach((b) => (b.disabled = busy));
        updateButton();
    }

    function updateButton() {
        btnScan.disabled = scanning || !urlInput.value.trim();
    }

    function startProgress() {
        let step = 0;
        loadingStep.textContent = STEPS[0];
        progressFill.style.width = "12%";
        clearInterval(progressTimer);
        progressTimer = setInterval(() => {
            step = Math.min(step + 1, STEPS.length - 1);
            loadingStep.textContent = STEPS[step];
            progressFill.style.width = `${Math.min(95, 12 + step * 16)}%`;
        }, 1800);
    }

    function stopProgress() {
        clearInterval(progressTimer);
    }

    /* ---------- Escaneo ---------- */

    async function scan(raw) {
        let target = (raw || "").trim();
        if (!target || scanning) return;
        if (!/^https?:\/\//i.test(target)) target = "https://" + target;
        urlInput.value = target;

        errorBox.hidden = true;
        results.hidden = true;
        loading.hidden = false;
        setBusy(true);
        startProgress();

        try {
            const res = await fetch("/api/v1/scan", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: target }),
            });

            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: res.statusText }));
                throw new Error(
                    typeof err.detail === "string" && err.detail
                        ? err.detail
                        : "El servidor respondió con un error."
                );
            }

            const data = await res.json();
            stopProgress();
            loading.hidden = true;
            setBusy(false);
            renderResults(data);
        } catch (e) {
            stopProgress();
            loading.hidden = true;
            setBusy(false);
            errorMessage.textContent = e.message || "No pudimos conectar con el servidor.";
            errorBox.hidden = false;
        }
    }

    /* ---------- Render del informe ---------- */

    function renderResults(data) {
        const tone = toneOf(data.verdict);
        lastReport = data;
        pdfError.hidden = true;

        $("verdict-band").className = `verdict tone-${tone}`;
        $("report-url").textContent = data.target_url || "";
        $("verdict-title").textContent = prettify(data.verdict);
        $("verdict-summary").textContent = data.verdict_summary || "";
        $("score-value").textContent = data.score;
        $("report-date").textContent =
            "Informe generado el " +
            new Date().toLocaleString("es-CL", { dateStyle: "long", timeStyle: "short" });

        $("pilares").innerHTML = PILARES.map(({ key, name, icon: ic }) => {
            const p = data.pilares && data.pilares[key];
            if (!p) return "";
            const t = toneOf(p.status);
            const pct = p.max_score ? Math.round((p.score / p.max_score) * 100) : 0;
            return `
                <div class="pilar tone-${t}">
                    <div class="pilar-head">${icon(ic)}<h3>${esc(name)}</h3></div>
                    <p class="pilar-status">${icon(TONE_ICON[t], 16)}${esc(prettify(p.status))}</p>
                    <div class="track"><div class="fill" style="width:${pct}%"></div></div>
                    <p class="pilar-points">${esc(p.score)} de ${esc(p.max_score)} puntos</p>
                </div>`;
        }).join("");

        const list = $("findings-list");
        if (data.findings && data.findings.length) {
            list.innerHTML = data.findings
                .map((f) => {
                    const t = FINDING_TONE[f.status] || "info";
                    const ticket = f.remediation_ticket
                        ? `<div class="ticket">
                               <div class="ticket-head">
                                   <p class="ticket-title">${icon("i-wrench", 16)}Cómo corregirlo</p>
                                   ${f.technical_raw ? `<code>${esc(f.technical_raw)}</code>` : ""}
                               </div>
                               <p>${esc(f.remediation_ticket)}</p>
                           </div>`
                        : "";
                    return `
                        <li class="finding tone-${t}">
                            ${icon(TONE_ICON[t], 22)}
                            <div class="finding-body">
                                <p class="finding-pilar">${esc(pilarName(f.pilar))}</p>
                                <h4>${esc(f.title)}</h4>
                                <p class="finding-detail">${esc(f.detail)}</p>
                                ${ticket}
                            </div>
                        </li>`;
                })
                .join("");
        } else {
            list.innerHTML = '<li class="finding"><p class="muted">No se registraron hallazgos adicionales.</p></li>';
        }

        results.hidden = false;
        results.scrollIntoView({ behavior: "smooth", block: "start" });
    }

    /* ---------- Descarga del informe en PDF (servicio del backend) ---------- */

    const btnPdf = $("btn-pdf");
    const pdfIcon = $("pdf-icon");
    const pdfLabel = $("pdf-label");
    const pdfError = $("pdf-error");
    let lastReport = null;

    function setPdfBusy(busy) {
        btnPdf.disabled = busy;
        pdfIcon.innerHTML = `<use href="#${busy ? "i-loader" : "i-download"}"/>`;
        pdfIcon.classList.toggle("spin", busy);
        pdfLabel.textContent = busy ? "Generando PDF..." : "Descargar informe PDF";
    }

    async function downloadPdf() {
        if (!lastReport) return;
        pdfError.hidden = true;
        setPdfBusy(true);
        try {
            if (lastReport.pdf_report_url) {
                window.open(lastReport.pdf_report_url, "_blank");
            } else {
                // Pide el PDF al backend con el resultado de la auditoría actual
                const res = await fetch("/api/v1/audits/generate-pdf", {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(lastReport),
                });
                if (!res.ok) throw new Error("El servidor no pudo generar el PDF.");
                const blobUrl = URL.createObjectURL(await res.blob());
                const a = document.createElement("a");
                a.href = blobUrl;
                const disposition = res.headers.get("Content-Disposition") || "";
                const match = disposition.match(/filename="?([^";]+)"?/);
                a.download = match ? match[1] : "DataCheck_Auditoria.pdf";
                document.body.appendChild(a);
                a.click();
                a.remove();
                URL.revokeObjectURL(blobUrl);
            }
        } catch (e) {
            pdfError.textContent = "No se pudo descargar el PDF: " + e.message;
            pdfError.hidden = false;
        } finally {
            setPdfBusy(false);
        }
    }

    /* ---------- Eventos ---------- */

    form.addEventListener("submit", (e) => {
        e.preventDefault();
        scan(urlInput.value);
    });

    urlInput.addEventListener("input", updateButton);

    examples.forEach((btn) => {
        btn.addEventListener("click", () => {
            urlInput.value = btn.dataset.url;
            scan(btn.dataset.url);
        });
    });

    btnPdf.addEventListener("click", downloadPdf);

    /* ---------- Tema claro / oscuro ---------- */

    const themeBtn = $("theme-toggle");
    const themeIcon = $("theme-icon");

    function applyTheme(theme) {
        document.documentElement.dataset.theme = theme;
        const dark = theme === "dark";
        themeIcon.setAttribute("href", dark ? "#i-sun" : "#i-moon");
        const label = dark ? "Cambiar a tema claro" : "Cambiar a tema oscuro";
        themeBtn.setAttribute("aria-label", label);
        themeBtn.title = label;
    }

    applyTheme(document.documentElement.dataset.theme === "dark" ? "dark" : "light");

    themeBtn.addEventListener("click", () => {
        const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
        applyTheme(next);
        try { localStorage.setItem("datacheck-theme", next); } catch (e) {}
    });

    /* ---------- Bookmarklet y ?url= ---------- */

    const bookmarklet = $("bookmarklet-link");
    bookmarklet.href =
        "javascript:(function(){var u=encodeURIComponent(window.location.href);" +
        `window.open('${window.location.origin}/?url='+u,'_blank');})();`;
    // Dentro de DataCheck solo sirve arrastrarlo a la barra de marcadores.
    bookmarklet.addEventListener("click", (e) => e.preventDefault());

    const queryUrl = new URLSearchParams(window.location.search).get("url");
    if (queryUrl) {
        urlInput.value = queryUrl;
        updateButton();
        setTimeout(() => scan(queryUrl), 300);
    }
});
