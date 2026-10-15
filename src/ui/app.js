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
    const urlError = $("url-error");

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

    /* ---------- Validación de la dirección ---------- */

    const DOMAIN_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,61}$/;
    const IPV4_RE = /^(?:\d{1,3}\.){3}\d{1,3}$/;
    const FORMAT_MSG = "URL inaccesible o formato no válido. Escribe un dominio como ejemplo.cl, sin espacios.";

    function parseTarget(raw) {
        const text = (raw || "").trim();
        if (!text) return { error: "Escribe la dirección de un sitio web." };
        if (/\s/.test(text)) return { error: FORMAT_MSG };

        const proto = text.match(/^([a-z][a-z0-9+.-]*):\/\//i);
        if (proto && !/^https?$/i.test(proto[1])) {
            return { error: "URL inaccesible o formato no válido. Solo se aceptan direcciones http:// o https://." };
        }

        const withProto = proto ? text : "https://" + text;
        let host;
        try {
            host = new URL(withProto).hostname;
        } catch (e) {
            return { error: FORMAT_MSG };
        }
        // localhost y direcciones IP se aceptan para poder probar sitios locales
        if (!(DOMAIN_RE.test(host) || host === "localhost" || IPV4_RE.test(host))) {
            return { error: FORMAT_MSG };
        }
        return { url: withProto };
    }

    function showFieldError(message) {
        urlError.textContent = message;
        urlError.hidden = false;
        urlInput.setAttribute("aria-invalid", "true");
        urlInput.setAttribute("aria-describedby", "url-error");
        urlInput.focus();
    }

    function clearFieldError() {
        urlError.hidden = true;
        urlInput.removeAttribute("aria-invalid");
        urlInput.removeAttribute("aria-describedby");
    }

    /* ---------- Datos del sitio auditado ---------- */

    function showSiteInfo(targetUrl, elapsedMs) {
        const link = $("report-url");
        const img = $("site-favicon");
        const fallback = $("site-fallback");
        const meta = $("scan-meta");

        $("report-url-text").textContent = targetUrl || "";

        // Solo se enlaza si es una dirección http(s) válida
        let origin = "";
        try {
            const u = new URL(targetUrl);
            if (u.protocol === "http:" || u.protocol === "https:") origin = u.origin;
        } catch (e) {}
        if (origin) link.setAttribute("href", targetUrl);
        else link.removeAttribute("href");

        // Ícono: se pide directamente al sitio auditado, sin servicios de terceros
        img.toggleAttribute("hidden", true);
        fallback.toggleAttribute("hidden", false);
        if (origin) {
            img.onload = () => {
                img.toggleAttribute("hidden", false);
                fallback.toggleAttribute("hidden", true);
            };
            img.onerror = () => {
                img.toggleAttribute("hidden", true);
                fallback.toggleAttribute("hidden", false);
            };
            img.src = origin + "/favicon.ico";
        }

        const ok = Number.isFinite(elapsedMs);
        meta.toggleAttribute("hidden", !ok);
        if (ok) {
            const secs = (elapsedMs / 1000).toLocaleString("es-CL", {
                minimumFractionDigits: 1,
                maximumFractionDigits: 1,
            });
            $("scan-time").textContent = `Revisado en ${secs} s`;
        }
    }

    /* ---------- Anillo de puntaje ---------- */

    const GAUGE_LEN = 2 * Math.PI * 52; // circunferencia del anillo (r = 52)
    let gaugeRun = 0;

    function animateGauge(score) {
        const value = Math.max(0, Math.min(100, Number(score) || 0));
        const arc = $("gauge-arc");
        const label = $("score-value");
        const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
        const run = ++gaugeRun;

        $("gauge").setAttribute("aria-label", `Puntaje de cumplimiento: ${value} de 100`);
        arc.style.strokeDasharray = GAUGE_LEN;
        arc.style.transition = "none";
        arc.style.strokeDashoffset = GAUGE_LEN;
        label.textContent = reduce ? value : 0;

        // Doble requestAnimationFrame: asegura que el navegador pinte el anillo vacío antes de llenarlo
        requestAnimationFrame(() => requestAnimationFrame(() => {
            if (run !== gaugeRun) return;
            arc.style.transition = "";
            arc.style.strokeDashoffset = GAUGE_LEN * (1 - value / 100);
            if (reduce) return;

            const start = performance.now();
            const duration = 1100;
            const tick = (now) => {
                if (run !== gaugeRun) return;
                const p = Math.min(1, (now - start) / duration);
                label.textContent = Math.round(value * (1 - Math.pow(1 - p, 3)));
                if (p < 1) requestAnimationFrame(tick);
            };
            requestAnimationFrame(tick);
        }));
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
        if (scanning) return;
        const parsed = parseTarget(raw);
        if (parsed.error) {
            errorBox.hidden = true;
            showFieldError(parsed.error);
            return;
        }
        clearFieldError();
        const target = parsed.url;
        urlInput.value = target;

        errorBox.hidden = true;
        results.hidden = true;
        loading.hidden = false;
        setBusy(true);
        startProgress();
        const t0 = performance.now();

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
            renderResults(data, performance.now() - t0);
        } catch (e) {
            stopProgress();
            loading.hidden = true;
            setBusy(false);
            errorMessage.textContent = e.message || "No pudimos conectar con el servidor.";
            errorBox.hidden = false;
        }
    }

    /* ---------- Render del informe ---------- */

    function renderResults(data, elapsedMs) {
        const tone = toneOf(data.verdict);
        lastReport = data;
        pdfError.hidden = true;

        $("verdict-band").className = `verdict tone-${tone}`;
        showSiteInfo(data.target_url, elapsedMs);
        $("verdict-title").textContent = prettify(data.verdict);
        $("verdict-summary").textContent = data.verdict_summary || "";
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
        animateGauge(data.score);
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

    urlInput.addEventListener("input", () => {
        clearFieldError();
        updateButton();
    });

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
