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

    /* ---------- Escaneo de flujo multietapa ---------- */

    async function scanFlow(target) {
        errorBox.hidden = true;
        results.hidden = true;
        loading.hidden = false;
        setBusy(true);

        const FLOW_STEPS = [
            "Iniciando auditoría de flujo multietapa (Nivel 0 pasivo)...",
            "Cargando página de inicio y descubriendo catálogo...",
            "Buscando enlaces de registro y cuenta de usuario...",
            "Localizando carrito o checkout dentro del mismo dominio...",
            "Verificando pasarelas de pago y cookies acumuladas...",
            "Consolidando inventario de rastreadores por etapa...",
        ];
        let step = 0;
        loadingStep.textContent = FLOW_STEPS[0];
        progressFill.style.width = "10%";
        clearInterval(progressTimer);
        progressTimer = setInterval(() => {
            step = Math.min(step + 1, FLOW_STEPS.length - 1);
            loadingStep.textContent = FLOW_STEPS[step];
            progressFill.style.width = `${Math.min(95, 10 + step * 15)}%`;
        }, 3000);

        const t0 = performance.now();

        try {
            const initRes = await fetch("/api/v1/flow-audit", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ url: target }),
            });
            if (!initRes.ok) {
                const err = await initRes.json().catch(() => ({ detail: initRes.statusText }));
                throw new Error(err.detail || "Error al iniciar auditoría de flujo.");
            }
            const { job_id } = await initRes.json();

            let attempts = 0;
            const maxAttempts = 60;
            let completedResult = null;

            while (attempts < maxAttempts) {
                await new Promise((r) => setTimeout(r, 2000));
                attempts++;
                const pollRes = await fetch(`/api/v1/flow-audit/${job_id}`);
                if (!pollRes.ok) continue;
                const pollData = await pollRes.json();
                if (pollData.status === "completed") {
                    completedResult = pollData.result;
                    break;
                } else if (pollData.status === "error") {
                    throw new Error(pollData.error || "Ocurrió un error en el recorrido del flujo.");
                }
            }

            if (!completedResult) {
                throw new Error("Tiempo de espera agotado al auditar el flujo.");
            }

            stopProgress();
            loading.hidden = true;
            setBusy(false);
            renderFlowResults(completedResult, performance.now() - t0);
        } catch (e) {
            stopProgress();
            loading.hidden = true;
            setBusy(false);
            errorMessage.textContent = e.message || "Error al auditar el flujo.";
            errorBox.hidden = false;
        }
    }

    /* ---------- Escaneo ---------- */

    async function scan(raw, forceNormal = false) {
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

        const flowChecked = $("flow-checkbox") && $("flow-checkbox").checked;
        if (flowChecked && !forceNormal) {
            return scanFlow(target);
        }

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

    function renderConsentBanner(data) {
        const consentSec = $("consent-section");
        if (!consentSec) return;

        const cb = data.consent_banner_audit;
        const fa = data.frames_audit;

        if (cb && cb.banner_detected) {
            consentSec.hidden = false;
            const badge = $("consent-badge");
            const hasReject = cb.has_reject_option;
            const verifiable = cb.buttons_verifiable;
            let cTone = "ok";
            let badgeText = "Conforme";

            if (!verifiable) {
                cTone = "info";
                badgeText = "No verificable pasivamente";
            } else if (!hasReject) {
                cTone = "warn";
                badgeText = cb.has_settings_option ? "2 Pasos (Sin rechazo directo)" : "Sin opción de rechazo";
            }

            if (badge) {
                badge.className = `badge tone-${cTone}`;
                badge.textContent = badgeText;
            }

            const buttonsHtml = (cb.detected_buttons && cb.detected_buttons.length)
                ? cb.detected_buttons.map(b => `<span class="consent-pill">${esc(b)}</span>`).join(" ")
                : '<span class="muted">No se detectaron botones legibles</span>';

            const frameInfo = cb.banner_source_frame
                ? `<p class="consent-meta"><b>Marco de origen:</b> <code>${esc(cb.banner_source_frame)}</code></p>`
                : '<p class="consent-meta"><b>Marco de origen:</b> Frame principal</p>';

            const blockingText = cb.blocks_prior_to_consent === true
                ? '<span class="badge tone-ok">Bloqueo preventivo activo</span>'
                : (cb.blocks_prior_to_consent === false
                    ? '<span class="badge tone-fail">Sin bloqueo preventivo (trackers detectados)</span>'
                    : '<span class="badge tone-info">N/A</span>');

            const framesSummary = fa ? `
                <div class="consent-frames-summary">
                    <p class="small muted">
                        <b>Auditoría de marcos embebidos:</b> Total frames: ${esc(fa.total_frames || 1)} |
                        Terceros: ${esc(fa.third_party_frames || 0)} |
                        CMPs detectados: ${esc(fa.cmp_frames || 0)}
                    </p>
                </div>` : "";

            $("consent-card-content").innerHTML = `
                <div class="consent-card-grid">
                    <div class="consent-item">
                        <span class="muted small">Proveedor CMP:</span>
                        <p><b>${esc(cb.cmp_provider || "Genérico / Heurístico")}</b></p>
                    </div>
                    <div class="consent-item">
                        <span class="muted small">Bloqueo Pre-Consentimiento:</span>
                        <p>${blockingText}</p>
                    </div>
                    <div class="consent-item">
                        <span class="muted small">Opciones de Consentimiento:</span>
                        <p>
                            Aceptar: <b>${cb.has_accept_option ? "Sí" : "No"}</b> |
                            Rechazar: <b>${cb.has_reject_option ? "Sí" : "No"}</b> |
                            Configurar: <b>${cb.has_settings_option ? "Sí" : "No"}</b>
                        </p>
                    </div>
                    <div class="consent-item">
                        <span class="muted small">Verificable Pasivamente:</span>
                        <p><b>${verifiable ? "Sí" : "No (Shadow DOM Cerrado)"}</b></p>
                    </div>
                </div>
                <div class="consent-buttons-row">
                    <span class="muted small">Botones detectados:</span>
                    <div class="consent-pills-list">${buttonsHtml}</div>
                </div>
                ${frameInfo}
                ${framesSummary}
            `;
        } else if (cb && !cb.banner_detected) {
            consentSec.hidden = false;
            const badge = $("consent-badge");
            if (badge) {
                badge.className = "badge tone-info";
                badge.textContent = "No detectado";
            }
            const faSummary = fa ? `
                <div class="consent-frames-summary">
                    <p class="small muted">
                        <b>Auditoría de marcos embebidos:</b> Total frames: ${esc(fa.total_frames || 1)} |
                        Terceros: ${esc(fa.third_party_frames || 0)}
                    </p>
                </div>` : "";
            $("consent-card-content").innerHTML = `
                <p class="muted">No se detectó un banner de consentimiento ni gestor CMP visible en la carga pasiva del sitio.</p>
                ${faSummary}
            `;
        } else {
            consentSec.hidden = true;
        }
    }

    function renderResponsibleParty(data) {
        const respSec = $("responsible-section");
        if (!respSec) return;

        const rp = data.responsible_party_audit;
        if (!rp) {
            respSec.hidden = true;
            return;
        }

        respSec.hidden = false;
        const badge = $("responsible-badge");
        const v = rp.verdict || "OBSERVACION";
        let tone = "ok";
        let badgeText = "Conforme (Art. 14 ter)";

        if (v === "NO_VERIFICABLE") {
            tone = "info";
            badgeText = "No verificable";
        } else if (v === "OBSERVACION" || v === "NO_DETECTADO") {
            tone = "warn";
            badgeText = "Observación de Transparencia";
        }

        if (badge) {
            badge.className = `badge tone-${tone}`;
            badge.textContent = badgeText;
        }

        const isIdentified = rp.identified || rp.representative_found;

        let identDetailsHtml = "";
        if (rp.corporate_name) {
            identDetailsHtml += `<p style="margin: 4px 0 0; font-size: 0.88rem; font-weight: 600; color: var(--text, #fff);">${esc(rp.corporate_name)}</p>`;
        }
        if (rp.detected_rut) {
            identDetailsHtml += `<p style="margin: 2px 0 0; font-size: 0.78rem; font-family: monospace; color: var(--text-muted, #a1a1aa);">RUT: ${esc(rp.detected_rut)}</p>`;
        }
        if (rp.representative_found && !rp.corporate_name) {
            identDetailsHtml += `<p style="margin: 4px 0 0; font-size: 0.82rem; color: var(--text, #fff);">Representante legal mencionado</p>`;
        }

        const identText = isIdentified
            ? `<div style="display: flex; align-items: center; gap: 6px;"><span class="badge tone-ok">Detectado</span></div>${identDetailsHtml}`
            : '<span class="badge tone-warn">No detectado</span>';

        const dpoText = rp.dpo_found
            ? '<span class="badge tone-ok">Indicado</span><p style="margin: 4px 0 0; font-size: 0.8rem; color: var(--text, #fff);">Oficial de Privacidad / DPO</p>'
            : '<span class="badge tone-neutral">No especificado (Opcional según Art. 49/50)</span>';

        let channelRows = [];
        if (rp.contact_email) {
            channelRows.push(`<div><span style="font-size: 0.75rem; color: var(--text-muted, #999);">Email:</span> <code style="font-size: 0.78rem;">${esc(rp.contact_email)}</code></div>`);
        }
        if (rp.contact_channels_found && rp.contact_channels_found.includes("formulario")) {
            channelRows.push(`<div><span style="font-size: 0.75rem; color: var(--text-muted, #999);">Formulario:</span> <span class="consent-pill" style="font-size: 0.75rem;">Detectado</span></div>`);
        }
        if (rp.postal_address) {
            channelRows.push(`<div><span style="font-size: 0.75rem; color: var(--text-muted, #999);">Domicilio:</span> <span style="font-size: 0.78rem; color: var(--text, #fff);">${esc(rp.postal_address)}</span></div>`);
        } else if (rp.contact_channels_found && rp.contact_channels_found.includes("domicilio")) {
            channelRows.push(`<div><span style="font-size: 0.75rem; color: var(--text-muted, #999);">Domicilio:</span> <span class="consent-pill" style="font-size: 0.75rem;">Físico detectado</span></div>`);
        }

        const channelsHtml = channelRows.length
            ? `<div style="display: flex; flex-direction: column; gap: 4px; margin-top: 4px;">${channelRows.join("")}</div>`
            : (rp.contact_channels_found && rp.contact_channels_found.length
                ? rp.contact_channels_found.map(c => `<span class="consent-pill">${esc(c.toUpperCase())}</span>`).join(" ")
                : '<span class="muted">Ninguno detectado</span>');

        const disclaimer = (v !== "CUMPLE")
            ? `<p class="consent-meta" style="margin-top: 10px; font-style: italic; font-size: 0.82rem; color: var(--text-muted, #71717a);">
                 <b>Nota técnica:</b> Diagnóstico técnico pasivo de caja negra: la ausencia de detección no implica necesariamente inexistencia jurídica, sino que los datos no se encuentran visibles de forma estructurada en la página pública evaluada.
               </p>`
            : '';

        const content = $("responsible-card-content");
        if (content) {
            content.innerHTML = `
                <div class="responsible-grid" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; margin-top: 8px;">
                    <div class="resp-item" style="background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.07);">
                        <div style="font-size: 0.8rem; color: var(--text-muted, #999); margin-bottom: 4px;">Individualización Empresa / Representante</div>
                        <div>${identText}</div>
                    </div>
                    <div class="resp-item" style="background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.07);">
                        <div style="font-size: 0.8rem; color: var(--text-muted, #999); margin-bottom: 4px;">Encargado de Prevención / DPO</div>
                        <div>${dpoText}</div>
                    </div>
                    <div class="resp-item" style="background: rgba(255,255,255,0.03); padding: 10px; border-radius: 6px; border: 1px solid rgba(255,255,255,0.07);">
                        <div style="font-size: 0.8rem; color: var(--text-muted, #999); margin-bottom: 4px;">Canales de atención habilitados</div>
                        <div>${channelsHtml}</div>
                    </div>
                </div>
                ${disclaimer}
            `;
        }
    }

    /* ---------- Render del informe estándar ---------- */

    function renderResults(data, elapsedMs) {
        const tone = toneOf(data.verdict);
        lastReport = data;
        pdfError.hidden = true;

        const flowSec = $("flow-section");
        if (flowSec) flowSec.hidden = true;

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

        renderConsentBanner(data);
        renderResponsibleParty(data);

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

        // Condicional de re-auditoría programada (RF-SCHED-01)
        if (data.verdict === "RECHAZADO" || data.verdict === "CON_OBSERVACIONES") {
            scheduleCard.hidden = false;
            scheduleSuccess.hidden = true;
            scheduleError.hidden = true;
            scheduleForm.hidden = false;
            setScheduleBusy(false);
        } else {
            scheduleCard.hidden = true;
        }

        results.hidden = false;
        results.scrollIntoView({ behavior: "smooth", block: "start" });
        animateGauge(data.score);
    }

    /* ---------- Render del informe de flujo multietapa ---------- */

    function renderFlowResults(data, elapsedMs) {
        const flowSec = $("flow-section");
        if (flowSec) flowSec.hidden = false;
        if ($("consent-section")) $("consent-section").hidden = true;
        if ($("responsible-section")) $("responsible-section").hidden = true;
        lastReport = data;
        pdfError.hidden = true;

        const tone = toneOf(data.flow_verdict);
        $("verdict-band").className = `verdict tone-${tone}`;
        showSiteInfo(data.target_url, elapsedMs);
        $("verdict-title").textContent = `Flujo: ${prettify(data.flow_verdict)}`;
        $("verdict-summary").textContent = data.flow_verdict_summary || "";
        $("report-date").textContent = "Auditoría de flujo completada el " + new Date().toLocaleString("es-CL", { dateStyle: "long", timeStyle: "short" });

        // Ocultar pilares estándar en la vista de flujo
        $("pilares").innerHTML = "";

        const badge = $("flow-verdict-badge");
        if (badge) {
            badge.className = `badge tone-${tone}`;
            badge.textContent = prettify(data.flow_verdict);
        }

        const summaryText = $("flow-summary-text");
        if (summaryText) {
            summaryText.textContent = data.flow_verdict_summary || "";
        }

        const timeline = $("flow-timeline");
        if (timeline) {
            if (!data.flow_detected) {
                timeline.innerHTML = `
                    <div class="flow-stage-card tone-warn">
                        <div class="flow-stage-header">
                            <span class="flow-stage-title">Flujo de compra/registro no detectado</span>
                        </div>
                        <p class="flow-stage-url">${esc(data.flow_not_detected_reason || "No se identificaron enlaces al catálogo, registro o carrito en el mismo dominio.")}</p>
                        <p class="muted" style="margin-top:8px;">Puedes ejecutar el análisis estándar para revisar la política de privacidad, canales ARCO y cookies pre-consentimiento.</p>
                        <button type="button" id="btn-fallback-scan" class="btn-primary" style="margin-top:14px;height:42px;font-size:14px;padding:0 20px;">
                            ${icon("i-search", 16)} Ejecutar auditoría estándar
                        </button>
                    </div>
                `;
                const fbBtn = $("btn-fallback-scan");
                if (fbBtn) {
                    fbBtn.onclick = () => scan(data.target_url, true);
                }
            } else {
                timeline.innerHTML = (data.stages_evaluated || []).map((s, idx) => {
                    const sTone = toneOf(s.verdict);
                    const domPills = (s.new_tracker_domains || []).map(d => `<span class="flow-pill pill-domain">🌐 ${esc(d)}</span>`).join("");
                    const ckPills = (s.new_tracker_cookies || []).map(c => `<span class="flow-pill pill-cookie">🍪 ${esc(c)}</span>`).join("");
                    const note = s.verification_note ? `<p class="flow-note">${esc(s.verification_note)}</p>` : "";
                    return `
                        <div class="flow-stage-card tone-${sTone}">
                            <div class="flow-stage-header">
                                <span class="flow-stage-title">Etapa ${idx + 1}: ${esc(s.stage_label || s.stage_name)}</span>
                                <span class="badge tone-${sTone}">${esc(prettify(s.verdict))}</span>
                            </div>
                            <p class="flow-stage-url"><a href="${esc(s.url)}" target="_blank" rel="noopener">${esc(s.url)}</a></p>
                            <div class="flow-stage-meta">
                                ${domPills || ckPills ? `<span><b>Nuevos rastreadores:</b></span> ${domPills} ${ckPills}` : `<span class="muted">Sin nuevos rastreadores detectados en esta etapa</span>`}
                            </div>
                            ${note}
                        </div>
                    `;
                }).join("");
            }
        }

        const limitDiv = $("flow-limitations");
        if (limitDiv) {
            if (data.limitations && data.limitations.length) {
                limitDiv.innerHTML = `
                    <b>Limitaciones declaradas (Nivel 0 pasivo):</b>
                    <ul>${data.limitations.map(l => `<li>${esc(l)}</li>`).join("")}</ul>
                `;
            } else {
                limitDiv.innerHTML = "";
            }
        }

        const list = $("findings-list");
        if (data.flow_findings && data.flow_findings.length) {
            list.innerHTML = data.flow_findings.map((f) => {
                const t = FINDING_TONE[f.status] || "info";
                const ticket = f.remediation_ticket
                    ? `<div class="ticket">
                           <div class="ticket-head">
                               <p class="ticket-title">${icon("i-wrench", 16)}Cómo corregirlo (${esc(f.stage_label)})</p>
                               ${f.technical_raw ? `<code>${esc(f.technical_raw)}</code>` : ""}
                           </div>
                           <p>${esc(f.remediation_ticket)}</p>
                       </div>`
                    : "";
                return `
                    <li class="finding tone-${t}">
                        ${icon(TONE_ICON[t], 22)}
                        <div class="finding-body">
                            <p class="finding-pilar">Etapa: ${esc(f.stage_label)}</p>
                            <h4>${esc(f.title)}</h4>
                            <p class="finding-detail">${esc(f.detail)}</p>
                            ${ticket}
                        </div>
                    </li>`;
            }).join("");
        } else {
            list.innerHTML = '<li class="finding"><p class="muted">No se registraron hallazgos adicionales en el flujo.</p></li>';
        }

        results.hidden = false;
        results.scrollIntoView({ behavior: "smooth", block: "start" });
        const flowScore = data.flow_verdict === "CUMPLE" ? 100 : (data.flow_verdict === "NO_VERIFICABLE" ? 50 : 0);
        animateGauge(flowScore);
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

    /* ---------- Re-calendarización automática (RF-SCHED-01, RF-SCHED-02) ---------- */

    const scheduleCard = $("schedule-card");
    const scheduleForm = $("schedule-form");
    const scheduleEmail = $("schedule-email");
    const btnSchedule = $("btn-schedule");
    const scheduleBtnIcon = $("schedule-btn-icon");
    const scheduleBtnLabel = $("schedule-btn-label");
    const scheduleSuccess = $("schedule-success");
    const scheduleSuccessDesc = $("schedule-success-desc");
    const scheduleError = $("schedule-error");

    function setScheduleBusy(busy) {
        btnSchedule.disabled = busy;
        scheduleBtnIcon.innerHTML = `<use href="#${busy ? "i-loader" : "i-mail"}"/>`;
        scheduleBtnIcon.classList.toggle("spin", busy);
        scheduleBtnLabel.textContent = busy ? "Programando..." : "Calendarizar Re-auditoría";
    }

    async function handleScheduleSubmit(e) {
        e.preventDefault();
        scheduleError.hidden = true;
        scheduleSuccess.hidden = true;

        if (!lastReport || !lastReport.audit_id) {
            scheduleError.textContent = "No se puede programar sin un ID de auditoría guardado.";
            scheduleError.hidden = false;
            return;
        }

        const email = scheduleEmail.value.trim();
        if (!email || !email.includes("@")) {
            scheduleError.textContent = "Por favor ingresa un correo electrónico válido.";
            scheduleError.hidden = false;
            return;
        }

        const modeInput = document.querySelector('input[name="interval_mode"]:checked');
        const interval_mode = modeInput ? modeInput.value : "DEMO_2_MIN";

        setScheduleBusy(true);

        try {
            const res = await fetch("/api/v1/schedules", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    audit_id: lastReport.audit_id,
                    email: email,
                    interval_mode: interval_mode
                })
            });

            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: res.statusText }));
                throw new Error(typeof err.detail === "string" ? err.detail : "Error al calendarizar.");
            }

            const data = await res.json();
            const dateStr = new Date(data.scheduled_at).toLocaleString("es-CL", { dateStyle: "short", timeStyle: "short" });
            scheduleSuccessDesc.textContent = `${data.message} Próxima ejecución: ${dateStr}.`;
            scheduleSuccess.hidden = false;
            scheduleForm.hidden = true;
        } catch (err) {
            scheduleError.textContent = "No se pudo programar: " + err.message;
            scheduleError.hidden = false;
        } finally {
            setScheduleBusy(false);
        }
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
    scheduleForm.addEventListener("submit", handleScheduleSubmit);


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
