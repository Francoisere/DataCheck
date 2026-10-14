document.addEventListener("DOMContentLoaded", () => {
    const scanForm = document.getElementById("scan-form");
    const targetUrlInput = document.getElementById("target-url-input");
    const btnScan = document.getElementById("btn-scan");
    const loadingState = document.getElementById("loading-state");
    const resultsDashboard = document.getElementById("results-dashboard");
    const loadingStep = document.getElementById("loading-step");
    const progressBarFill = document.getElementById("progress-bar-fill");
    const exampleChips = document.querySelectorAll(".btn-chip");
    const bookmarkletLink = document.getElementById("bookmarklet-link");

    // Configurar Bookmarklet ejecutable para navegador
    setupBookmarklet();

    // Event Listeners para Chips de ejemplo
    exampleChips.forEach(chip => {
        chip.addEventListener("click", () => {
            const sampleUrl = chip.dataset.url;
            targetUrlInput.value = sampleUrl;
            startScan(sampleUrl);
        });
    });

    // Form Submit Handler
    scanForm.addEventListener("submit", (e) => {
        e.preventDefault();
        const url = targetUrlInput.value.trim();
        if (url) {
            startScan(url);
        }
    });

    async function startScan(rawUrl) {
        let url = rawUrl.trim();
        if (!url) return;

        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "https://" + url;
            targetUrlInput.value = url;
        }

        showLoadingState();
        const stopProgress = simulateProgressSteps();

        try {
            console.log("Iniciando escaneo para:", url);
            const response = await fetch("/api/v1/scan", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({ url })
            });

            stopProgress();

            if (!response.ok) {
                const errData = await response.json().catch(() => ({ detail: response.statusText }));
                throw new Error(errData.detail || "Error en la respuesta del servidor");
            }

            const data = await response.json();
            console.log("Resultado del escaneo:", data);
            renderResults(data);
        } catch (error) {
            stopProgress();
            hideLoadingState();
            alert(`Error al auditar el sitio web: ${error.message}`);
        }
    }

    function showLoadingState() {
        loadingState.classList.remove("hidden");
        resultsDashboard.classList.add("hidden");
        btnScan.disabled = true;
        progressBarFill.style.width = "10%";
    }

    function hideLoadingState() {
        loadingState.classList.add("hidden");
        btnScan.disabled = false;
    }

    function simulateProgressSteps() {
        const steps = [
            "Iniciando navegador Headless Chromium en Playwright...",
            "Navegando al sitio e interceptando peticiones salientes...",
            "Auditando cookies depositadas pre-consentimiento y localStorage...",
            "Inspeccionando enlaces en footer para Política de Privacidad...",
            "Evaluando palabras clave normativas y canales ARCO (Ley 19.628)...",
            "Generando dictamen técnico..."
        ];

        let currentStep = 0;
        const interval = setInterval(() => {
            currentStep++;
            if (currentStep < steps.length) {
                loadingStep.textContent = steps[currentStep];
                progressBarFill.style.width = `${Math.min(95, (currentStep + 1) * 15)}%`;
            }
        }, 1800);

        return () => clearInterval(interval);
    }

    function renderResults(data) {
        hideLoadingState();
        progressBarFill.style.width = "100%";
        resultsDashboard.classList.remove("hidden");

        // Scroll suave hacia los resultados
        resultsDashboard.scrollIntoView({ behavior: "smooth" });

        // Target URL & Summary
        document.getElementById("target-url-display").textContent = data.target_url;
        document.getElementById("verdict-summary").textContent = data.verdict_summary;
        document.getElementById("score-value").textContent = data.score;

        // Verdict Badge
        const verdictBadge = document.getElementById("verdict-badge");
        verdictBadge.textContent = data.verdict;
        verdictBadge.className = "verdict-badge " + data.verdict.toLowerCase().replace("_", "");

        // PDF Download Button
        const btnPdf = document.getElementById("btn-download-pdf");
        if (btnPdf) {
            btnPdf.style.display = "inline-flex";
            btnPdf.onclick = async () => {
                const originalText = btnPdf.textContent;
                btnPdf.textContent = "⏳ Generando PDF...";
                btnPdf.disabled = true;

                try {
                    if (data.pdf_report_url) {
                        window.open(data.pdf_report_url, "_blank");
                    } else {
                        // Fallback directo generando el PDF a partir del payload actual
                        const pdfRes = await fetch("/api/v1/audits/generate-pdf", {
                            method: "POST",
                            headers: { "Content-Type": "application/json" },
                            body: JSON.stringify(data)
                        });
                        if (!pdfRes.ok) throw new Error("Error al generar el PDF");
                        const blob = await pdfRes.blob();
                        const blobUrl = window.URL.createObjectURL(blob);
                        const a = document.createElement("a");
                        a.href = blobUrl;
                        a.download = `DataCheck_Auditoria_${(data.target_url || "sitio").replace(/[^a-zA-Z0-9]/g, "_")}.pdf`;
                        document.body.appendChild(a);
                        a.click();
                        a.remove();
                        window.URL.revokeObjectURL(blobUrl);
                    }
                } catch (err) {
                    alert("Error al descargar el PDF: " + err.message);
                } finally {
                    btnPdf.textContent = originalText;
                    btnPdf.disabled = false;
                }
            };
        }


        // Pilares
        updatePilarCard("privacy", data.pilares.politica_privacidad);
        updatePilarCard("arco", data.pilares.canales_arco);
        updatePilarCard("cookies", data.pilares.consentimiento_cookies);

        // Render Findings
        const findingsList = document.getElementById("findings-list");
        findingsList.innerHTML = "";

        if (data.findings && data.findings.length > 0) {
            data.findings.forEach(finding => {
                const item = document.createElement("div");
                item.className = "finding-item";

                let icon = "ℹ️";
                if (finding.status === "OK") icon = "✅";
                if (finding.status === "WARNING") icon = "⚠️";
                if (finding.status === "FAIL") icon = "❌";

                let remediationHtml = "";
                if (finding.remediation_ticket) {
                    remediationHtml = `
                        <div class="remediation-ticket-box">
                            <div class="ticket-header">
                                <span class="ticket-tag">🛠️ Ticket de Remediación Técnica</span>
                                ${finding.technical_raw ? `<code class="technical-raw-badge">${escapeHtml(finding.technical_raw)}</code>` : ""}
                            </div>
                            <p class="ticket-text">${escapeHtml(finding.remediation_ticket)}</p>
                        </div>
                    `;
                }

                item.innerHTML = `
                    <span class="finding-icon">${icon}</span>
                    <div class="finding-content">
                        <h4>[${escapeHtml(finding.pilar)}] ${escapeHtml(finding.title)}</h4>
                        <p class="finding-detail">${escapeHtml(finding.detail)}</p>
                        ${remediationHtml}
                    </div>
                `;
                findingsList.appendChild(item);
            });
        } else {
            findingsList.innerHTML = "<p>No se registraron hallazgos adicionales.</p>";
        }
    }

    function escapeHtml(text) {
        if (!text) return "";
        const div = document.createElement("div");
        div.textContent = text;
        return div.innerHTML;
    }

    function updatePilarCard(pilarKey, pilarData) {
        const badge = document.getElementById(`pilar-${pilarKey}-badge`);
        const fill = document.getElementById(`pilar-${pilarKey}-fill`);
        const num = document.getElementById(`pilar-${pilarKey}-num`);

        if (badge && fill && num && pilarData) {
            badge.textContent = pilarData.status;
            badge.className = `pilar-status-badge ${pilarData.status.toLowerCase()}`;

            const percent = Math.round((pilarData.score / pilarData.max_score) * 100);
            fill.style.width = `${percent}%`;
            num.textContent = `${pilarData.score} / ${pilarData.max_score} pts`;
        }
    }

    function setupBookmarklet() {
        const host = window.location.origin;
        // Script bookmarklet que toma la URL actual del usuario y la envía a auditar
        const bookmarkletCode = `javascript:(function(){var url=encodeURIComponent(window.location.href);window.open('${host}/?url='+url,'_blank');})();`;
        if (bookmarkletLink) {
            bookmarkletLink.href = bookmarkletCode;
        }

        // Si se recibe ?url= en los parámetros GET de la página actual (vía bookmarklet)
        const urlParams = new URLSearchParams(window.location.search);
        const queryUrl = urlParams.get("url");
        if (queryUrl) {
            const decoded = decodeURIComponent(queryUrl);
            targetUrlInput.value = decoded;
            setTimeout(() => {
                startScan(decoded);
            }, 300);
        }
    }
});
