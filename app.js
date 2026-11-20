const $ = (id) => document.getElementById(id);

function setStatus(id, message) { $(id).textContent = message; }
function showError(target, message) {
  $(target).replaceChildren();
  const p = document.createElement("p");
  p.textContent = message;
  $(target).append(p);
}
function addResult(target, label, value) {
  const item = document.createElement("div");
  item.className = "result-item";
  const strong = document.createElement("strong");
  strong.textContent = label;
  const code = document.createElement("code");
  code.textContent = value || "Not available";
  item.append(strong, code);
  $(target).append(item);
}
async function copyText(text, statusId) {
  try {
    await navigator.clipboard.writeText(text);
    if (statusId) setStatus(statusId, "Copied to clipboard.");
  } catch {
    if (statusId) setStatus(statusId, "Clipboard access was unavailable. Select and copy the text manually.");
  }
}

// Tabs
document.querySelectorAll(".tab").forEach(button => {
  button.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(b => b.classList.toggle("active", b === button));
    document.querySelectorAll(".panel").forEach(p => p.classList.toggle("active", p.id === `panel-${button.dataset.panel}`));
  });
});

// QR code: QRCode.js encodes the supplied text locally in the browser.
let currentQr = null;
$("qr-create").addEventListener("click", () => {
  const value = $("qr-input").value.trim();
  const size = Number($("qr-size").value);
  const target = $("qr-code");
  target.replaceChildren();
  $("qr-download").disabled = true;
  if (!value) return setStatus("qr-status", "Enter some text or a URL first.");
  if (value.length > 2000) return setStatus("qr-status", "Please use 2,000 characters or fewer.");
  if (typeof QRCode === "undefined") return setStatus("qr-status", "The QR library could not load. Check your connection or CDN access.");
  try {
    currentQr = new QRCode(target, { text:value, width:size, height:size, correctLevel:QRCode.CorrectLevel.M });
    $("qr-download").disabled = false;
    setStatus("qr-status", "QR code generated in your browser.");
  } catch {
    setStatus("qr-status", "Unable to generate this QR code. Try shorter text.");
  }
});
$("qr-download").addEventListener("click", () => {
  const canvas = $("qr-code").querySelector("canvas");
  const img = $("qr-code").querySelector("img");
  const dataUrl = canvas ? canvas.toDataURL("image/png") : img?.src;
  if (!dataUrl) return;
  const link = document.createElement("a");
  link.href = dataUrl;
  link.download = "qr-code.png";
  link.click();
});

// Password generator: rejection sampling avoids modulo bias.
$("pw-length").addEventListener("input", () => $("pw-length-value").textContent = $("pw-length").value);
function secureIndex(max) {
  const limit = Math.floor(256 / max) * max;
  const byte = new Uint8Array(1);
  do { crypto.getRandomValues(byte); } while (byte[0] >= limit);
  return byte[0] % max;
}
$("pw-generate").addEventListener("click", () => {
  let groups = [];
  const ambiguous = "O0Il";
  const addGroup = (enabled, chars) => {
    if (enabled) groups.push([...chars].filter(c => !$("pw-avoid").checked || !ambiguous.includes(c)).join(""));
  };
  addGroup($("pw-upper").checked, "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
  addGroup($("pw-lower").checked, "abcdefghijklmnopqrstuvwxyz");
  addGroup($("pw-numbers").checked, "0123456789");
  addGroup($("pw-symbols").checked, "!@#$%^&*()-_=+[]{};:,.?/");
  if (!groups.length) return setStatus("pw-status", "Select at least one character group.");
  const length = Number($("pw-length").value);
  if (length < groups.length) return setStatus("pw-status", "Increase the length to include every selected character group.");
  const all = groups.join("");
  const chars = groups.map(group => group[secureIndex(group.length)]);
  while (chars.length < length) chars.push(all[secureIndex(all.length)]);
  // Secure Fisher-Yates shuffle.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = secureIndex(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  $("pw-output").textContent = chars.join("");
  $("pw-copy").disabled = false;
  setStatus("pw-status", "Generated locally using the browser's cryptographic random number generator.");
});
$("pw-copy").addEventListener("click", () => copyText($("pw-output").textContent, "pw-status"));

// DNS lookup via the site's Pages Function.
$("dns-search").addEventListener("click", async () => {
  const domain = $("dns-domain").value.trim().replace(/\.$/, "");
  const type = $("dns-type").value;
  const target = "dns-results";
  if (!domain || domain.length > 253 || !/^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(domain)) {
    return showError(target, "Enter a valid public domain name, such as example.com.");
  }
  $(target).textContent = "Looking up DNS records…";
  try {
    const response = await fetch(`/api/dns?name=${encodeURIComponent(domain)}&type=${encodeURIComponent(type)}`, {headers:{"Accept":"application/json"}});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "DNS lookup failed.");
    $(target).replaceChildren();
    if (!data.answers || !data.answers.length) return showError(target, "No records were returned for this query. The record may not exist, or the resolver may have no answer.");
    data.answers.forEach(answer => addResult(target, `${answer.typeName || type} · TTL ${answer.TTL ?? "unknown"}`, answer.data));
  } catch (error) { showError(target, error.message || "Unable to complete the DNS lookup."); }
});

// Browser privacy check. Signals are descriptive, not a fingerprinting or anonymity verdict.
$("privacy-run").addEventListener("click", () => {
  const target = "privacy-results";
  $(target).replaceChildren();
  const checks = [
    ["HTTPS / secure context", window.isSecureContext ? "Secure context" : "Not a secure context"],
    ["Do Not Track", navigator.doNotTrack === "1" ? "Enabled" : navigator.doNotTrack === "0" ? "Explicitly disabled" : "Not signalled"],
    ["Global Privacy Control", navigator.globalPrivacyControl === true ? "Enabled" : "Not exposed or disabled"],
    ["Third-party cookie setting", "Not reliably detectable by a normal webpage"],
    ["Local storage", (() => { try { localStorage.setItem("__privacy_test","1"); localStorage.removeItem("__privacy_test"); return "Available"; } catch { return "Blocked or unavailable"; } })()],
    ["Browser language", navigator.language || "Not available"],
    ["Timezone", Intl.DateTimeFormat().resolvedOptions().timeZone || "Not available"],
    ["Cookies enabled", navigator.cookieEnabled ? "Browser reports enabled" : "Browser reports disabled"]
  ];
  checks.forEach(([label,value]) => addResult(target, label, value));
});

// IP information is derived by the Pages Function from Cloudflare request metadata.
$("ip-check").addEventListener("click", async () => {
  const target = "ip-results";
  $(target).textContent = "Checking connection…";
  try {
    const response = await fetch("/api/ip", {headers:{"Accept":"application/json"}, cache:"no-store"});
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to retrieve connection information.");
    $(target).replaceChildren();
    addResult(target, "Public IP address", data.ip || "Not available");
    addResult(target, "Country", data.country || "Not available");
    addResult(target, "Region", data.region || "Not available");
    addResult(target, "City", data.city || "Not available");
    addResult(target, "Timezone", data.timezone || "Not available");
    addResult(target, "Cloudflare data centre", data.colo || "Not available");
    addResult(target, "Network ASN", data.asn ? `AS${data.asn}` : "Not available");
  } catch (error) { showError(target, error.message || "Unable to retrieve IP information."); }
});


// Public email security checks.
let latestEmailAssessment = null;
$("email-check").addEventListener("click", async () => {
  const domain = $("email-domain").value.trim().replace(/\.$/, "").toLowerCase();
  const selector = $("dkim-selector").value.trim();
  const target = "email-results";
  const validDomain = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/;
  if (!validDomain.test(domain)) return showError(target, "Enter a valid public domain name, such as example.com.");
  if (selector && !/^[a-zA-Z0-9_-]{1,63}$/.test(selector)) return showError(target, "Enter a valid DKIM selector using letters, numbers, hyphens or underscores.");
  $("email-report").hidden = true;
  latestEmailAssessment = null;
  $(target).textContent = "Checking public DNS and policy configuration…";
  try {
    const params = new URLSearchParams({domain});
    if (selector) params.set("selector", selector);
    const response = await fetch(`/api/email-security?${params.toString()}`, {
      headers: {"Accept":"application/json"}, cache: "no-store"
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Email security lookup failed.");
    latestEmailAssessment = data;
    $("email-report").hidden = false;
    $(target).replaceChildren();

    const heading = document.createElement("p");
    heading.className = "status";
    heading.textContent = `DNS assessment for ${data.domain}`;
    $(target).append(heading);

    const coverage = data.coverage || { found: 0, total: 3, percentage: 0 };
    const coverageBlock = document.createElement("div");
    coverageBlock.className = "coverage-summary";
    const coverageHeading = document.createElement("div");
    coverageHeading.className = "coverage-heading";
    const coverageTitle = document.createElement("strong");
    coverageTitle.textContent = "Email authentication coverage";
    const coverageValue = document.createElement("strong");
    coverageValue.textContent = `${coverage.percentage}%`;
    coverageHeading.append(coverageTitle, coverageValue);
    const coverageTrack = document.createElement("div");
    coverageTrack.className = "coverage-track";
    coverageTrack.setAttribute("role", "progressbar");
    coverageTrack.setAttribute("aria-label", "Email authentication records found");
    coverageTrack.setAttribute("aria-valuemin", "0");
    coverageTrack.setAttribute("aria-valuemax", "100");
    coverageTrack.setAttribute("aria-valuenow", String(coverage.percentage));
    const coverageFill = document.createElement("div");
    coverageFill.className = "coverage-fill";
    coverageFill.style.width = `${coverage.percentage}%`;
    coverageTrack.append(coverageFill);
    const coverageDetail = document.createElement("p");
    coverageDetail.className = "fine-print";
    coverageDetail.textContent = `${coverage.found} of 3 authentication record types found (SPF, DKIM and DMARC). This measures record presence only, not configuration quality or successful email authentication.`;
    coverageBlock.append(coverageHeading, coverageTrack, coverageDetail);
    $(target).append(coverageBlock);

    if (data.health && data.health.percentage !== null) {
      const health = document.createElement("div"); health.className = "coverage-summary";
      const line = document.createElement("div"); line.className = "coverage-heading";
      const label = document.createElement("strong"); label.textContent = "Indicative configuration health";
      const score = document.createElement("strong"); score.textContent = `${data.health.percentage}%`;
      line.append(label, score);
      const note = document.createElement("p"); note.className = "fine-print"; note.textContent = data.health.note;
      health.append(line, note); $(target).append(health);
    }

    const addSection = (name, item) => {
      const block = document.createElement("div");
      block.className = "result-item";
      const title = document.createElement("strong");
      title.textContent = `${name}: ${item.status}`;
      block.append(title);
      const detail = document.createElement("p");
      detail.textContent = item.summary;
      block.append(detail);
      if (item.records && item.records.length) {
        item.records.forEach(record => {
          const code = document.createElement("code");
          code.textContent = record;
          block.append(code);
        });
      }
      if (item.notes && item.notes.length) {
        const note = document.createElement("p");
        note.className = "fine-print";
        note.textContent = item.notes.join(" ");
        block.append(note);
      }
      $(target).append(block);
    };
    addSection("SPF", data.spf);
    addSection("DKIM", data.dkim);
    addSection("DMARC", data.dmarc);
    addSection("MX records", data.mx);
    addSection("MTA-STS", data.mtaSts);
    addSection("TLS-RPT", data.tlsRpt);
    addSection("DNSSEC", data.dnssec);
    addSection("BIMI", data.bimi);
    addSection("DANE / TLSA", data.dane);
    addSection("Live SMTP TLS", data.smtpTls);
  } catch (error) {
    showError(target, error.message || "Unable to complete the email security check.");
  }
});


// Download a plain-text copy of the latest assessment. The report is generated locally.
$("email-report").addEventListener("click", () => {
  if (!latestEmailAssessment) return;
  const data = latestEmailAssessment;
  const sections = ["spf", "dkim", "dmarc", "mx", "mtaSts", "tlsRpt", "dnssec", "bimi", "dane", "smtpTls"];
  const lines = [`Email security assessment: ${data.domain}`, `Generated: ${new Date().toISOString()}`, `Authentication coverage: ${data.coverage.percentage}% (${data.coverage.found}/${data.coverage.total})`, `Indicative configuration health: ${data.health?.percentage == null ? "Not calculated" : `${data.health.percentage}%`}`, ""];
  for (const key of sections) {
    const item = data[key]; if (!item) continue;
    lines.push(`${key.toUpperCase()}: ${item.status}`, item.summary || "");
    for (const record of item.records || []) lines.push(`  Record: ${record}`);
    for (const note of item.notes || []) lines.push(`  Note: ${note}`);
    lines.push("");
  }
  lines.push("Limitations: This is a DNS/HTTPS configuration assessment, not a live email delivery, SMTP TLS negotiation, or authentication test. DKIM selector discovery is not exhaustive. Optional technologies are not required for every domain.");
  const blob = new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" });
  const link = document.createElement("a"); const objectUrl = URL.createObjectURL(blob);
  link.href = objectUrl; link.download = `email-security-${data.domain}.txt`;
  document.body.append(link); link.click(); link.remove(); URL.revokeObjectURL(objectUrl);
});
