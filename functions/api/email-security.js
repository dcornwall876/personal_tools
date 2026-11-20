const DOMAIN_RE = /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/;
const COMMON_SELECTORS = ["default","google","google1","google2","selector1","selector2","s1","s2","dkim","dkim1","dkim2","mail","email","k1","k2","mandrill","sendgrid","protonmail","protonmail2","protonmail3","zoho","amazonses"];

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().replace(/\.$/, "").toLowerCase();
  const selector = (url.searchParams.get("selector") || "").trim();
  if (!DOMAIN_RE.test(domain)) return json({ error: "Invalid public domain name." }, 400);
  if (selector && !/^[a-zA-Z0-9_-]{1,63}$/.test(selector)) return json({ error: "Invalid DKIM selector." }, 400);

  try {
    const [spfTxt, dmarcTxt, mxData, tlsRptTxt, bimiTxt] = await Promise.all([
      lookupDns(domain, "TXT"), lookupDns(`_dmarc.${domain}`, "TXT"), lookupDns(domain, "MX"),
      lookupDns(`_smtp._tls.${domain}`, "TXT"), lookupDns(`default._bimi.${domain}`, "TXT")
    ]);
    const selectors = [...new Set([...COMMON_SELECTORS, ...(selector ? [selector] : [])])];
    const discovered = [];
    for (let i = 0; i < selectors.length; i += 5) {
      const batch = selectors.slice(i, i + 5);
      const results = await Promise.all(batch.map(async candidate => ({ selector: candidate, records: await lookupDns(`${candidate}._domainkey.${domain}`, "TXT") })));
      for (const result of results) {
        const keys = result.records.filter(value => /^v=DKIM1(?:;|\s|$)/i.test(value) || /(?:^|;)\s*p\s*=/i.test(value));
        if (keys.length) discovered.push({ selector: result.selector, records: keys });
      }
    }
    const spfRecords = spfTxt.filter(value => /^v=spf1(?:\s|$)/i.test(value));
    const dmarcRecords = dmarcTxt.filter(value => /^v=DMARC1(?:;|\s|$)/i.test(value));
    const spf = await assessSpf(spfRecords, domain);
    const dmarc = assessDmarc(dmarcRecords);
    const dkim = assessDkim(discovered, selectors, selector, domain);
    const mx = mxData.length ? result("MX records found", "Mail exchangers are published. This does not verify that the servers accept mail or are reachable over SMTP.", mxData) : result("No MX records found", "No MX records were returned for this domain. If it receives email, check its mail-hosting DNS configuration.");
    const mtaSts = await checkMtaSts(domain);
    const tlsRpt = assessTlsRpt(tlsRptTxt);
    const dnssec = mxData.authenticated ? result("DNSSEC validated by resolver", "Cloudflare DNS marked the MX response as authenticated (AD flag). This indicates resolver-side DNSSEC validation for this response; it is not an independent DNSSEC audit.") : result("Not confirmed", "The MX DNS response did not carry an authenticated-data (AD) indication. DNSSEC may be absent, not validated by this resolver, or the signal may be unavailable.");
    const bimi = assessBimi(bimiTxt);
    const mxTargets = mxData.map(record => record.trim().split(/\s+/).slice(1).join(" ").replace(/\.$/, "")).filter(Boolean);
    const tlsaChecks = await Promise.all(mxTargets.slice(0, 5).map(async host => ({ host, records: await lookupDns(`_25._tcp.${host}`, "TLSA") })));
    const tlsaRecords = tlsaChecks.flatMap(x => x.records.map(r => `${x.host}: ${r}`));
    const dane = tlsaRecords.length ? result("TLSA record found", "A TLSA record was found for at least one MX hostname on SMTP port 25. This is a DANE-related DNS indicator; it does not verify the DNSSEC chain or successful SMTP validation.", tlsaRecords) : result("No TLSA record found", mxTargets.length ? `No TLSA records were found for the first ${Math.min(mxTargets.length,5)} MX hostname(s) checked. DANE is optional.` : "No MX hostname was available to check for SMTP TLSA records.");
    const found = [spfRecords.length > 0, discovered.length > 0, dmarcRecords.length > 0].filter(Boolean).length;
    const coverage = { found, total: 3, percentage: Math.round(found / 3 * 100) };
    const checks = [spf, dkim, dmarc, mx, mtaSts, tlsRpt, dnssec, bimi, dane];
    const health = calculateHealth(checks);
    return json({ domain, spf, dkim, dmarc, mx, mtaSts, tlsRpt, dnssec, bimi, dane, smtpTls: result("Not tested", "Live SMTP TLS negotiation has not been performed. This checker validates published DNS records and retrieves the MTA-STS policy over HTTPS, but it does not open a direct SMTP connection or verify the mail server’s negotiated TLS version or certificate. Use a dedicated SMTP/TLS test for that."), coverage, health }, 200);
  } catch {
    return json({ error: "The public DNS lookup could not be completed. Please try again." }, 502);
  }
}

async function lookupDns(name, type) {
  const visited = new Set(); let current = name.replace(/\.$/, ""); const values = []; let authenticated = false;
  for (let hop = 0; hop < 8; hop++) {
    const normalized = current.toLowerCase().replace(/\.$/, ""); if (visited.has(normalized)) break; visited.add(normalized);
    const resolver = new URL("https://cloudflare-dns.com/dns-query"); resolver.searchParams.set("name", current); resolver.searchParams.set("type", type);
    const response = await fetch(resolver.toString(), { headers: { Accept: "application/dns-json" }, cf: { cacheTtl: 60, cacheEverything: true } });
    if (!response.ok) throw new Error("DNS resolver error");
    const data = await response.json(); authenticated = authenticated || data.AD === true;
    const answers = data.Answer || [];
    for (const answer of answers.filter(item => item.type === typeCode(type))) { const value = String(answer.data || "").replace(/^"|"$/g, "").replace(/"\s*"/g, ""); if (value && !values.includes(value)) values.push(value); }
    const cname = answers.find(item => item.type === 5); if (!cname) break; current = String(cname.data || "").replace(/\.$/, ""); if (!current) break;
  }
  values.authenticated = authenticated; return values;
}
function typeCode(type) { return ({ A:1, NS:2, CNAME:5, SOA:6, PTR:12, MX:15, TXT:16, AAAA:28, SRV:33, TLSA:52 })[type]; }
function result(status, summary, records = [], notes = []) { return { status, summary, records, notes }; }
async function assessSpf(records, domain) {
  if (!records.length) return result("Not found", "No SPF TXT record beginning with v=spf1 was found at the domain.");
  if (records.length > 1) return result("Problem detected", "Multiple SPF records were found. A domain should publish one SPF policy; multiple records can cause SPF PermError.", records);

  const record = records[0];
  const notes = [];
  if (!/(^|\s)[+~?-]?all(\s|$)/i.test(record)) notes.push("No 'all' mechanism was detected. Review whether the policy is complete.");
  if (/\+all(?:\s|$)/i.test(record)) notes.push("The +all mechanism authorizes all senders and is generally unsafe.");
  if (/%\{[^}]+\}/.test(record)) notes.push("SPF macros are present. The recursive DNS-lookup estimate may be incomplete because macro expansion depends on the sending context.");

  const stats = { lookups: 0, issues: [], visited: new Set() };
  await countSpfLookups(domain, record, stats, 0);
  if (stats.lookups > 10) notes.push(`The SPF policy tree appears to require ${stats.lookups} DNS-querying terms, exceeding SPF's limit of 10.`);
  else notes.push(`The recursive SPF estimate found ${stats.lookups} DNS-querying term(s) across the policy and its include/redirect records (maximum 10).`);
  notes.push(...stats.issues);

  return result(notes.some(note => /exceed|multiple|loop|could not|unable|macro/i.test(note)) ? "Review recommended" : "Record found", "One SPF record was found. The checker follows include and redirect policies and counts common DNS-querying mechanisms. This is a diagnostic estimate, not a full SPF evaluation for a specific sending IP address.", records, notes);
}

async function countSpfLookups(domain, record, stats, depth) {
  if (depth > 10) {
    stats.issues.push("SPF include/redirect nesting exceeded the checker’s safe recursion depth; the lookup estimate may be incomplete.");
    return;
  }
  const normalizedDomain = domain.toLowerCase().replace(/\.$/, "");
  if (stats.visited.has(normalizedDomain)) {
    stats.issues.push(`An SPF include/redirect loop or repeated policy reference was detected at ${normalizedDomain}.`);
    return;
  }
  stats.visited.add(normalizedDomain);

  const tokens = record.trim().split(/\s+/).slice(1);
  for (const token of tokens) {
    const term = token.replace(/^[+?~-]/, "");
    const include = term.match(/^include:([^\s]+)$/i);
    const redirect = term.match(/^redirect=([^\s]+)$/i);
    const exists = term.match(/^exists:([^\s]+)$/i);
    const simple = term.match(/^(a|mx|ptr)(?::([^\s/]+))?(?:\/.*)?$/i);

    if (include || redirect) {
      stats.lookups += 1;
      const target = (include || redirect)[1].replace(/\.$/, "");
      if (!/^(?=.{1,253}$)(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?)(?:\.(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?))*$/.test(target)) {
        stats.issues.push(`Could not safely evaluate SPF target '${target}'.`);
        continue;
      }
      try {
        const targetTxt = await lookupDns(target, "TXT");
        const targetPolicies = targetTxt.filter(value => /^v=spf1(?:\s|$)/i.test(value));
        if (targetPolicies.length > 1) {
          stats.issues.push(`The SPF target ${target} publishes multiple SPF records.`);
        } else if (targetPolicies.length === 1) {
          await countSpfLookups(target, targetPolicies[0], stats, depth + 1);
        } else {
          stats.issues.push(`The SPF ${include ? "include" : "redirect"} target ${target} did not publish an SPF record.`);
        }
      } catch {
        stats.issues.push(`The SPF target ${target} could not be queried; the lookup estimate may be incomplete.`);
      }
    } else if (exists || simple) {
      stats.lookups += 1;
    }
  }
  stats.visited.delete(normalizedDomain);
}

function assessDmarc(records) {
  if (!records.length) return result("Not found", "No DMARC TXT record was found at _dmarc." );
  if (records.length > 1) return result("Problem detected", "Multiple DMARC records were found. Only one DMARC record should be published.", records);
  const record = records[0]; const tags = Object.fromEntries(record.split(";").map(p => p.trim()).filter(Boolean).map(p => { const i=p.indexOf("="); return i>-1 ? [p.slice(0,i).trim().toLowerCase(),p.slice(i+1).trim()] : ["",""]; }).filter(([k])=>k));
  const notes=[]; if (!/^DMARC1$/i.test(tags.v||"")) notes.push("The DMARC version tag is missing or not in the expected position.");
  if (!["none","quarantine","reject"].includes((tags.p||"").toLowerCase())) notes.push("The policy tag p= is missing or unrecognized.");
  if ((tags.p||"").toLowerCase()==="none") notes.push("The policy is monitoring-only (p=none); it does not request quarantine or rejection.");
  if (!tags.rua) notes.push("No aggregate reporting address (rua) was found.");
  if (tags.pct && (!/^\d+$/.test(tags.pct) || Number(tags.pct)>100)) notes.push("The pct value should be an integer from 0 to 100.");
  if (tags.sp && !["none","quarantine","reject"].includes(tags.sp.toLowerCase())) notes.push("The sp tag has an unrecognized value.");
  return result(notes.length ? "Review recommended" : "Record found", `DMARC policy: ${tags.p||"not specified"}. Alignment: adkim=${tags.adkim||"r (default)"}, aspf=${tags.aspf||"r (default)"}. This does not test live message alignment or report delivery.`, records, notes);
}
function assessDkim(found, tested, custom, domain) {
  const records=found.flatMap(x=>x.records.map(r=>`${x.selector}._domainkey.${domain}: ${r}`));
  if (!found.length) return result("No key found in common-selector scan", `No recognizable DKIM public-key record was found among ${tested.length} tested selectors.`, [], ["Selector discovery is not exhaustive; selectors can have arbitrary names.", custom ? `Custom selector '${custom}' was included.` : "Try a selector supplied by your email provider."]);
  return result(`${found.length} DKIM selector${found.length===1?"":"s"} found`, `Found ${records.length} public-key record(s) across ${found.length} selector(s). A published key does not prove outgoing messages are signed or pass DKIM.`, records, [`Tested ${tested.length} common selector names; this scan is not exhaustive.`]);
}
function assessTlsRpt(records) {
  if (!records.length) return result("Not found", "No TLS-RPT TXT record was found at _smtp._tls.");
  const valid=records.filter(r=>/^v=TLSRPTv1(?:;|\s|$)/i.test(r));
  const notes=[]; if (!valid.length) notes.push("A TXT record exists, but no recognizable v=TLSRPTv1 record was found.");
  if (valid.some(r=>!/rua\s*=\s*mailto:/i.test(r))) notes.push("A rua=mailto reporting destination was not detected.");
  return result(valid.length ? (notes.length?"Review recommended":"Record found") : "Unrecognized record", "TLS-RPT publishes destinations for reports about TLS delivery problems. This check cannot confirm that reports are actually being delivered.", records, notes);
}
function assessBimi(records) {
  if (!records.length) return result("Not found", "No BIMI TXT record was found at default._bimi. BIMI is optional and generally depends on DMARC enforcement and other requirements.");
  const valid=records.some(r=>/^v=BIMI1(?:;|\s|$)/i.test(r));
  return result(valid?"Record found":"Unrecognized record", "A BIMI-related TXT record was returned. This does not validate the logo, certificate, or mailbox-provider display eligibility.", records, valid?[]:["The returned TXT record did not begin with v=BIMI1."]);
}
async function checkMtaSts(domain) {
  const dns=await lookupDns(`_mta-sts.${domain}`,"TXT");
  if (!dns.length) return result("Not found", "No _mta-sts TXT record was found.");
  const record=dns.find(r=>/^v=STSv1(?:;|\s|$)/i.test(r));
  if (!record) return result("Unrecognized record", "A TXT record exists, but no recognizable v=STSv1 identifier was found.", dns);
  let id=""; const idMatch=record.match(/(?:^|;)\s*id\s*=\s*([^;\s]+)/i); if(idMatch) id=idMatch[1];
  try {
    const response=await fetch(`https://mta-sts.${domain}/.well-known/mta-sts.txt`,{headers:{Accept:"text/plain"},redirect:"manual"});
    if(!response.ok) return result("Policy file unavailable", `The MTA-STS TXT record exists, but the HTTPS policy endpoint returned HTTP ${response.status}.`, [record]);
    const body=(await response.text()).slice(0,12000); const fields={};
    for(const line of body.split(/\r?\n/)){const m=line.match(/^\s*([a-z_-]+)\s*:\s*(.*?)\s*$/i);if(m) (fields[m[1].toLowerCase()]??=[]).push(m[2]);}
    const notes=[]; if((fields.version||[])[0]!=="STSv1") notes.push("The policy version should be STSv1.");
    if(!["testing","enforce","none"].includes((fields.mode||[])[0])) notes.push("The policy mode is missing or unrecognized.");
    if(!(fields.mx||[]).length) notes.push("No mx pattern was found in the policy file.");
    if(!/^\d+$/.test((fields["max_age"]||[])[0]||"")) notes.push("max_age is missing or not numeric.");
    return result(notes.length?"Review recommended":"Policy file retrieved", `The MTA-STS policy file was retrieved over HTTPS. DNS policy id: ${id||"not specified"}. Mode: ${(fields.mode||[])[0]||"not specified"}.`, [record, ...body.split(/\r?\n/).filter(Boolean)], notes);
  } catch { return result("Policy file could not be retrieved", "The MTA-STS DNS record exists, but the HTTPS policy endpoint could not be reached.", [record]); }
}
function calculateHealth(checks) {
  // Score only records actually detected. Absence of optional technologies such as
  // BIMI or DANE must not lower the score. This is not a deliverability rating.
  const applicable = checks.filter(item => Array.isArray(item.records) && item.records.length > 0);
  const warnings = applicable.reduce((count, item) => count + (/Review recommended|Problem detected|Unrecognized|unavailable|could not be retrieved/i.test(item.status) ? Math.max(1, (item.notes || []).length) : 0), 0);
  const percentage = applicable.length ? Math.max(0, Math.round((1 - warnings / Math.max(1, applicable.length * 2)) * 100)) : null;
  return { percentage, evaluated: applicable.length, note: "Indicative diagnostic score based only on detected records and basic warnings. Missing optional technologies are not penalized. This is not a certification, live authentication test, or deliverability score." };
}
function json(data,status){return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store","X-Content-Type-Options":"nosniff"}});}
