
const TXT_TYPE = "TXT";
const DOMAIN_RE = /^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/;

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().replace(/\.$/, "").toLowerCase();
  const selector = (url.searchParams.get("selector") || "").trim();

  if (!DOMAIN_RE.test(domain)) return json({ error: "Invalid public domain name." }, 400);
  if (selector && !/^[a-zA-Z0-9_-]{1,63}$/.test(selector)) {
    return json({ error: "Invalid DKIM selector." }, 400);
  }

  try {
    const [spfTxt, dmarcTxt] = await Promise.all([
      lookupTxt(domain),
      lookupTxt(`_dmarc.${domain}`)
    ]);

    // Selectors are provider-chosen, so this is a best-effort common-name scan.
    const commonSelectors = [
      "default", "google", "google1", "google2", "selector1", "selector2",
      "s1", "s2", "dkim", "dkim1", "dkim2", "mail", "email",
      "k1", "k2", "mandrill", "sendgrid", "protonmail", "protonmail2",
      "protonmail3", "zoho", "amazonses"
    ];
    const selectors = [...new Set([...commonSelectors, ...(selector ? [selector] : [])])];
    const discovered = [];

    // Bounded concurrency avoids sending a large burst of DNS requests.
    for (let i = 0; i < selectors.length; i += 5) {
      const batch = selectors.slice(i, i + 5);
      const results = await Promise.all(batch.map(async candidate => ({
        selector: candidate,
        records: await lookupTxt(`${candidate}._domainkey.${domain}`)
      })));
      for (const result of results) {
        const keys = result.records.filter(value => /(?:^|;)\s*p\s*=/i.test(value) || /^v=DKIM1/i.test(value));
        if (keys.length) discovered.push({ selector: result.selector, records: keys });
      }
    }

    const spfRecords = spfTxt.filter(value => /^v=spf1(?:\s|$)/i.test(value));
    const spf = assessSpf(spfRecords);
    const dmarcRecords = dmarcTxt.filter(value => /^v=DMARC1(?:\s|$)/i.test(value));
    const dmarc = assessDmarc(dmarcRecords);
    const dkim = assessDkim(discovered, selectors, selector, domain);

    return json({ domain, spf, dkim, dmarc }, 200);
  } catch {
    return json({ error: "The public DNS lookup could not be completed. Please try again." }, 502);
  }
}

async function lookupTxt(name) {
  // Follow CNAME aliases because DNS-over-HTTPS JSON may return the alias
  // without including the target TXT answer in the same response.
  const visited = new Set();
  let current = name.replace(/\.$/, "");
  const txtRecords = [];

  for (let hop = 0; hop < 8; hop++) {
    const normalized = current.toLowerCase().replace(/\.$/, "");
    if (visited.has(normalized)) break;
    visited.add(normalized);

    const resolver = new URL("https://cloudflare-dns.com/dns-query");
    resolver.searchParams.set("name", current);
    resolver.searchParams.set("type", TXT_TYPE);
    const response = await fetch(resolver.toString(), {
      headers: { "Accept": "application/dns-json" },
      cf: { cacheTtl: 60, cacheEverything: true }
    });
    if (!response.ok) throw new Error("DNS resolver error");

    const data = await response.json();
    const answers = data.Answer || [];

    for (const answer of answers.filter(item => item.type === 16)) {
      const value = answer.data
        .replace(/^"/, "")
        .replace(/"$/, "")
        .replace(/"\s*"/g, "");
      if (value && !txtRecords.includes(value)) txtRecords.push(value);
    }

    const cname = answers.find(item => item.type === 5);
    if (!cname) break;

    const target = String(cname.data || "").replace(/\.$/, "");
    if (!target) break;
    current = target;
  }

  return txtRecords;
}
function assessSpf(records) {
  if (!records.length) return { status: "Not found", summary: "No SPF TXT record beginning with v=spf1 was found at the domain.", records: [] };
  if (records.length > 1) return { status: "Problem detected", summary: "Multiple SPF records were found. A domain should publish one SPF policy; multiple records can cause SPF PermError.", records };
  const record = records[0];
  const notes = [];
  if (!/(^|\s)(all)(\s|$)/i.test(record)) notes.push("No 'all' mechanism was detected. Review whether the policy is complete.");
  if (/\+all(?:\s|$)/i.test(record)) notes.push("The +all mechanism authorizes all senders and is generally unsafe.");
  if (record.length > 450) notes.push("The TXT policy is unusually long; check DNS TXT string handling and SPF evaluation.");
  return {
    status: notes.length ? "Review recommended" : "Record found",
    summary: "One SPF record was found. This basic check does not recursively evaluate includes or confirm the SPF 10-DNS-lookup limit.",
    records, notes
  };
}

function assessDmarc(records) {
  if (!records.length) return { status: "Not found", summary: "No DMARC TXT record was found at _dmarc." + " The domain may not publish a DMARC policy.", records: [] };
  if (records.length > 1) return { status: "Problem detected", summary: "Multiple DMARC records were found. Only one DMARC record should be published.", records };
  const record = records[0];
  const tags = Object.fromEntries(record.split(";").map(part => part.trim()).filter(Boolean).map(part => {
    const index = part.indexOf("=");
    return index > -1 ? [part.slice(0, index).trim().toLowerCase(), part.slice(index + 1).trim()] : ["", ""];
  }).filter(([key]) => key));
  const notes = [];
  if (!/^v=DMARC1$/i.test(tags.v || "")) notes.push("The DMARC version tag is missing or not in the expected position.");
  if (!["none", "quarantine", "reject"].includes((tags.p || "").toLowerCase())) notes.push("The policy tag p= is missing or has an unrecognized value.");
  if ((tags.p || "").toLowerCase() === "none") notes.push("The policy is monitoring-only (p=none); it does not request quarantine or rejection.");
  if (!tags.rua) notes.push("No aggregate reporting address (rua) was found.");
  return {
    status: notes.length ? "Review recommended" : "Record found",
    summary: `DMARC policy: ${tags.p || "not specified"}. This check reviews common tags and does not validate report delivery or alignment in live mail.`,
    records, notes
  };
}

function assessDkim(discovered, testedSelectors, customSelector, domain) {
  const records = discovered.flatMap(item =>
    item.records.map(record => `${item.selector}._domainkey.${domain}: ${record}`)
  );

  if (!discovered.length) {
    return {
      status: "No key found in common-selector scan",
      summary: `No recognizable DKIM public-key record was found among ${testedSelectors.length} tested selectors.`,
      records: [],
      notes: [
        "This scan is not exhaustive. DKIM selectors can use names not included in the common-selector list.",
        customSelector
          ? `Your custom selector '${customSelector}' was included in the scan.`
          : "You can try a custom selector supplied by your email provider."
      ]
    };
  }

  const notes = [
    `Tested ${testedSelectors.length} selector names. This is a best-effort scan of common names, not a complete directory of all possible DKIM selectors.`,
    "Finding a public key does not verify that outgoing messages are actually signed or that their signatures pass."
  ];
  if (customSelector) notes.push(`Your custom selector '${customSelector}' was included.`);

  return {
    status: `${discovered.length} DKIM selector${discovered.length === 1 ? "" : "s"} found`,
    summary: `Found ${records.length} recognizable DKIM public-key record(s) across ${discovered.length} selector(s).`,
    records,
    notes
  };
}

function json(data, status) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
