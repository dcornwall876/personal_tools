
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
    const [spfTxt, dmarcTxt, dkimTxt] = await Promise.all([
      lookupTxt(domain),
      lookupTxt(`_dmarc.${domain}`),
      selector ? lookupTxt(`${selector}._domainkey.${domain}`) : Promise.resolve(null)
    ]);

    const spfRecords = spfTxt.filter(value => /^v=spf1(?:\\s|$)/i.test(value));
    const spf = assessSpf(spfRecords);
    const dmarcRecords = dmarcTxt.filter(value => /^v=DMARC1(?:\\s|$)/i.test(value));
    const dmarc = assessDmarc(dmarcRecords);
    const dkim = assessDkim(dkimTxt, selector);

    return json({ domain, spf, dkim, dmarc }, 200);
  } catch {
    return json({ error: "The public DNS lookup could not be completed. Please try again." }, 502);
  }
}

async function lookupTxt(name) {
  const resolver = new URL("https://cloudflare-dns.com/dns-query");
  resolver.searchParams.set("name", name);
  resolver.searchParams.set("type", TXT_TYPE);
  const response = await fetch(resolver.toString(), {
    headers: { "Accept": "application/dns-json" },
    cf: { cacheTtl: 60, cacheEverything: true }
  });
  if (!response.ok) throw new Error("DNS resolver error");
  const data = await response.json();
  return (data.Answer || []).filter(answer => answer.type === 16).map(answer =>
    answer.data.replace(/^"|"$/g, "").replace(/"\\s*"/g, "")
  );
}

function assessSpf(records) {
  if (!records.length) return { status: "Not found", summary: "No SPF TXT record beginning with v=spf1 was found at the domain.", records: [] };
  if (records.length > 1) return { status: "Problem detected", summary: "Multiple SPF records were found. A domain should publish one SPF policy; multiple records can cause SPF PermError.", records };
  const record = records[0];
  const notes = [];
  if (!/(^|\\s)(all)(\\s|$)/i.test(record)) notes.push("No 'all' mechanism was detected. Review whether the policy is complete.");
  if (/\\+all(?:\\s|$)/i.test(record)) notes.push("The +all mechanism authorizes all senders and is generally unsafe.");
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

function assessDkim(records, selector) {
  if (!selector) return {
    status: "Selector needed",
    summary: "Enter a DKIM selector to check its public key. Selectors are provider-specific and cannot be reliably inferred from the domain alone.",
    records: [],
    notes: ["A missing selector is not evidence that DKIM is absent."]
  };
  const keys = records.filter(value => /(?:^|;)\\s*p\\s*=/.test(value) || /^v=DKIM1/i.test(value));
  if (!records.length || !keys.length) return {
    status: "No key found for this selector",
    summary: `No recognizable DKIM TXT public-key record was found at ${selector}._domainkey.`,
    records: records || [],
    notes: ["Other DKIM selectors may exist. This result applies only to the selector entered."]
  };
  const notes = [];
  const record = keys[0];
  const pMatch = record.match(/(?:^|;)\\s*p\\s*=\\s*([^;]*)/i);
  if (pMatch && !pMatch[1].trim()) notes.push("The p= public-key value is empty; this can indicate a revoked key.");
  if (keys.length > 1) notes.push("More than one DKIM-like TXT record was returned for this selector; review the DNS configuration.");
  return {
    status: notes.length ? "Review recommended" : "Public key found",
    summary: `A DKIM TXT record was found for selector '${selector}'. This does not verify signatures on actual messages.`,
    records: keys, notes
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
