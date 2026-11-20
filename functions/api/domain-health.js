const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))*$/i;

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const domain = (url.searchParams.get("domain") || "").trim().replace(/\.$/, "").toLowerCase();

  if (!DOMAIN_RE.test(domain) || !domain.includes(".")) {
    return json({ error: "Enter a valid public domain name, such as example.com." }, 400);
  }

  try {
    const [a, aaaa, caa, ns] = await Promise.all([
      lookupDns(domain, "A"),
      lookupDns(domain, "AAAA"),
      lookupDns(domain, "CAA"),
      lookupDns(domain, "NS")
    ]);

    const hasAddress = a.records.length > 0 || aaaa.records.length > 0;
    const dns = hasAddress
      ? check("Pass", "Public address records were returned.", [...a.records, ...aaaa.records])
      : check("Warning", "No A or AAAA records were returned. The domain may not host a website, or its address records may be unavailable.");

    const dnssec = (a.authenticated || aaaa.authenticated)
      ? check("Pass", "The DNS resolver returned the authenticated-data (AD) signal for an address lookup. This is evidence of resolver-side DNSSEC validation, not an independent DNSSEC audit.")
      : check("Warning", "The resolver did not return an authenticated-data (AD) signal for the address lookup. DNSSEC may be absent, or the resolver may not provide a validation signal.");

    const caaCheck = caa.records.length
      ? check("Pass", "CAA records are published and identify which certificate authorities may issue certificates for this domain.", caa.records)
      : check("Warning", "No CAA records were found. CAA is optional, but publishing records can restrict which certificate authorities may issue certificates for the domain.");

    const nsCheck = ns.records.length
      ? check("Pass", "Authoritative nameserver records were returned.", ns.records)
      : check("Warning", "No NS records were returned by this lookup.");

    let httpsCheck;
    if (!hasAddress) {
      httpsCheck = check("Not tested", "HTTPS was not tested because no public A or AAAA address record was found.");
    } else {
      try {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 7000);
        let response;
        try {
          response = await fetch(`https://${domain}/`, {
            method: "HEAD",
            redirect: "manual",
            signal: controller.signal,
            headers: { "User-Agent": "PersonalTools-DomainHealth/1.0" }
          });
        } finally {
          clearTimeout(timeout);
        }
        const location = response.headers.get("location");
        httpsCheck = check("Pass", `An HTTPS connection was established. The server returned HTTP ${response.status}${response.statusText ? ` ${response.statusText}` : ""}. This confirms HTTPS endpoint reachability, not the full site's security posture.`, [
          `HTTP status: ${response.status}`,
          ...(location ? [`Redirect location: ${location}`] : [])
        ]);
      } catch (error) {
        httpsCheck = check("Fail", error?.name === "AbortError"
          ? "The HTTPS request timed out after 7 seconds."
          : "An HTTPS connection could not be established. The site may not support HTTPS, may be unavailable, or may block automated requests.");
      }
    }

    return json({
      domain,
      generatedAt: new Date().toISOString(),
      dns,
      dnssec,
      caa: caaCheck,
      nameservers: nsCheck,
      https: httpsCheck,
      addressRecords: [...a.records, ...aaaa.records]
    }, 200);
  } catch {
    return json({ error: "The domain health lookup could not be completed. Please try again." }, 502);
  }
}

async function lookupDns(name, type) {
  const resolver = new URL("https://cloudflare-dns.com/dns-query");
  resolver.searchParams.set("name", name);
  resolver.searchParams.set("type", type);
  const response = await fetch(resolver.toString(), {
    headers: { Accept: "application/dns-json" },
    cf: { cacheTtl: 60, cacheEverything: true }
  });
  if (!response.ok) throw new Error("DNS resolver error");
  const data = await response.json();
  return {
    records: (data.Answer || []).filter(record => record.type === ({ A: 1, NS: 2, AAAA: 28, CAA: 257 }[type])).map(record => record.data),
    authenticated: data.AD === true,
    status: data.Status
  };
}

function check(status, summary, records = []) {
  return { status, summary, records };
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
