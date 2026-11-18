const ALLOWED_TYPES = new Set(["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA", "PTR", "SRV"]);
const TYPE_NAMES = {1:"A", 2:"NS", 5:"CNAME", 6:"SOA", 12:"PTR", 15:"MX", 16:"TXT", 28:"AAAA", 33:"SRV", 257:"CAA"};

export async function onRequestGet({ request }) {
  const url = new URL(request.url);
  const name = (url.searchParams.get("name") || "").trim().replace(/\.$/, "");
  const type = (url.searchParams.get("type") || "A").toUpperCase();

  if (!name || name.length > 253 || !/^(?=.{1,253}$)([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(\.([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(name)) {
    return json({ error: "Invalid public domain name." }, 400);
  }
  if (!ALLOWED_TYPES.has(type)) return json({ error: "Unsupported DNS record type." }, 400);

  try {
    const resolverUrl = new URL("https://cloudflare-dns.com/dns-query");
    resolverUrl.searchParams.set("name", name);
    resolverUrl.searchParams.set("type", type);
    const upstream = await fetch(resolverUrl.toString(), {
      headers: { "Accept": "application/dns-json" },
      cf: { cacheTtl: 60, cacheEverything: true }
    });
    if (!upstream.ok) return json({ error: "The DNS resolver returned an error." }, 502);
    const result = await upstream.json();
    return json({
      name,
      type,
      status: result.Status,
      answers: (result.Answer || []).map(answer => ({
        name: answer.name,
        type: answer.type,
        typeName: TYPE_NAMES[answer.type] || String(answer.type),
        TTL: answer.TTL,
        data: answer.data
      }))
    }, 200);
  } catch {
    return json({ error: "The DNS lookup could not be completed." }, 502);
  }
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
