export async function onRequestGet({ request }) {
  // Cloudflare supplies these values for the current incoming request.
  // The endpoint returns only the caller's own connection metadata.
  const cf = request.cf || {};
  const ip = request.headers.get("CF-Connecting-IP") || "";

  return new Response(JSON.stringify({
    ip,
    country: cf.country || null,
    region: cf.region || null,
    city: cf.city || null,
    timezone: cf.timezone || null,
    colo: cf.colo || null,
    asn: cf.asn || null
  }), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store, private",
      "X-Content-Type-Options": "nosniff"
    }
  });
}
