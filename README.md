# Personal Tools

A privacy-conscious utility website for Cloudflare Pages.

## Included tools

- QR code generator (runs in the browser; QRCode.js is loaded from cdnjs)
- Password generator (Web Crypto random values, browser-side)
- DNS lookup (Cloudflare Pages Function querying Cloudflare DNS-over-HTTPS)
- Expanded email security checker (SPF, DKIM, DMARC, MX, MTA-STS, TLS-RPT, DNSSEC, BIMI and DANE/TLSA indicators; includes a downloadable text report)
- Browser privacy check (local browser signals)
- IP information (Cloudflare request metadata for the current visitor)

## Deploy with GitHub and Cloudflare Pages

1. Create a GitHub repository. It can be private.
2. Upload the contents of this folder to the repository root. Keep the `functions` folder at the root.
3. In Cloudflare, open **Workers & Pages** → **Create application** → **Pages** → **Connect to Git**.
4. Select this repository.
5. Use these settings:
   - Production branch: `main`
   - Framework preset: `None`
   - Build command: leave blank
   - Build output directory: `.` (repository root)
6. Deploy.
7. In the Pages project, open **Settings** → **Functions** / **Build configuration** if needed and confirm Pages Functions are enabled. The `functions` directory must be at the project root.
8. Under **Custom domains**, add `tools.YOURDOMAIN.com` and follow Cloudflare's prompts.

If your repository has a `public` folder and you prefer to use it as the Pages output directory, move `functions` into the same deployment root as the generated output or use a build setup that copies it. The simplest setup for this project is to keep `index.html`, `app.js`, `styles.css`, `_headers`, and `functions/` together in the repository root.

## Privacy notes

- Password generation happens in the browser.
- QR content is encoded in the browser. The QRCode.js library is loaded from cdnjs, so the browser contacts that CDN to download the library. The QR text itself is not sent to the CDN.
- DNS lookups, including the email security checks, are sent by Pages Functions to Cloudflare's public DNS-over-HTTPS resolver. The MTA-STS check also requests the domain's public policy URL over HTTPS.
- The IP endpoint returns the IP address and coarse connection metadata Cloudflare sees for the current visitor. It does not intentionally persist the response, but Cloudflare may process operational data under its service terms.
- The privacy check inspects ordinary browser-exposed settings. It is not a comprehensive fingerprinting, tracking, WebRTC leak or anonymity test.
- Do not enter secrets into the DNS lookup tool. Do not treat this website as a password manager.

## Security headers

`_headers` applies baseline security headers to static responses. Review the Content Security Policy if you add more third-party scripts, images, fonts or APIs. Do not add `unsafe-inline` or broad wildcard sources casually.

## Local testing

Static tools can be tested by opening `index.html` in a browser, but DNS and IP endpoints require Cloudflare Pages Functions. Deploy to a Pages preview or production URL to test all six tools.


## Email security checker scope

- SPF: detects SPF TXT records and multiple policies, follows common include/redirect references to estimate DNS-querying terms against the 10-lookup limit, and flags common policy concerns. Macro-based SPF mechanisms and unusual DNS behavior can make the estimate incomplete; this is not a full SPF evaluation for a sending IP address.
- DKIM: checks common selector names and an optional custom selector. Selector discovery is best-effort and not exhaustive; no match does not prove DKIM is absent.
- DMARC: checks the policy, alignment tags, reporting destination and selected syntax concerns. It does not validate real message alignment or report delivery.
- MX: lists published mail exchangers; it does not test SMTP reachability.
- MTA-STS: retrieves the public policy over HTTPS and checks its main fields.
- TLS-RPT: detects and performs basic syntax checks on the reporting TXT record; it cannot confirm reports are arriving.
- DNSSEC: reports the authenticated-data (AD) signal returned by the DNS resolver; this is a resolver-side validation indicator.
- BIMI: detects the conventional default BIMI TXT record; it does not validate logo assets, certificates or mailbox-provider eligibility.
- DANE/TLSA: checks conventional SMTP port-25 TLSA records for up to five MX hosts. It does not validate the complete DNSSEC chain or a live SMTP handshake.
- Live SMTP TLS negotiation is deliberately marked **Not tested**. The checker does not open an SMTP connection or verify a live STARTTLS handshake, negotiated TLS version or mail-server certificate. Cloudflare Pages Functions are not used here to claim a live SMTP test.
- Authentication coverage is the percentage of SPF, DKIM and DMARC record types detected. The separate diagnostic score is an indicative heuristic based on detected records and basic warnings; neither score is a certification or deliverability guarantee.
- The checker follows DNS CNAME aliases with a bounded chain of up to eight hops and loop detection.

