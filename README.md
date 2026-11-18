# Personal Tools

A privacy-conscious utility website for Cloudflare Pages.

## Included tools

- QR code generator (runs in the browser; QRCode.js is loaded from cdnjs)
- Password generator (Web Crypto random values, browser-side)
- DNS lookup (Cloudflare Pages Function querying Cloudflare DNS-over-HTTPS)
- Hash generator (Web Crypto SHA-256 / SHA-384 / SHA-512, browser-side)
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

- Password generation and hashing happen in the browser.
- QR content is encoded in the browser. The QRCode.js library is loaded from cdnjs, so the browser contacts that CDN to download the library. The QR text itself is not sent to the CDN.
- DNS lookups are sent by the Pages Function to Cloudflare's public DNS-over-HTTPS resolver.
- The IP endpoint returns the IP address and coarse connection metadata Cloudflare sees for the current visitor. It does not intentionally persist the response, but Cloudflare may process operational data under its service terms.
- The privacy check inspects ordinary browser-exposed settings. It is not a comprehensive fingerprinting, tracking, WebRTC leak or anonymity test.
- Do not enter secrets into the DNS lookup tool. Do not treat this website as a password manager.

## Security headers

`_headers` applies baseline security headers to static responses. Review the Content Security Policy if you add more third-party scripts, images, fonts or APIs. Do not add `unsafe-inline` or broad wildcard sources casually.

## Local testing

Static tools can be tested by opening `index.html` in a browser, but DNS and IP endpoints require Cloudflare Pages Functions. Deploy to a Pages preview or production URL to test all six tools.
