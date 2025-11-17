// app.js
const express = require('express');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;

//const FLAG = process.env.FLAG || "FLAG{headers_are_powerful}";

// Serve static files from /static
app.use('/static', express.static(path.join(__dirname, 'static')));

// Small helper: convert IPv4 string to 32-bit number
function ipToInt(ip) {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some(p => isNaN(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}

// Check if ip is inside cidr (e.g. "59.103.0.0/16")
function cidrContains(cidr, ip) {
  const [net, prefix] = cidr.split('/');
  const ipInt = ipToInt(ip);
  const netInt = ipToInt(net);
  if (ipInt === null || netInt === null) return false;
  const mask = prefix === '0' ? 0 : (0xffffffff << (32 - Number(prefix))) >>> 0;
  return (ipInt & mask) === (netInt & mask);
}

// Representative Pakistan CIDR blocks (a small selection for the challenge).
const PAKISTAN_CIDRS = [
  '39.32.0.0/11',
  '59.103.0.0/16',
  '119.152.0.0/13',
  '101.50.64.0/18',
  '103.111.38.0/23'
];

function isPakistanIp(ip) {
  if (!ip || typeof ip !== 'string') return false;
  const first = ip.split(',')[0].trim();
  for (const cidr of PAKISTAN_CIDRS) {
    if (cidrContains(cidr, first)) return true;
  }
  return false;
}

function levelHtml(title = '', msg = '', imgFile = '') {
  // If title and msg are empty we won't render the text — only the image.
  const titleHtml = title ? `<h1>${title}</h1>` : '';
  const msgHtml = msg ? `<p>${msg}</p>` : '';

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8">
        <title>${title || 'Headers CTF'}</title>
        <style>
          body{font-family: Arial, Helvetica, sans-serif; padding:20px; max-width:820px; margin:auto; text-align:center}
          .meme{max-width:80%; height:auto; border-radius:8px; box-shadow: 0 4px 10px rgba(0,0,0,0.08)}
          code{background:#eee;padding:2px 6px;border-radius:4px}
        </style>
      </head>
      <body>
        ${titleHtml}
        ${msgHtml}
        ${imgFile ? `<img class="meme" src="/static/${imgFile}" alt="hint image">` : ''}
      </body>
    </html>
  `;
}

app.get('/', (req, res) => {
  const ua = req.get('User-Agent') || '';
  const dateHeader = req.get('Date') || '';
  const lang = (req.get('Accept-Language') || '').toLowerCase();
  const xff = req.get('X-Forwarded-For') || '';
  const referer = req.get('Referer') || '';
  const origin = req.get('Origin') || '';

  // 1) User-Agent check (ACM-CTF)
  if (!ua.includes('ACM-CTF')) {
    // show only the image that contains the hint
    return res.status(403).send(levelHtml('', '', 'drake-01.png'));
  }

  // 2) Date header: require year 2036
  let dateOk = false;
  if (dateHeader) {
    const parsed = Date.parse(dateHeader);
    if (!isNaN(parsed)) {
      const d = new Date(parsed);
      if (d.getUTCFullYear() === 2036) dateOk = true;
    }
  }
  if (!dateOk) {
    return res.status(403).send(levelHtml('', '', 'drake-02.png'));
  }

  // 3) Accept-Language check
  if (!lang.startsWith('en')) {
    return res.status(403).send(levelHtml('', '', 'drake-03.png'));
  }

  // 4) "Same-site" check: Accept either Referer or Origin that matches this host
  const host = req.get('host') || '';
  let sameSite = false;
  if (referer) {
    try {
      const r = new URL(referer);
      if (r.host === host) sameSite = true;
    } catch (e) { /* ignore invalid referer */ }
  }
  if (!sameSite && origin) {
    try {
      const o = new URL(origin);
      if (o.host === host) sameSite = true;
    } catch (e) { /* ignore */ }
  }
  if (!sameSite) {
    return res.status(403).send(levelHtml('', '', 'drake-04.png'));
  }

  // 5) X-Forwarded-For: require a Pakistan IP (first IP in the header)
  if (!isPakistanIp(xff)) {
    return res.status(403).send(levelHtml('', '', 'drake-05.png'));
  }

  // Success: all checks passed -> reveal flag (image + flag text)
  return res.send(levelHtml('Congratulations 🎉', `All headers verified!`, 'drake-06.png'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Headers CTF running on http://0.0.0.0:${PORT}`);
});
