// InSec backend - simples e direto (Dev Jr.)
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const urlLib = require('url');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const GOOGLE_SB_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

// Utils
function normalizeHost(input) {
  try { return new URL(input).hostname; }
  catch {
    try { return new URL('https://' + input).hostname; }
    catch { return null; }
  }
}

function parseServerHeader(hdr) {
  if (!hdr) return 'desconhecido';
  const h = hdr.toLowerCase();
  if (h.includes('cloudflare')) return 'Cloudflare';
  if (h.includes('akamai')) return 'Akamai';
  if (h.includes('fastly')) return 'Fastly';
  if (h.includes('google front')) return 'Google Front End';
  if (h.includes('netlify')) return 'Netlify Edge';
  return 'none';
}

async function getHeaders(url) {
  try {
    const res = await axios.get(url, { timeout: 8000, maxRedirects: 5, validateStatus: () => true });
    const headers = res.headers || {};
    const server = headers['server'] || headers['via'] || '';
    const rateLimit = !!(headers['x-ratelimit-limit'] || headers['ratelimit-limit']);
    const wafProvider = (()=>{
      if (headers['cf-ray'] || headers['cf-cache-status']) return 'Cloudflare';
      if (headers['x-akamai-transformed'] || headers['x-akamai-request-id']) return 'Akamai';
      if (headers['x-sucuri-id'] || headers['x-sucuri-cache']) return 'Sucuri';
      if ((headers['server']||'').toLowerCase().includes('fastly')) return 'Fastly';
      return 'none';
    })();
    // tech hints
    const tech = [];
    if (headers['x-powered-by']) tech.push(headers['x-powered-by']);
    if (headers['server']) tech.push('server:' + headers['server']);
    return { headers, server, rateLimit, wafProvider, tech };
  } catch (e) {
    return { headers: {}, server: '', rateLimit: false, wafProvider: 'none', tech: [] };
  }
}

async function getSSLLabs(host) {
  try {
    const url = `https://api.ssllabs.com/api/v3/analyze?host=${host}&publish=off&all=done&fromCache=on`;
    const { data } = await axios.get(url, { timeout: 15000 });
    const ep = (data.endpoints && data.endpoints[0]) || {};
    // protocols list (basic)
    const protocols = (ep.details && ep.details.protocols) ? ep.details.protocols.map(p => `${p.name} ${p.version}`) : [];
    return {
      status: data.status,
      grade: ep.grade || null,
      protocols
    };
  } catch (e) {
    return { status: 'error' };
  }
}

async function getObservatory(host) {
  try {
    // Trigger analysis (rescan)
    await axios.post(`https://http-observatory.security.mozilla.org/api/v1/analyze?host=${host}&rescan=true`);
    // Fetch latest results
    const { data } = await axios.get(`https://http-observatory.security.mozilla.org/api/v1/getScanResults?host=${host}`, { timeout: 15000 });
    const hsts = data.find(x => x.name === 'strict-transport-security') || null;
    return {
      hstsEnabled: hsts ? (hsts.score_modifier >= 0 && (hsts.pass || hsts.score_description?.includes('present'))) : false,
      hstsMaxAge: hsts?.output?.max_age || null
    };
  } catch (e) {
    return { hstsEnabled: false, hstsMaxAge: null };
  }
}

// Simple Levenshtein distance (Dev Jr.)
function levenshtein(a, b) {
  const m = [];
  for (let i=0;i<=b.length;i++) m[i]=[i];
  for (let j=0;j<=a.length;j++) m[0][j]=j;
  for (let i=1;i<=b.length;i++) {
    for (let j=1;j<=a.length;j++) {
      m[i][j] = Math.min(
        m[i-1][j]+1,
        m[i][j-1]+1,
        m[i-1][j-1] + (b.charAt(i-1)==a.charAt(j-1)?0:1)
      );
    }
  }
  return m[b.length][a.length];
}

function brandLookalike(host) {
  const brands = [
    {name:'google', domain:'google.com'},
    {name:'facebook', domain:'facebook.com'},
    {name:'microsoft', domain:'microsoft.com'},
    {name:'apple', domain:'apple.com'},
    {name:'gov.br', domain:'gov.br'},
    {name:'itau', domain:'itau.com.br'},
    {name:'nubank', domain:'nubank.com.br'}
  ];
  const parts = host.split('.').slice(-2).join('.'); // base domain approx
  for (const b of brands) {
    const dist = levenshtein(parts, b.domain);
    if (dist <= 2 && parts !== b.domain) {
      return { suspicious: true, brand: b.domain, distance: dist };
    }
  }
  return { suspicious: false };
}

async function fetchTitle(url) {
  try {
    const { data } = await axios.get(url, { timeout: 8000, maxContentLength: 200000 });
    const m = String(data).match(/<title[^>]*>([^<]{0,120})<\/title>/i);
    return m ? m[1].trim() : null;
  } catch {
    return null;
  }
}

async function safeBrowsing(url) {
  if (!GOOGLE_SB_KEY) return 'unknown';
  try {
    const body = {
      client: { clientId: "insec", clientVersion: "1.0" },
      threatInfo: {
        threatTypes: ["MALWARE","SOCIAL_ENGINEERING","UNWANTED_SOFTWARE","POTENTIALLY_HARMFUL_APPLICATION"],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    };
    const { data } = await axios.post(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${GOOGLE_SB_KEY}`, body, { timeout: 8000 });
    if (data && data.matches && data.matches.length) return 'threat';
    return 'ok';
  } catch (e) {
    return 'error';
  }
}

app.post('/api/scan', async (req, res) => {
  const input = req.body?.url || '';
  const host = normalizeHost(input);
  if (!host) return res.status(400).json({ error: 'URL inválida' });

  const url = `https://${host}`;

  // Parallel tasks (simple Promise.all)
  const [hdrs, tls, obs, title, sb] = await Promise.all([
    getHeaders(url),
    getSSLLabs(host),
    getObservatory(host),
    fetchTitle(url),
    safeBrowsing(url)
  ]);

  const waf = { provider: hdrs.wafProvider, rateLimit: hdrs.rateLimit };
  const hsts = { enabled: !!obs.hstsEnabled, maxAge: obs.hstsMaxAge || null };

  // Very naive SQLi "passive" indicator: look for server stack only
  const sqli = { errorsExposed: false }; // not doing active probes in this prototype

  const phishing = {
    safeBrowsing: sb,
    brandLookalike: brandLookalike(host),
    title: title
  };

  const report = {
    host,
    headers: { server: hdrs.server || '' },
    waf,
    tls,
    hsts,
    tech: hdrs.tech,
    sqli,
    phishing
  };

  res.json(report);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log('InSec backend rodando na porta ' + PORT);
});
