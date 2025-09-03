const form = document.getElementById('scanForm');
const urlInput = document.getElementById('url');
const result = document.getElementById('result');
const output = document.getElementById('output');
const loading = document.getElementById('loading');
const riskBadge = document.getElementById('riskBadge');
const btn = document.getElementById('scanBtn');

function normalizeHost(input) {
  try {
    const u = new URL(input);
    return u.hostname;
  } catch {
    // try prepend https://
    try {
      const u2 = new URL('https://' + input);
      return u2.hostname;
    } catch {
      return null;
    }
  }
}

function renderKV(title, items) {
  const group = document.createElement('div');
  group.className = 'group';
  const h4 = document.createElement('h4');
  h4.textContent = title;
  group.appendChild(h4);

  const kv = document.createElement('div');
  kv.className = 'kv';
  items.forEach(([k, v]) => {
    const kd = document.createElement('div'); kd.className = 'k'; kd.textContent = k;
    const vd = document.createElement('div'); vd.className = 'v'; vd.textContent = v;
    kv.appendChild(kd); kv.appendChild(vd);
  });
  group.appendChild(kv);
  return group;
}

function computeRisk(data) {
  // naive risk: count warnings/errors
  let risk = 0;
  if (data?.tls?.grade && ['A','A+'].includes(data.tls.grade)) {} else risk++;
  if (data?.hsts?.enabled === false) risk++;
  if (data?.waf?.provider === 'none') risk++;
  if (data?.phishing?.safeBrowsing === 'threat') risk += 2;
  if (data?.phishing?.brandLookalike?.suspicious) risk++;
  return risk <= 1 ? 'Baixo' : risk === 2 ? 'Médio' : 'Alto';
}

form.addEventListener('submit', async () => {
  const value = urlInput.value.trim();
  const host = normalizeHost(value);
  if (!host) {
    alert('URL inválida.');
    return;
  }
  result.classList.remove('hidden');
  loading.classList.remove('hidden');
  output.innerHTML = '';
  btn.disabled = true;

  try {
    const res = await fetch('/api/scan', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ url: value })
    });
    const data = await res.json();

    loading.classList.add('hidden');
    output.innerHTML = '';

    // TLS / MitM (via SSL Labs + HSTS)
    const tlsItems = [
      ['Host', data.host || host],
      ['Nota TLS', data.tls?.grade || '—'],
      ['Protocolos', (data.tls?.protocols || []).join(', ') || '—'],
      ['HSTS', data.hsts?.enabled ? 'Ativo' : 'Inativo'],
      ['HSTS max-age', data.hsts?.maxAge || '—']
    ];
    output.appendChild(renderKV('TLS & MitM (indicadores)', tlsItems));

    // DoS / DDoS (indicadores passivos)
    const ddosItems = [
      ['CDN/WAF', data.waf?.provider || '—'],
      ['Rate-Limit header', data.waf?.rateLimit ? 'Detectado' : 'Não detectado'],
      ['Server', data.headers?.server || '—']
    ];
    output.appendChild(renderKV('DoS/DDoS (indicadores passivos)', ddosItems));

    // SQL Injection (passivo)
    const sqliItems = [
      ['Checagem ativa', 'Não realizada (somente passiva)'],
      ['Erros SQL expostos', data.sqli?.errorsExposed ? 'Possível' : 'Não observado'],
      ['Stack tecnológico', (data.tech || []).join(', ') || '—']
    ];
    output.appendChild(renderKV('SQL Injection (passivo)', sqliItems));

    // Phishing
    const phishItems = [
      ['Google Safe Browsing', data.phishing?.safeBrowsing === 'ok' ? 'OK' :
        data.phishing?.safeBrowsing === 'unknown' ? 'Sem chave API' :
        data.phishing?.safeBrowsing === 'error' ? 'Erro API' :
        data.phishing?.safeBrowsing === 'threat' ? 'Ameaça detectada' : '—'],
      ['Semelhança com marcas', data.phishing?.brandLookalike?.suspicious ? 'Suspeito' : 'Normal'],
      ['Título da página', data.phishing?.title || '—'],
      ['Domínio', data.host || host]
    ];
    output.appendChild(renderKV('Phishing', phishItems));

    // Overall risk
    const risk = computeRisk(data);
    riskBadge.textContent = `Risco: ${risk}`;

  } catch (e) {
    loading.classList.add('hidden');
    output.innerHTML = '<div class="group">Falha ao analisar. Tente novamente.</div>';
    console.error(e);
  } finally {
    btn.disabled = false;
  }
});
