# InSec — InsideSecurity 

Site simples inspirado no Have I Been Pwned, com verificação **passiva** de segurança usando APIs públicas.

> ⚠️ Foco Dev Jr.: código direto, sem complicações. Não executa ataques ativos (nada de DoS/DDoS ou injeções).

## O que checa
- **TLS & MitM (indicadores):** nota TLS via **SSL Labs**, presença de **HSTS** via **Mozilla Observatory**.
- **DoS/DDoS (indicadores passivos):** detecção de **CDN/WAF** e cabeçalhos de _rate limit_.
- **SQL Injection (passivo):** não realiza payloads; apenas indicações (no protótipo: desabilitado).
- **Phishing:** **Google Safe Browsing API** (opcional) + heurística de _lookalike_ com marcas e comparação de título/domínio.

## Rodando
```bash
npm install
# opcional: exportar chave do Google Safe Browsing (v4)
# Linux/Mac:
export GOOGLE_SAFE_BROWSING_KEY="SUA_CHAVE_AQUI"
# Windows PowerShell:
# setx GOOGLE_SAFE_BROWSING_KEY "SUA_CHAVE_AQUI"

npm start
# Acesse: http://localhost:3000
```

## Observações
- SSL Labs pode retornar `IN_PROGRESS` na primeira chamada. Rode novamente após alguns segundos para nota final.
- Mozilla Observatory já faz _rescan_ e retorna o último resultado disponível.
- Checagens **DoS/DDoS** aqui são **apenas indícios** (CDN/WAF, rate limit). Testes ativos de carga **não são realizados** por ética e segurança.
- Para phishing, sem a chave do Google Safe Browsing a saída marcará **"Sem chave API"**.
