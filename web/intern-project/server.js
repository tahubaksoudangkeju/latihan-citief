const fs = require('fs').promises;
const http = require('http');
const path = require('path');
const { URL } = require('url');
const crypto = require('crypto');
const undici = require('undici');
const { dset } = require('dset');
const fastJwt = require('fast-jwt');

const FLAG = process.env.FLAG || 'CYB0X1{fake_flag_for_testing}';
const PROXY_SECRET = crypto.randomBytes(32).toString('base64url');
const AUDIT = crypto.createHash('sha1').update(PROXY_SECRET).digest('hex');
const JWT_SECRET = crypto.createHash('sha256').update(AUDIT + '.jwt').digest('hex');
const ADMIN_TOKEN = crypto.randomBytes(48).toString('base64url');

const CONFIG = {
  port: 3000,
  backupPort: 3001
};

const UI_DIR = path.join(process.cwd(), 'public');
const state = { 
  sessions: new Map(), 
  security: {},
  nonces: new Map() 
};

function issueNonce(tag = 'generic') {
  const nonce = crypto.randomBytes(16).toString('base64url');
  state.nonces.set(nonce, { ts: Date.now(), used: false, tag });
  return nonce;
}

function validateNonce(nonce, consumeTag = '') {
  if (typeof nonce !== 'string' || nonce.length < 8) return false;
  const entry = state.nonces.get(nonce);
  if (!entry || entry.used) return false;
  if (Date.now() - entry.ts > 120000) { state.nonces.delete(nonce); return false; }
  entry.used = true;
  entry.tag = consumeTag || entry.tag;
  state.nonces.set(nonce, entry);
  return true;
}

async function sendStatic(res, relPath) {
  try {
    const abs = path.join(UI_DIR, relPath);
    if (!abs.startsWith(UI_DIR)) return send(res, 403, 'forbidden');
    const data = await fs.readFile(abs);
    const ext = path.extname(abs);
    const ct = ext === '.html' ? 'text/html; charset=utf-8'
      : ext === '.js' ? 'text/javascript; charset=utf-8'
      : ext === '.css' ? 'text/css; charset=utf-8'
      : 'application/octet-stream';
    res.writeHead(200, { 'content-type': ct });
    res.end(data);
  } catch (e) {
    send(res, 404, 'not found');
  }
}

function send(res, code, body, headers={}) {
  const h = Object.assign({'content-type':'application/json; charset=utf-8'}, headers);
  res.writeHead(code, h);
  if (typeof body === 'string') res.end(body);
  else res.end(JSON.stringify(body));
}

function renderTemplate(template, context = {}) {
  const safeContext = Object.assign({
  Version: '6.3.0',
    Status: 'operational',
    Timestamp: new Date().toISOString(),
    RequestId: crypto.randomBytes(8).toString('hex'),
    AdminToken: ADMIN_TOKEN,
    JwtKeyHint: JWT_SECRET.slice(0, 8) + '...' 
  }, context);

  const bannedChar = [
    'token','secret','process','global','constructor','__proto__','prototype','admin','jwt','key',
    'flag','config','session','audit','authorization','bearer','header','mfa','role','function',
    'class','require','import','export','eval','child','spawn','exec','fs','net','http','https',
    'crypto','env','system','os','user','password','root','shell','assert','debug','inspect','hook',
    'console','log','vm','worker','thread','subprocess','stdin','stdout','stderr','path','url',
    'buffer','memory','heap','stack','argv','main','module','context','globals','window','document',
    'element','node','child_process','execFile','fork','socket','tls','udp','dns','cluster','timer',
    'interval','timeout','setImmediate','performance','gc','v8','wasm','napi','bindings','ffi',
    'reflect','proxy','descriptor','defineProperty','lookup','getOwnProperty','setPrototypeOf',
    'getPrototypeOf','toString','valueOf','caller','callee','arguments','apply','bind','call',
    'constructorFunction','super','extends','instanceof','importMeta','requireResolve'
  ];

  return String(template).replace(/\{\{\s*([A-Za-z0-9_]+)\s*\}\}/g, (m, key) => {
    const lower = key.toLowerCase();
    if (bannedChar.some(b => lower.includes(b))) return '';
    return (safeContext[key] ?? '');
  });
}

const jwtVerify = fastJwt.createVerifier({
  key: JWT_SECRET,
  algorithms: ['HS256']
});

function createBackupServer() {
  const backupServer = http.createServer(async (req, res) => {
    const u = new URL(req.url, `http://localhost:${CONFIG.backupPort}`);
    
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Headers', '*');
    res.setHeader('Access-Control-Allow-Methods', '*');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      return res.end();
    }
    
    if (u.pathname === '/auth/admin' || u.pathname === '/admin-backup') {
      const auth = req.headers.authorization;
      if (auth && auth.includes(ADMIN_TOKEN)) {
        const sessionToken = crypto.randomBytes(24).toString('hex');
        state.sessions.set(sessionToken, { 
          role: 'admin', 
          created: Date.now(),
          source: 'backup_auth'
        });
        
        send(res, 200, {
          status: 'authenticated',
          session: sessionToken,
          capabilities: ['admin_panel', 'system_config']
        });
      } else {
        send(res, 401, { error: 'authentication required' });
      }
      return;
    }
    
    if (u.pathname === '/reflect') {
      const nonce = issueNonce('reflect');
      res.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      return res.end(JSON.stringify({
        url: u.toString(),
        audit: AUDIT,
        nonce
      }));
    }
    
    send(res, 404, { error: 'endpoint not found' });
  });
  
  backupServer.listen(CONFIG.backupPort, () => {
    console.log(`Backup service: localhost:${CONFIG.backupPort}`);
  });
}

const server = http.createServer(async (req, res) => {
  const u = new URL(req.url, `http://localhost:${CONFIG.port}`);
  
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', '*');
  res.setHeader('Access-Control-Allow-Methods', '*');
  res.setHeader('X-Powered-By', 'CYB0X1 Secure Web Gateway');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(200);
    return res.end();
  }

  if (req.method === 'GET' && (u.pathname === '/' || u.pathname === '/index.html')) {
    return sendStatic(res, 'index.html');
  }
  
  if (req.method === 'GET' && u.pathname.startsWith('/assets/')) {
    return sendStatic(res, u.pathname.slice(1));
  }
  
  if (req.method === 'POST' && u.pathname === '/api/scan') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const result = `Security scan results for: ${data.url}
        Target: ${data.url}
        Status: Analyzed
        Threats: None detected
        Classification: Safe
        Scan ID: ${Math.random().toString(36).slice(2)}`;
        
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end(result);
      } catch (e) {
        send(res, 400, { error: 'invalid request' });
      }
    });
    return;
  }
  
  if (req.method === 'POST' && (u.pathname === '/api/preview' || u.pathname === '/api/render')) {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        const rendered = renderTemplate(data.template || '');
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end(rendered);
      } catch (e) {
        send(res, 400, { error: 'template error' });
      }
    });
    return;
  }
  
  if (req.method === 'POST' && u.pathname === '/prefs') {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        const prefs = JSON.parse(body);

        for (const k of Object.keys(prefs)) {
          const lk = k.toLowerCase();
          if (lk === 'role' || lk.endsWith('.role')) {
            return send(res, 403, { error: 'role modification blocked' });
          }
        }

        if (Object.prototype.hasOwnProperty.call(prefs, 'security.mfaRequired') && prefs['security.mfaRequired'] === false) {
          const nonce = req.headers['x-nonce'];
          const proof = req.headers['x-mfa-proof'];
          if (!nonce || !proof) return send(res, 403, { error: 'mfa disable requires nonce and proof' });
          if (!validateNonce(String(nonce), 'prefs-mfa')) return send(res, 403, { error: 'invalid nonce' });
          const expected = crypto.createHmac('sha256', AUDIT).update('mfa=false:' + String(nonce)).digest('hex');
          if (String(proof) !== expected) return send(res, 403, { error: 'invalid mfa proof' });
          state.security.mfaRequired = false;
        }

        for (const [key, value] of Object.entries(prefs)) {
          if (key === 'security.mfaRequired') continue; 
          dset(state, key, value);
        }

        send(res, 200, { ok: true });
      } catch (e) {
        send(res, 400, { error: 'invalid preferences' });
      }
    });
    return;
  }
  
  if (req.method === 'GET' && u.pathname === '/relay') {
    const targetUrl = u.searchParams.get('u') || '/';
    
    try {
      const response = await undici.request(targetUrl, {
        maxRedirections: 2,
        headers: {
          'proxy-authorization': 'Basic ' + Buffer.from('svc:' + PROXY_SECRET).toString('base64')
        }
      });

      const text = await response.body.text();
      try { send(res, 200, JSON.parse(text)); }
      catch { send(res, 200, text, { 'content-type': 'text/plain; charset=utf-8' }); }
    } catch (e) {
      send(res, 500, { error: 'relay failed' });
    }
    return;
  }
  
  if (req.method === 'GET' && u.pathname === '/rdr') {
    const target = u.searchParams.get('to') || `http://127.0.0.1:${CONFIG.backupPort}/reflect`;
    res.writeHead(302, { 'location': target });
    res.end();
    return;
  }
  
  if (req.method === 'POST' && u.pathname === '/flag') {
    const auth = req.headers.authorization;
    const auditHeader = req.headers['x-audit'];
    const sessionHeader = req.headers['x-session'];
    const nonceHeader = req.headers['x-nonce'];
    const proofHeader = req.headers['x-proof'];

    if (!sessionHeader || !state.sessions.has(String(sessionHeader))) {
      return send(res, 403, { error: 'session required' });
    }
    const session = state.sessions.get(String(sessionHeader));
    if (!session || session.role !== 'admin') {
      return send(res, 403, { error: 'admin session required' });
    }

    if (state.security.mfaRequired !== false) {
      return send(res, 403, { error: 'mfa required' });
    }

    if (String(auditHeader) !== AUDIT) {
      return send(res, 403, { error: 'invalid audit' });
    }

    if (!proofHeader) return send(res, 403, { error: 'missing proof' });
    const expectedProof = crypto.createHmac('sha256', AUDIT).update(String(sessionHeader)).digest('hex');
    if (String(proofHeader) !== expectedProof) return send(res, 403, { error: 'invalid proof' });

    if (!nonceHeader || !validateNonce(String(nonceHeader), 'flag')) {
      return send(res, 403, { error: 'invalid nonce' });
    }

    if (auth && auth.startsWith('Bearer ')) {
      try {
        const token = auth.split(' ')[1];
        const payload = jwtVerify(token, { issuer: 'https://auth.secure.local' });
        if (!payload || payload.aud !== AUDIT) return send(res, 403, { error: 'invalid audience' });
        const expectedJti = crypto.createHash('sha1').update(String(nonceHeader) + String(payload.sub || '')).digest('hex');
        if (payload.jti !== expectedJti) return send(res, 403, { error: 'invalid jti' });
        if (payload.role === 'admin') {
          return send(res, 200, { flag: FLAG });
        }
      } catch (e) {
        // verification failed
      }
    }
    return send(res, 403, { error: 'insufficient privileges' });
  }

  if (req.method === 'POST' && u.pathname === '/admin/session') {
    const auth = req.headers.authorization || '';
    const nonceHeader = req.headers['x-nonce'];
    if (!auth.startsWith('Bearer ')) return send(res, 401, { error: 'authorization required' });
    if (!nonceHeader || !validateNonce(String(nonceHeader), 'admin-session')) return send(res, 403, { error: 'invalid nonce' });
    try {
      const token = auth.split(' ')[1];
      const payload = jwtVerify(token, { issuer: 'https://auth.secure.local' });
      if (!payload || payload.aud !== AUDIT) return send(res, 403, { error: 'invalid audience' });
      const expectedJti = crypto.createHash('sha1').update(String(nonceHeader) + String(payload.sub || '')).digest('hex');
      if (payload.jti !== expectedJti) return send(res, 403, { error: 'invalid jti' });
      if (payload.role === 'admin') {
        const sessionToken = crypto.randomBytes(24).toString('hex');
        state.sessions.set(sessionToken, { role: 'admin', created: Date.now(), source: 'jwt' });
        return send(res, 200, { ok: true, session: sessionToken });
      }
    } catch (e) {}
    return send(res, 403, { error: 'invalid token' });
  }
  
  send(res, 404, { error: 'not found' });
});

createBackupServer();

server.listen(CONFIG.port, () => {
  console.log(`SecureChain Enterprise Gateway v6.3.0`);
  console.log(`Service: localhost:${CONFIG.port}`);
  console.log(`Backup: localhost:${CONFIG.backupPort}`);
});
