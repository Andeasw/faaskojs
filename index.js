#!/usr/bin/env node

const os = require('os');
const http = require('http');
const fs = require('fs');
const axios = require('axios');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { Buffer } = require('buffer');
const { exec, execSync, spawn } = require('child_process');
const { WebSocket, createWebSocketStream } = require('ws');

process.on('uncaughtException', () => {});
process.on('unhandledRejection', () => {});

const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       
const NEZHA_PORT = process.env.NEZHA_PORT || '';           
const NEZHA_KEY = process.env.NEZHA_KEY || '';             
const KOMARI_SERVER = process.env.KOMARI_SERVER || '';     
const KOMARI_KEY = process.env.KOMARI_KEY || '';           
const DOMAIN = process.env.DOMAIN || 'your-domain.com';    
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     
const SUB_PATH = process.env.SUB_PATH || 'sub';            
const NAME = process.env.NAME || '';                       
const PORT = process.env.PORT || 3000;                     

let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.8.8', '1.1.1.1', '2001:4860:4860::8888'];
const BLOCKED_DOMAINS = ['speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me', 'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'];

const NGINX_DEFAULT_HTML = `<!DOCTYPE html><html><head><title>Welcome to nginx!</title><style>html { color-scheme: light dark; }body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }</style></head><body><h1>Welcome to nginx!</h1><p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p><p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p><p><em>Thank you for using nginx!</em></p></body></html>`;

function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => hostLower === blocked || hostLower.endsWith('.' + blocked));
}

function formatIPv6(ip) {
  return net.isIPv6(ip) ? `[${ip}]` : ip;
}

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
    ISP = `${res.data.country_code}-${res.data.isp}`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0' }, timeout: 3000 });
      ISP = `${res2.data.countryCode}-${res2.data.org}`.replace(/ /g, '_');
    } catch (e2) { ISP = 'Unknown'; }
  }
}

async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
      try {
          const res = await axios.get('https://api64.ipify.org', { timeout: 5000 });
          CurrentDomain = res.data.trim(); Tls = 'none'; CurrentPort = PORT;
      } catch (e) { CurrentDomain = 'change-your-domain.com'; Tls = 'tls'; CurrentPort = 443; }
  } else { CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443; }
}

const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/') {
    fs.readFile(path.join(__dirname, 'index.html'), 'utf8', (err, content) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(err ? NGINX_DEFAULT_HTML : content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    await getisp(); await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
    const safeDomain = formatIPv6(CurrentDomain);
    
    const vlsURL = `vless://${UUID}@${safeDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${safeDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${safeDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(Buffer.from(vlsURL + '\n' + troURL + '\n' + ssURL).toString('base64') + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' }); res.end('404 Not Found\n');
  }
});

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (net.isIP(host)) { resolve(host); return; }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) { reject(new Error('Resolve failed')); return; }
      const type = net.isIPv6(host) ? 'AAAA' : 'A';
      axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=${type}`, { timeout: 5000, headers: { 'Accept': 'application/dns-json' }})
        .then(response => {
          if (response.data.Status === 0 && response.data.Answer && response.data.Answer.length > 0) {
            const ip = response.data.Answer.find(r => r.type === 1 || r.type === 28);
            if (ip) { resolve(ip.data); return; }
          }
          tryNextDNS();
        }).catch(() => tryNextDNS());
    }
    tryNextDNS();
  });
}

function handleVlsConnection(ws, msg) {
  const [VERSION] = msg;
  const id = msg.slice(1, 17);
  if (!id.every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) return false;
  let i = msg.slice(17, 18).readUInt8() + 19;
  const port = msg.slice(i, i += 2).readUInt16BE(0);
  const ATYP = msg.slice(i, i += 1).readUInt8();
  const host = ATYP == 1 ? msg.slice(i, i += 4).join('.') :
    (ATYP == 2 ? new TextDecoder().decode(msg.slice(i + 1, i += 1 + msg.slice(i, i + 1).readUInt8())) :
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, j, a) => (j % 2 ? s.concat(a.slice(j - 1, j + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16).padStart(4, '0')).join(':') : ''));
  if (isBlockedDomain(host)) { ws.close(); return false; }
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host).then(resolvedIP => { net.connect({ host: resolvedIP, port }, function () { this.write(msg.slice(i)); duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex); }).on('error', () => {}); })
    .catch(() => { net.connect({ host, port }, function () { this.write(msg.slice(i)); duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex); }).on('error', () => {}); });
  return true;
}

function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    if (crypto.createHash('sha224').update(UUID).digest('hex') !== msg.slice(0, 56).toString()) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (msg[offset] !== 0x01) return false;
    offset += 1; const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; } 
    else if (atyp === 0x03) { const hostLen = msg[offset]; offset += 1; host = msg.slice(offset, offset + hostLen).toString(); offset += hostLen; } 
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, j, a) => (j % 2 ? s.concat(a.slice(j - 1, j + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16).padStart(4, '0')).join(':'); offset += 16; } 
    else return false;
    port = msg.readUInt16BE(offset); offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(resolvedIP => { net.connect({ host: resolvedIP, port }, function () { if (offset < msg.length) this.write(msg.slice(offset)); duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex); }).on('error', () => {}); })
      .catch(() => { net.connect({ host, port }, function () { if (offset < msg.length) this.write(msg.slice(offset)); duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex); }).on('error', () => {}); });
    return true;
  } catch (error) { return false; }
}

function handleSsConnection(ws, msg) {
  try {
    let offset = 0; const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; } 
    else if (atyp === 0x03) { const hostLen = msg[offset]; offset += 1; host = msg.slice(offset, offset + hostLen).toString(); offset += hostLen; } 
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, j, a) => (j % 2 ? s.concat(a.slice(j - 1, j + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16).padStart(4, '0')).join(':'); offset += 16; } 
    else return false;
    port = msg.readUInt16BE(offset); offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(resolvedIP => { net.connect({ host: resolvedIP, port }, function () { if (offset < msg.length) this.write(msg.slice(offset)); duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex); }).on('error', () => {}); })
      .catch(() => { net.connect({ host, port }, function () { if (offset < msg.length) this.write(msg.slice(offset)); duplex.on('error', () => {}).pipe(this).on('error', () => {}).pipe(duplex); }).on('error', () => {}); });
    return true;
  } catch (error) { return false; }
}

const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  if (!(req.url || '').startsWith(`/${WSPATH}`)) { ws.close(); return; }
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0 && msg.slice(1, 17).every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) { if (!handleVlsConnection(ws, msg)) ws.close(); return; }
    if (msg.length >= 58 && handleTrojConnection(ws, msg)) return;
    if (msg.length > 0 && [0x01, 0x03, 0x04].includes(msg[0])) { if (handleSsConnection(ws, msg)) return; }
    ws.close();
  }).on('error', () => {});
});

const N_BIN = 'sys_net'; const K_BIN = 'sys_core';
const getDownloadUrl = (type) => {
  const isArm = (os.arch() === 'arm' || os.arch() === 'arm64' || os.arch() === 'aarch64');
  if (type === 'nezha') return isArm ? (NEZHA_PORT ? 'https://arm64.ssss.nyc.mn/agent' : 'https://arm64.ssss.nyc.mn/v1') : (NEZHA_PORT ? 'https://amd64.ssss.nyc.mn/agent' : 'https://amd64.ssss.nyc.mn/v1');
  return isArm ? 'https://rt.jp.eu.org/nucleusp/K/Karm' : 'https://rt.jp.eu.org/nucleusp/K/Kamd';
};

const downloadFile = async (url, dest) => {
  try {
    const response = await axios({ method: 'get', url: url, responseType: 'stream', timeout: 15000 });
    const writer = fs.createWriteStream(dest);
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
      writer.on('finish', () => { try { fs.chmodSync(dest, 0o775); resolve(); } catch(e){ resolve(); } });
      writer.on('error', reject);
    });
  } catch (err) { throw err; }
};

const runnz = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;
  try {
    if (fs.existsSync(N_BIN)) return;
    await downloadFile(getDownloadUrl('nezha'), N_BIN);
    let cmd = '';
    let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
    if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
      cmd = `setsid nohup ./${N_BIN} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${tlsPorts.includes(NEZHA_PORT) ? '--tls' : ''} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
    } else {
      const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
      fs.writeFileSync('config.yaml', `client_secret: ${NEZHA_KEY}\ndisable_auto_update: true\ninsecure_tls: true\nreport_delay: 4\nserver: ${NEZHA_SERVER}\ntls: ${tlsPorts.includes(port) ? 'true' : 'false'}\nuuid: ${UUID}`);
      cmd = `setsid nohup ./${N_BIN} -c config.yaml >/dev/null 2>&1 &`;
    }
    exec(cmd, { shell: '/bin/bash' }, () => {});
  } catch (e) {}
};

const kmState = { proc: null, crashCount: 0, stopped: false };
const runKomari = async () => {
  if (!KOMARI_SERVER || !KOMARI_KEY || kmState.stopped) return;
  try {
    if (!fs.existsSync(K_BIN)) await downloadFile(getDownloadUrl('komari'), K_BIN);
    const startTime = Date.now();
    const proc = spawn(`./${K_BIN}`, ['-e', KOMARI_SERVER.startsWith('http') ? KOMARI_SERVER : `https://${KOMARI_SERVER}`, '-t', KOMARI_KEY], { stdio: 'ignore', detached: false });
    kmState.proc = proc;
    proc.on('error', () => { kmState.stopped = true; });
    proc.on('close', () => {
      kmState.proc = null; if (kmState.stopped) return;
      kmState.crashCount = (Date.now() - startTime > 30000) ? 0 : kmState.crashCount + 1;
      setTimeout(runKomari, Math.min(2000 * Math.pow(2, kmState.crashCount), 60000));
    });
  } catch (e) { setTimeout(runKomari, 60000); }
};

async function addAccessTask() {
  if (!AUTO_ACCESS || !DOMAIN) return;
  try { await axios.post("https://oooo.serv00.net/add-url", { url: `https://${DOMAIN}/${SUB_PATH}` }, { headers: { 'Content-Type': 'application/json' }}); } catch (e) {}
}

const clearMechanisms = () => {
  [N_BIN, K_BIN, 'config.yaml'].forEach(f => { if (fs.existsSync(f)) try { fs.unlinkSync(f); } catch (e) {} });
};

httpServer.listen(PORT, '::', () => {
  runnz().catch(()=>{});
  runKomari().catch(()=>{});
  setTimeout(clearMechanisms, 180000);
  addAccessTask().catch(()=>{});
});
