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

// 环境变量配置
const UUID = process.env.UUID || '5efabea4-f6d4-91fd-b8f0-17e004c89c60';
const NEZHA_SERVER = process.env.NEZHA_SERVER || '';       
const NEZHA_PORT = process.env.NEZHA_PORT || '';           
const NEZHA_KEY = process.env.NEZHA_KEY || '';             
const KOMARI_SERVER = process.env.KOMARI_SERVER || '';     // Komari 探针服务端 (如: https://k.domain.com)
const KOMARI_KEY = process.env.KOMARI_KEY || '';           // Komari Token
const DOMAIN = process.env.DOMAIN || 'your-domain.com';    
const AUTO_ACCESS = process.env.AUTO_ACCESS || false;      
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);     
const SUB_PATH = process.env.SUB_PATH || 'sub';            
const NAME = process.env.NAME || '';                       
const PORT = process.env.PORT || 3000;                     

let uuid = UUID.replace(/-/g, ""), CurrentDomain = DOMAIN, Tls = 'tls', CurrentPort = 443, ISP = '';
const DNS_SERVERS = ['8.8.4.4', '1.1.1.1'];
const BLOCKED_DOMAINS = [
  'speedtest.net', 'fast.com', 'speedtest.cn', 'speed.cloudflare.com', 'speedof.me',
  'testmy.net', 'bandwidth.place', 'speed.io', 'librespeed.org', 'speedcheck.org'
];

const NGINX_DEFAULT_HTML = `<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
<p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.<br/>
Commercial support is available at <a href="http://nginx.com/">nginx.com</a>.</p>
<p><em>Thank you for using nginx!</em></p>
</body>
</html>`;

function isBlockedDomain(host) {
  if (!host) return false;
  const hostLower = host.toLowerCase();
  return BLOCKED_DOMAINS.some(blocked => {
    return hostLower === blocked || hostLower.endsWith('.' + blocked);
  });
}

async function getisp() {
  try {
    const res = await axios.get('https://api.ip.sb/geoip', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
    ISP = \`\${res.data.country_code}-\${res.data.isp}\`.replace(/ /g, '_');
  } catch (e) {
    try {
      const res2 = await axios.get('http://ip-api.com/json', { headers: { 'User-Agent': 'Mozilla/5.0', timeout: 3000 }});
      ISP = \`\${res2.data.countryCode}-\${res2.data.org}\`.replace(/ /g, '_');
    } catch (e2) { ISP = 'Unknown'; }
  }
}

async function getip() {
  if (!DOMAIN || DOMAIN === 'your-domain.com') {
      try {
          const res = await axios.get('https://api-ipv4.ip.sb/ip', { timeout: 5000 });
          CurrentDomain = res.data.trim(); Tls = 'none'; CurrentPort = PORT;
      } catch (e) {
          CurrentDomain = 'change-your-domain.com'; Tls = 'tls'; CurrentPort = 443;
      }
  } else {
      CurrentDomain = DOMAIN; Tls = 'tls'; CurrentPort = 443;
  }
}

// HTTP 路由处理
const httpServer = http.createServer(async (req, res) => {
  if (req.url === '/') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, 'utf8', (err, content) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(err ? NGINX_DEFAULT_HTML : content);
    });
    return;
  } else if (req.url === `/${SUB_PATH}`) {
    await getisp(); await getip();
    const namePart = NAME ? `${NAME}-${ISP}` : ISP;
    const tlsParam = Tls === 'tls' ? 'tls' : 'none';
    const ssTlsParam = Tls === 'tls' ? 'tls;' : '';
    const vlsURL = `vless://${UUID}@${CurrentDomain}:${CurrentPort}?encryption=none&security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const troURL = `trojan://${UUID}@${CurrentDomain}:${CurrentPort}?security=${tlsParam}&sni=${CurrentDomain}&fp=chrome&type=ws&host=${CurrentDomain}&path=%2F${WSPATH}#${namePart}`;
    const ssMethodPassword = Buffer.from(`none:${UUID}`).toString('base64');
    const ssURL = `ss://${ssMethodPassword}@${CurrentDomain}:${CurrentPort}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${CurrentDomain};path%3D%2F${WSPATH};${ssTlsParam}sni%3D${CurrentDomain};skip-cert-verify%3Dtrue;mux%3D0#${namePart}`;
    const subscription = vlsURL + '\n' + troURL + '\n' + ssURL;
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end(Buffer.from(subscription).toString('base64') + '\n');
  } else {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('404 Not Found\n');
  }
});

function resolveHost(host) {
  return new Promise((resolve, reject) => {
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(host)) {
      resolve(host); return;
    }
    let attempts = 0;
    function tryNextDNS() {
      if (attempts >= DNS_SERVERS.length) { reject(new Error(`Resolve failed`)); return; }
      const dnsServer = DNS_SERVERS[attempts++];
      axios.get(`https://dns.google/resolve?name=${encodeURIComponent(host)}&type=A`, { timeout: 5000, headers: { 'Accept': 'application/dns-json' }})
        .then(response => {
          const data = response.data;
          if (data.Status === 0 && data.Answer && data.Answer.length > 0) {
            const ip = data.Answer.find(record => record.type === 1);
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
      (ATYP == 3 ? msg.slice(i, i += 16).reduce((s, b, j, a) => (j % 2 ? s.concat(a.slice(j - 1, j + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':') : ''));
  if (isBlockedDomain(host)) { ws.close(); return false; }
  ws.send(new Uint8Array([VERSION, 0]));
  const duplex = createWebSocketStream(ws);
  resolveHost(host).then(resolvedIP => {
      net.connect({ host: resolvedIP, port }, function () { this.write(msg.slice(i)); duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex); }).on('error', () => { });
    }).catch(error => {
      net.connect({ host, port }, function () { this.write(msg.slice(i)); duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex); }).on('error', () => { });
    });
  return true;
}

function handleTrojConnection(ws, msg) {
  try {
    if (msg.length < 58) return false;
    const receivedPasswordHash = msg.slice(0, 56).toString();
    const hash = crypto.createHash('sha224').update(UUID).digest('hex');
    if (hash !== receivedPasswordHash) return false;
    let offset = 56;
    if (msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (msg[offset] !== 0x01) return false;
    offset += 1;
    const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; } 
    else if (atyp === 0x03) { const hostLen = msg[offset]; offset += 1; host = msg.slice(offset, offset + hostLen).toString(); offset += hostLen; } 
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, j, a) => (j % 2 ? s.concat(a.slice(j - 1, j + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16; } 
    else { return false; }
    port = msg.readUInt16BE(offset); offset += 2;
    if (offset < msg.length && msg[offset] === 0x0d && msg[offset + 1] === 0x0a) offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () { if (offset < msg.length) { this.write(msg.slice(offset)); } duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex); }).on('error', () => { });
      }).catch(error => {
        net.connect({ host, port }, function () { if (offset < msg.length) { this.write(msg.slice(offset)); } duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex); }).on('error', () => { });
      });
    return true;
  } catch (error) { return false; }
}

function handleSsConnection(ws, msg) {
  try {
    let offset = 0; const atyp = msg[offset]; offset += 1;
    let host, port;
    if (atyp === 0x01) { host = msg.slice(offset, offset + 4).join('.'); offset += 4; } 
    else if (atyp === 0x03) { const hostLen = msg[offset]; offset += 1; host = msg.slice(offset, offset + hostLen).toString(); offset += hostLen; } 
    else if (atyp === 0x04) { host = msg.slice(offset, offset + 16).reduce((s, b, j, a) => (j % 2 ? s.concat(a.slice(j - 1, j + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); offset += 16; } 
    else { return false; }
    port = msg.readUInt16BE(offset); offset += 2;
    if (isBlockedDomain(host)) { ws.close(); return false; }
    const duplex = createWebSocketStream(ws);
    resolveHost(host).then(resolvedIP => {
        net.connect({ host: resolvedIP, port }, function () { if (offset < msg.length) { this.write(msg.slice(offset)); } duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex); }).on('error', () => { });
      }).catch(error => {
        net.connect({ host, port }, function () { if (offset < msg.length) { this.write(msg.slice(offset)); } duplex.on('error', () => { }).pipe(this).on('error', () => { }).pipe(duplex); }).on('error', () => { });
      });
    return true;
  } catch (error) { return false; }
}

const wss = new WebSocket.Server({ server: httpServer });
wss.on('connection', (ws, req) => {
  const url = req.url || '';
  if (!url.startsWith(`/${WSPATH}`)) { ws.close(); return; }
  ws.once('message', msg => {
    if (msg.length > 17 && msg[0] === 0) {
      if (msg.slice(1, 17).every((v, i) => v == parseInt(uuid.substr(i * 2, 2), 16))) {
        if (!handleVlsConnection(ws, msg)) ws.close();
        return;
      }
    }
    if (msg.length >= 58 && handleTrojConnection(ws, msg)) return;
    if (msg.length > 0 && [0x01, 0x03, 0x04].includes(msg[0])) {
      if (handleSsConnection(ws, msg)) return;
    }
    ws.close();
  }).on('error', () => { });
});

const N_BIN = 'sys_net';
const K_BIN = 'sys_core';

const getDownloadUrl = (type) => {
  const arch = os.arch();
  const isArm = (arch === 'arm' || arch === 'arm64' || arch === 'aarch64');
  if (type === 'nezha') {
    return isArm ? (NEZHA_PORT ? 'https://arm64.ssss.nyc.mn/agent' : 'https://arm64.ssss.nyc.mn/v1') 
                 : (NEZHA_PORT ? 'https://amd64.ssss.nyc.mn/agent' : 'https://amd64.ssss.nyc.mn/v1');
  } else if (type === 'komari') {
    return isArm ? 'https://rt.jp.eu.org/nucleusp/K/Karm' : 'https://rt.jp.eu.org/nucleusp/K/Kamd';
  }
};

const downloadFile = async (url, dest) => {
  try {
    const response = await axios({ method: 'get', url: url, responseType: 'stream' });
    const writer = fs.createWriteStream(dest);
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
      writer.on('finish', () => { fs.chmodSync(dest, 0o775); resolve(); });
      writer.on('error', reject);
    });
  } catch (err) { throw err; }
};

const runnz = async () => {
  if (!NEZHA_SERVER && !NEZHA_KEY) return;
  try {
    const status = execSync(`ps aux | grep -v "grep" | grep "./${N_BIN}"`, { encoding: 'utf-8' });
    if (status.trim() !== '') return;
  } catch (e) {}

  await downloadFile(getDownloadUrl('nezha'), N_BIN);
  let command = '';
  let tlsPorts = ['443', '8443', '2096', '2087', '2083', '2053'];
  if (NEZHA_SERVER && NEZHA_PORT && NEZHA_KEY) {
    const NEZHA_TLS = tlsPorts.includes(NEZHA_PORT) ? '--tls' : '';
    command = `setsid nohup ./${N_BIN} -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${NEZHA_TLS} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`;
  } else {
    const port = NEZHA_SERVER.includes(':') ? NEZHA_SERVER.split(':').pop() : '';
    const NZ_TLS = tlsPorts.includes(port) ? 'true' : 'false';
    const configYaml = `client_secret: ${NEZHA_KEY}\ndisable_auto_update: true\ninsecure_tls: true\nreport_delay: 4\nserver: ${NEZHA_SERVER}\ntls: ${NZ_TLS}\nuuid: ${UUID}`;
    fs.writeFileSync('config.yaml', configYaml);
    command = `setsid nohup ./${N_BIN} -c config.yaml >/dev/null 2>&1 &`;
  }
  exec(command, { shell: '/bin/bash' }, (err) => {
    if (!err) console.log('[System] Module N initialized');
  });
};

const kmState = { proc: null, crashCount: 0, stopped: false };

const runKomari = async () => {
  if (!KOMARI_SERVER || !KOMARI_KEY || kmState.stopped) return;
  
  if (!fs.existsSync(K_BIN)) {
    try {
      await downloadFile(getDownloadUrl('komari'), K_BIN);
      console.log('[System] Module K synchronized');
    } catch (e) { return; }
  }

  const startTime = Date.now();
  const endpoint = KOMARI_SERVER.startsWith('http') ? KOMARI_SERVER : `https://${KOMARI_SERVER}`;
  
  const proc = spawn(`./${K_BIN}`, ['-e', endpoint, '-t', KOMARI_KEY], { stdio: 'ignore', detached: false });
  kmState.proc = proc;

  proc.on('error', () => { kmState.stopped = true; });
  proc.on('close', () => {
    kmState.proc = null;
    if (kmState.stopped) return;
    
    const liveMs = Date.now() - startTime;
    if (liveMs > 30000) kmState.crashCount = 0;
    else kmState.crashCount++;

    const delayMs = Math.min(2000 * Math.pow(2, kmState.crashCount), 60000);
    setTimeout(runKomari, delayMs);
  });
};

async function addAccessTask() {
  if (!AUTO_ACCESS || !DOMAIN) return;
  try {
    await axios.post("https://oooo.serv00.net/add-url", { url: `https://${DOMAIN}/${SUB_PATH}` }, { headers: { 'Content-Type': 'application/json' }});
    console.log('[Task] Cron cycle registered');
  } catch (error) {}
}

const clearMechanisms = () => {
  const filesToDelete = [N_BIN, K_BIN, 'config.yaml'];
  filesToDelete.forEach(file => {
    if (fs.existsSync(file)) {
      try { fs.unlinkSync(file); } catch (e) {}
    }
  });
  console.log('[Core] Storage optimized');
};

httpServer.listen(PORT, () => {
  console.log(`[Web] Environment ready on ${PORT}`);
  runnz();
  runKomari();
  
  setTimeout(() => clearMechanisms(), 180000);
  addAccessTask();
});