#!/usr/bin/env node
import fs from "fs";
import path from "path";
import axios from "axios";
import * as cheerio from "cheerio";
import TelegramBot from "node-telegram-bot-api";
import puppeteer from "puppeteer";
import { exec } from "child_process";
import { promisify } from "util";
import os from "os";
import crypto from "crypto";
import readline from "readline";

const execAsync = promisify(exec);
const CONFIG = JSON.parse(fs.readFileSync("config.json", "utf8"));
const COUNTRY_PREFIX = JSON.parse(fs.readFileSync("negara.json", "utf8"));
const COUNTRY_CODES = JSON.parse(fs.readFileSync("country.json", "utf8"));
const processedCalls = new Set();
const LIVE_CALLS_URL = "https://www.orangecarrier.com/live/calls";
const LOGIN_URL = "https://www.orangecarrier.com/login";

// ----- LICENSING / PROTECTION -----
const HWID_FILE = "hwid.lock";
const LICENSE_FILE = "license.dat";

// Secret key untuk enkripsi — sebaiknya gunakan ENV var di deployment (process.env.LICENSE_KEY)
const LICENSE_SECRET = process.env.LICENSE_KEY || "DRX-SECRET-KEY-CHANGE-THIS";
const AES_KEY = crypto.createHash("sha256").update(LICENSE_SECRET).digest(); // 32 bytes

function getHWID() {
  if (fs.existsSync(HWID_FILE)) {
    try { return fs.readFileSync(HWID_FILE, "utf8"); } catch {}
  }

  // HWID aman: platform + arch + cpu model (tidak menggunakan serial)
  const cpuModel = (os.cpus() && os.cpus()[0] && os.cpus()[0].model) ? os.cpus()[0].model : "unknown-cpu";
  const raw = `${os.platform()}|${os.arch()}|${cpuModel}`;
  const hwid = crypto.createHash("sha256").update(raw).digest("hex");

  try { fs.writeFileSync(HWID_FILE, hwid, { encoding: "utf8", mode: 0o600 }); } catch {}
  return hwid;
}

function encryptData(obj) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", AES_KEY, iv);
  let encrypted = cipher.update(JSON.stringify(obj), "utf8", "base64");
  encrypted += cipher.final("base64");
  return iv.toString("base64") + ":" + encrypted;
}

function decryptData(str) {
  try {
    const [ivb64, enc] = str.split(":");
    if (!ivb64 || !enc) throw new Error("invalid");
    const iv = Buffer.from(ivb64, "base64");
    const decipher = crypto.createDecipheriv("aes-256-cbc", AES_KEY, iv);
    let dec = decipher.update(enc, "base64", "utf8");
    dec += decipher.final("utf8");
    return JSON.parse(dec);
  } catch (e) {
    throw new Error("Failed decrypt");
  }
}

function loadLicense() {
  if (!fs.existsSync(LICENSE_FILE)) {
    // Hilang = dianggap sudah dipakai / banned permanen
    return { used: false, banned: true, expired: 0 };
  }
  try {
    const blob = fs.readFileSync(LICENSE_FILE, "utf8");
    const data = decryptData(blob);
    // basic validation
    if (!data || typeof data !== "object") throw new Error("bad");
    return data;
  } catch (e) {
    // Jika file korup / dekrip gagal -> treat as banned
    return { used: true, banned: true, expired: 0 };
  }
}

function saveLicense(data) {
  try {
    const blob = encryptData(data);
    fs.writeFileSync(LICENSE_FILE, blob, { encoding: "utf8", mode: 0o600 });
  } catch (e) {
    // ignore write error (but akan gagal safe)
  }
}

async function askPassword() {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise(resolve => rl.question("Masukkan Password: ", resolve));
  rl.close();
  return (answer || "").trim();
}

async function verifyPassword() {
  const hwid = getHWID();
  let lic = loadLicense();
  const input = await askPassword();

  // Admin bypass selalu jalan
  if (input === "admin-drx") {
    console.log("✔ Admin login sukses (permanent)");
    return true;
  }

  // Trial logic
  if (input === "trial-3h") {
    // Jika license file hilang / flagged banned -> tolak
    if (lic.banned) {
      console.log("❌ Trial sudah pernah digunakan di komputer ini / file lisensi hilang. Tidak bisa digunakan lagi.");
      return false;
    }

    // Jika belum pernah dipakai => aktifkan trial 3 hari
    if (!lic.used) {
      const now = Date.now();
      const expires = now + 3 * 24 * 60 * 60 * 1000;
      lic = { used: true, hwid, expired: expires, banned: false, type: "trial" };
      saveLicense(lic);
      console.log("✔ Trial 3 hari aktif pada komputer ini.");
      return true;
    }

    // Jika sudah pernah dipakai dan belum expired => izinkan sampai expiry
    if (lic.used && !lic.banned) {
      if (lic.hwid !== hwid) {
        // HWID mismatch => tolak (mencegah pindah lisensi)
        console.log("❌ Trial tidak tersedia di perangkat ini (HWID mismatch).");
        return false;
      }
      if (Date.now() <= lic.expired) {
        const remainingMs = lic.expired - Date.now();
        const remainingHours = Math.ceil(remainingMs / (1000 * 60 * 60));
        console.log(`✔ Trial masih aktif (${remainingHours} jam tersisa).`);
        return true;
      } else {
        // expired -> langsung ban permanen pada mesin ini
        lic.banned = true;
        saveLicense(lic);
        console.log("❌ Trial telah kedaluwarsa. Trial tidak bisa digunakan lagi di komputer ini.");
        return false;
      }
    }
  }

  console.log("❌ Password salah!");
  return false;
}

async function terminalBanner() {
  console.clear();
  console.log(
    "\x1b[34m╔══════════════════════════════════╗\x1b[0m\n" +
    "\x1b[34m║\x1b[0m  \x1b[36m█   █ █ █ █▀█   █ █▄ ▄█ ▀█\x1b[0m  \x1b[34m║\x1b[0m\n" +
    "\x1b[34m║\x1b[0m  \x1b[36m█ █ █ █▀█ █ █   █ █ █ █  █\x1b[0m  \x1b[34m║\x1b[0m\n" +
    "\x1b[34m║
    "\x1b[34m╠══════════════════════════════════╣\x1b[0m\n" +
    "\x1b[34m║\x1b[35m    OrangeCarrier - LIVE CALL MONITOR   \x1b[34m║\x1b[0m\n" +
    "\x1b[34m╠══════════════════════════════════╣\x1b[0m\n" +
    "\x1b[34m║\x1b[33m     - CREATED DRIXALEXA -        \x1b[34m║\x1b[0m\n" +
    "\x1b[34m╚══════════════════════════════════╝\x1b[0m"
  );
}

function getCountryNameByPrefix(number) {
  const prefix = extractPrefix(number);
  if (!prefix) return "Unknown";

  const iso = COUNTRY_PREFIX[prefix];   // KH, IL, ID, dll
  if (!iso) return "Unknown";

  // country.json: { "KH": "Cambodia", "IL": "Israel", ... }
  return COUNTRY_CODES[iso] || "Unknown";
}
function extractPrefix(number) {
  number = String(number);

  // Coba 4 digit → 3 → 2 → 1
  for (let len = 4; len >= 1; len--) {
    const prefix = number.slice(0, len);
    if (COUNTRY_PREFIX[prefix]) {
      return prefix;
    }
  }

  return null;
}
function getFlagByPrefix(number) {
  const prefix = extractPrefix(number);
  if (!prefix) return "🏳"; // default

  // negara.json: { "855": "KH", "972": "IL", ... }
  const iso = COUNTRY_PREFIX[prefix]; // KH, ID, IL, dsb
  if (!iso) return "🏳";

  return String.fromCodePoint(
    ...iso.split("").map(c => 0x1F1E6 + c.charCodeAt(0) - 65)
  );
}

function maskNumber(number) {
  number = String(number);

  let prefix = extractPrefix(number);
  if (!prefix) {
    // fallback kalau prefix tidak ditemukan
    prefix = number.slice(0, 3);
  }

  const rest = number.slice(prefix.length);

  // Jika subscriber digit kurang dari 6, tidak aman untuk masking
  if (rest.length < 6) {
    return number;
  }

  const first3 = rest.slice(0, 3);      // 3 digit awal subscriber
  const fixed3 = "DRX";                 // kode tetap
  const last3 = rest.slice(-3);         // 3 digit akhir subscriber

  return prefix + first3 + fixed3 + last3;
}
function findChromiumPath() {
  // Prioritas: chromium sistem yang pasti jalan di container
  const systemChromiumPaths = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
    "/usr/local/bin/chromium",
    "/opt/chromium/chrome",
    "/opt/google/chrome/chrome",
  ];

  for (const p of systemChromiumPaths) {
    if (fs.existsSync(p)) {
      console.log("[AUTO-DETECT] Using system Chromium:", p);
      return p;
    }
  }

  console.warn("[AUTO-DETECT] No system Chromium found. Puppeteer bundled Chromium will be used (may fail).");
  return null; // Puppeteer akan fallback ke Chromium bawaan
}
async function loginWithPuppeteer(email, password) {
  console.log(`[LOGIN] Logging in as ${email}...`);

  const chromePath = findChromiumPath();
  console.log(`[BROWSER] Using: ${chromePath || "Puppeteer bundled Chrome"}`);

  const launchOptions = {
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-dev-shm-usage',
      '--disable-gpu',
      '--disable-software-rasterizer',
      '--disable-features=IsolateOrigins,site-per-process'
    ]
  };

  if (chromePath) {
    launchOptions.executablePath = chromePath;
  }

  const browser = await puppeteer.launch(launchOptions);

  const page = await browser.newPage();
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

  try {
    await page.goto(LOGIN_URL, { waitUntil: 'networkidle2', timeout: 30000 });

    await page.waitForSelector('input[name="email"]', { timeout: 10000 });
    await page.type('input[name="email"]', email, { delay: 50 });
    await page.type('input[name="password"]', password, { delay: 50 });

    await new Promise(r => setTimeout(r, 2000));

    const submitButton = await page.$('#loginSubmit') ||
      await page.$('button[type="submit"]') ||
      await page.$('button.btn-primary');

    if (submitButton) {
      await Promise.all([
        submitButton.click(),
        page.waitForNavigation({ waitUntil: 'networkidle2', timeout: 60000 })
      ]);
    } else {
      throw new Error('Submit button not found');
    }

    await new Promise(r => setTimeout(r, 3000));

    const url = page.url();
    if (url.includes('login')) {
      throw new Error('Login failed - still on login page');
    }

    console.log(`[LOGIN] Success for ${email}`);

    await page.goto(LIVE_CALLS_URL, { waitUntil: 'networkidle2', timeout: 30000 });
    await page.waitForSelector('#LiveCalls', { timeout: 15000 });

    console.log(`[LOGIN] Live calls page loaded for ${email}`);
    return { browser, page };

  } catch (err) {
    console.error(`[LOGIN] Failed for ${email}: ${err.message}`);
    await browser.close().catch(() => {});
    throw err;
  }
}

async function scrapeLiveCalls(page) {
  try {
    await page.waitForSelector('#LiveCalls', { timeout: 30000 });

    const calls = await page.evaluate(() => {
      const rows = Array.from(document.querySelectorAll('#LiveCalls tr'));
      return rows.map(row => {
        const tds = row.querySelectorAll('td');
        const playBtn = row.querySelector('button[onclick*="Play"]');
        if (!playBtn || tds.length < 5) return null;

        const onclick = playBtn.getAttribute('onclick');
        const match = onclick.match(/Play\(['"]([^'"]+)['"],\s*['"]([^'"]+)['"]\)/);
        if (!match) return null;

        return {
          did: match[1],
          uuid: match[2],
          country: tds[0].innerText.trim(),
          number: tds[1].innerText.trim(),
          cliNumber: tds[2].innerText.trim(),
          audioUrl: `https://www.orangecarrier.com/live/calls/sound?did=${match[1]}&uuid=${match[2]}`
        };
      }).filter(Boolean);
    });

    // Filter yang sudah diproses
    const newCalls = calls.filter(c => !processedCalls.has(c.uuid));

    for (const call of newCalls) {
      console.log(`[NEW CALL] ${call.country} | ${call.number} | CLI: ${call.cliNumber} | UUID: ${call.uuid}`);
    }

    return newCalls;
  } catch (err) {
    console.error('[SCRAPE] Error:', err.message);
    return [];
  }
}
async function downloadAudio(page, audioUrl, filename, retries = 5) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      console.log(`[DOWNLOAD] Attempt ${attempt} for ${filename}...`);

      const cookies = await page.cookies();
      const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');

      const response = await axios.get(audioUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Referer': LIVE_CALLS_URL,
          'Origin': 'https://www.orangecarrier.com',
          'Accept': 'audio/mpeg,*/*',
          'Cookie': cookieString
        },
        responseType: 'arraybuffer',
        timeout: 30000
      });

      fs.writeFileSync(filename, response.data);

      const stats = fs.statSync(filename);
      if (stats.size > 100) {
        console.log(`[DOWNLOAD] Success: ${filename} (${stats.size} bytes)`);
        return true;
      }

      console.log(`[DOWNLOAD] File too small, retrying...`);

    } catch (err) {
      console.error(`[DOWNLOAD] Attempt ${attempt} failed: ${err.message}`);

      if (attempt < retries) {
        try {
          await page.reload({ waitUntil: 'networkidle2' });
        } catch (_) {}
        await new Promise(r => setTimeout(r, 3000));
      }
    }
  }

  return false;
}

async function checkFfmpeg() {
  try {
    await execAsync('ffmpeg -version');
    return true;
  } catch {
    return false;
  }
}

async function convertToMp4(inputFile, outputFile) {
  try {
    await execAsync(
      `ffmpeg -y -loop 1 -i phone.png -i "${inputFile}" ` +
      `-filter_complex "scale=360:360, pad=360:360:(ow-iw)/2:(oh-ih)/2" ` +
      `-c:v libx264 -tune stillimage -c:a aac -b:a 192k -shortest -pix_fmt yuv420p "${outputFile}"`
    );
    console.log(`[CONVERT] Success: ${outputFile}`);
    return true;
  } catch (err) {
    console.error(`[CONVERT] Failed: ${err.message}`);
    return false;
  }
}

async function processCall(bot, page, call, hasFfmpeg) {
  const { uuid, country, number, cliNumber, audioUrl } = call;
  processedCalls.add(uuid);

  const flag = getFlagByPrefix(number);
  const countryName = getCountryNameByPrefix(number);
  const maskedNum = maskNumber(number);
  const detectionTime = new Date().toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' });

  const preMessage = await bot.sendMessage(
    CONFIG.CHAT_ID,
    `${flag} ${countryName} ${maskedNum}\n⏳ Audio sedang diproses...`
  );

  await new Promise(r => setTimeout(r, 14000));

  const tempMp3 = `temp_audio_${Date.now()}.mp3`;
  const tempMp4 = tempMp3.replace('.mp3', '.mp4');

  const caption = `
✨ <b>New Call Activity Detected</b> ✨

${flag} <b>Country:</b> ${countryName}
☎️ <b>Number:</b> ${maskedNum}
📞 <b>CLI:</b> ${cliNumber}
⏰ <b>Time:</b> ${detectionTime}
`;

  try {
    const downloaded = await downloadAudio(page, audioUrl, tempMp3);

    await bot.deleteMessage(CONFIG.CHAT_ID, preMessage.message_id).catch(() => {});

    if (downloaded) {
      if (hasFfmpeg) {
        const converted = await convertToMp4(tempMp3, tempMp4);

        if (converted && fs.existsSync(tempMp4)) {
          await bot.sendVideo(CONFIG.CHAT_ID, tempMp4, {
            caption,
            parse_mode: 'HTML'
          });
          console.log(`[SENT] Video for ${uuid} sent to Telegram`);
        } else {
          await bot.sendAudio(CONFIG.CHAT_ID, tempMp3, {
            caption,
            parse_mode: 'HTML'
          });
          console.log(`[SENT] Audio for ${uuid} sent to Telegram (ffmpeg failed)`);
        }
      } else {
        await bot.sendAudio(CONFIG.CHAT_ID, tempMp3, {
          caption,
          parse_mode: 'HTML'
        });
        console.log(`[SENT] Audio for ${uuid} sent to Telegram`);
      }
    } else {
      await bot.sendMessage(
        CONFIG.CHAT_ID,
        `${caption}\n\n⚠️ Audio download failed`,
        { parse_mode: 'HTML' }
      );
    }
  } catch (err) {
    console.error(`[PROCESS] Error: ${err.message}`);
    await bot.deleteMessage(CONFIG.CHAT_ID, preMessage.message_id).catch(() => {});
    await bot.sendMessage(
      CONFIG.CHAT_ID,
      `${caption}\n\n⚠️ Error: ${err.message}`,
      { parse_mode: 'HTML' }
    ).catch(() => {});
  } finally {
    try { if (fs.existsSync(tempMp3)) fs.unlinkSync(tempMp3); } catch (_) {}
    try { if (fs.existsSync(tempMp4)) fs.unlinkSync(tempMp4); } catch (_) {}
  }
}

async function monitorAccount(bot, account, hasFfmpeg) {
  const { email, password } = account;
  let browser, page;

  while (true) {
    try {
      if (!browser || !page) {
        const session = await loginWithPuppeteer(email, password);
        browser = session.browser;
        page = session.page;
      }

      const calls = await scrapeLiveCalls(page);

      for (const call of calls) {
        processCall(bot, page, call, hasFfmpeg).catch(err => {
          console.error(`[PROCESS] Error for ${call.uuid}: ${err.message}`);
        });
      }

      await page.reload({ waitUntil: 'networkidle2' }).catch(() => {});

    } catch (err) {
      console.error(`[MONITOR] Error for ${email}: ${err.message}`);

      if (browser) {
        await browser.close().catch(() => {});
        browser = null;
        page = null;
      }

      await bot.sendMessage(
        CONFIG.LOG_CHAT_ID,
        `🚨 *Worker Error* for \`${email}\`:\n\`${err.message}\``,
        { parse_mode: 'HTML' }
      ).catch(() => {});

      await new Promise(r => setTimeout(r, 30000));
    }

    await new Promise(r => setTimeout(r, 5000));
  }
}

async function main() {
  // cek lisensi dulu
  const ok = await verifyPassword();
  if (!ok) {
    console.log("Program dihentikan oleh sistem lisensi.");
    process.exit(0);
  }

  await terminalBanner();
  console.log("=== OrangeCarrier Live Call Monitor ===\n");
  const hasFfmpeg = await checkFfmpeg();
  console.log(`[SYSTEM] FFmpeg: ${hasFfmpeg ? 'Available ✓' : 'Not found (will send audio only)'}`);

  const bot = new TelegramBot(CONFIG.BOT_TOKEN, { polling: true });

  bot.onText(/\/start/, (msg) => {
    bot.sendMessage(msg.chat.id, "🔥 Live Call Monitor is running...\n\n📞 Monitoring for incoming calls\n🎵 Audio will be sent automatically");
  });

  bot.onText(/\/status/, async (msg) => {
    await bot.sendMessage(
      msg.chat.id,
      `📊 <b>Status</b>\n\nAccounts monitored: ${CONFIG.ACCOUNTS.length}\nProcessed calls: ${processedCalls.size}\nFFmpeg: ${hasFfmpeg ? '✓' : '✗'}`,
      { parse_mode: 'HTML' }
    );
  });

  await bot.sendMessage(CONFIG.LOG_CHAT_ID, `✅ Live Call Monitor Started\n\n📞 Monitoring for incoming calls...\n🎬 FFmpeg: ${hasFfmpeg ? 'Available' : 'Not found'}`, { parse_mode: 'Markdown' });

  for (const acc of CONFIG.ACCOUNTS) {
    if (acc.email.includes('example.com')) continue;
    monitorAccount(bot, acc, hasFfmpeg).catch(console.error);
  }

  console.log("[READY] Bot is now monitoring live calls");
}

main().catch(console.error);
