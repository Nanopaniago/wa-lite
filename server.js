import express from 'express';
import pino from 'pino';
import QRCode from 'qrcode';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import makeWASocket, {
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
} from '@whiskeysockets/baileys';

// ---------- Config ----------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
const AUTH_DIR = path.join(DATA_DIR, 'auth');
const STORE_FILE = path.join(DATA_DIR, 'store.json');
fs.mkdirSync(DATA_DIR, { recursive: true });

const env = process.env;
const PORT = Number(env.PORT || 3100);
const HOST = env.HOST || '0.0.0.0';
const API_TOKEN = env.API_TOKEN || '';
const WEBHOOK_URL = env.N8N_WEBHOOK_URL || '';
const WEBHOOK_SECRET = env.WEBHOOK_SECRET || '';
const WEBHOOK_FROM_ME = env.WEBHOOK_FROM_ME === 'true';
const WEBHOOK_GROUPS = env.WEBHOOK_GROUPS !== 'false';
const MAX_CHATS = Number(env.MAX_CHATS || 100);
const MAX_MSGS = Number(env.MAX_MSGS_PER_CHAT || 150);

if (!API_TOKEN || API_TOKEN.length < 12) {
  console.error('Defina um API_TOKEN com pelo menos 12 caracteres no .env.');
  process.exit(1);
}

const log = pino({ level: env.LOG_LEVEL || 'silent' });
const now = () => Math.floor(Date.now() / 1000);

// ---------- Armazenamento leve (memória + JSON, com limites) ----------
const chats = new Map();    // jid -> { jid, name, last, ts, unread }
const messages = new Map(); // jid -> [{ id, fromMe, text, type, ts, name, sender }]

try {
  const saved = JSON.parse(fs.readFileSync(STORE_FILE, 'utf8'));
  for (const c of saved.chats || []) chats.set(c.jid, c);
  for (const [jid, arr] of Object.entries(saved.messages || {})) messages.set(jid, arr);
} catch {}

const snapshot = () => JSON.stringify({ chats: [...chats.values()], messages: Object.fromEntries(messages) });
let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => {
    saveTimer = null;
    // escreve num ficheiro temporário e troca, para não corromper com um corte de energia
    const tmp = STORE_FILE + '.tmp';
    fs.writeFile(tmp, snapshot(), (err) => { if (!err) fs.rename(tmp, STORE_FILE, () => {}); });
  }, 5000);
}
function saveNow() {
  try { fs.writeFileSync(STORE_FILE, snapshot()); } catch {}
}

function trimStore() {
  if (chats.size <= MAX_CHATS) return;
  const sorted = [...chats.values()].sort((a, b) => b.ts - a.ts);
  for (const c of sorted.slice(MAX_CHATS)) { chats.delete(c.jid); messages.delete(c.jid); }
}

function ensureChat(jid) {
  let chat = chats.get(jid);
  if (!chat) {
    chat = { jid, name: jid.split('@')[0], last: '', ts: now(), unread: 0 };
    chats.set(jid, chat);
    if (jid.endsWith('@g.us')) resolveGroupName(jid);
  }
  return chat;
}

function storeMessage(jid, entry, pushName) {
  const arr = messages.get(jid) || [];
  if (arr.some((x) => x.id === entry.id)) return null; // duplicado
  const chat = ensureChat(jid);
  if (pushName && !entry.fromMe && !jid.endsWith('@g.us')) chat.name = pushName;
  chat.last = (entry.fromMe ? 'Você: ' : '') + entry.text.slice(0, 80);
  chat.ts = entry.ts;
  if (!entry.fromMe) chat.unread = (chat.unread || 0) + 1;
  arr.push(entry);
  if (arr.length > MAX_MSGS) arr.splice(0, arr.length - MAX_MSGS);
  messages.set(jid, arr);
  trimStore();
  scheduleSave();
  return chat;
}

// ---------- Eventos em tempo real (SSE) ----------
const clients = new Set();
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(payload);
}

// ---------- WhatsApp ----------
let sock = null;
let retries = 0;
const wa = { status: 'starting', qr: null, me: null, since: null };
const setStatus = (patch) => { Object.assign(wa, patch); broadcast('status', wa); };

const groupNames = new Map();
async function resolveGroupName(jid) {
  if (groupNames.has(jid) || !sock || wa.status !== 'connected') return;
  groupNames.set(jid, null);
  try {
    const meta = await sock.groupMetadata(jid);
    if (meta?.subject) {
      groupNames.set(jid, meta.subject);
      const chat = chats.get(jid);
      if (chat) { chat.name = meta.subject; scheduleSave(); broadcast('chat', chat); }
    }
  } catch { groupNames.delete(jid); }
}

function extractText(m) {
  let msg = m.message || {};
  for (let i = 0; i < 3; i++) {
    const inner = msg.ephemeralMessage?.message || msg.viewOnceMessage?.message
      || msg.viewOnceMessageV2?.message || msg.documentWithCaptionMessage?.message || msg.editedMessage?.message;
    if (!inner) break;
    msg = inner;
  }
  if (msg.conversation) return { text: msg.conversation, type: 'text' };
  if (msg.extendedTextMessage?.text) return { text: msg.extendedTextMessage.text, type: 'text' };
  if (msg.imageMessage) return { text: msg.imageMessage.caption || '📷 Imagem', type: 'image' };
  if (msg.videoMessage) return { text: msg.videoMessage.caption || '🎬 Vídeo', type: 'video' };
  if (msg.audioMessage) return { text: msg.audioMessage.ptt ? '🎙 Mensagem de voz' : '🎵 Áudio', type: 'audio' };
  if (msg.documentMessage) return { text: `📄 ${msg.documentMessage.fileName || 'Documento'}`, type: 'document' };
  if (msg.stickerMessage) return { text: 'Sticker', type: 'sticker' };
  if (msg.locationMessage) return { text: '📍 Localização', type: 'location' };
  if (msg.contactMessage) return { text: `👤 ${msg.contactMessage.displayName || 'Contacto'}`, type: 'contact' };
  if (msg.buttonsResponseMessage) return { text: msg.buttonsResponseMessage.selectedDisplayText || '', type: 'text' };
  if (msg.listResponseMessage) return { text: msg.listResponseMessage.title || '', type: 'text' };
  return null;
}

async function fireWebhook(payload, attempt = 1) {
  if (!WEBHOOK_URL) return;
  try {
    const r = await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(WEBHOOK_SECRET ? { 'X-Webhook-Secret': WEBHOOK_SECRET } : {}) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
  } catch (e) {
    if (attempt < 3) return setTimeout(() => fireWebhook(payload, attempt + 1), attempt * 3000);
    console.error('Webhook n8n falhou:', e.message);
  }
}

async function startSock() {
  const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
  const { version } = await fetchLatestBaileysVersion().catch(() => ({ version: undefined }));

  sock = makeWASocket({
    version,
    auth: state,
    logger: log,
    browser: ['WA Lite', 'Chrome', '2.0.0'],
    syncFullHistory: false,
    markOnlineOnConnect: false,
    generateHighQualityLinkPreview: false,
    shouldSyncHistoryMessage: () => false,
  });

  sock.ev.on('creds.update', saveCreds);

  sock.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
    if (qr) setStatus({ status: 'qr', qr: await QRCode.toDataURL(qr, { margin: 1, width: 320 }) });

    if (connection === 'open') {
      retries = 0;
      setStatus({ status: 'connected', qr: null, me: sock.user?.id || null, since: now() });
      console.log('WhatsApp conectado:', wa.me);
      for (const jid of chats.keys()) if (jid.endsWith('@g.us')) resolveGroupName(jid);
    }

    if (connection === 'close') {
      const code = lastDisconnect?.error?.output?.statusCode;
      setStatus({ status: 'disconnected', qr: null, me: null, since: null });
      if (code === DisconnectReason.loggedOut) {
        fs.rmSync(AUTH_DIR, { recursive: true, force: true });
        console.log('Sessão terminada no telemóvel. A gerar novo QR...');
        retries = 0;
      }
      // espera crescente: 2s, 4s, 8s... até 60s, para não martelar a rede
      const wait = Math.min(60000, 2000 * 2 ** retries++);
      setTimeout(() => startSock().catch(console.error), wait);
    }
  });

  sock.ev.on('messages.upsert', ({ messages: msgs, type }) => {
    for (const m of msgs) {
      const jid = m.key.remoteJid;
      if (!jid || jid === 'status@broadcast' || jid.endsWith('@newsletter')) continue;
      const fromMe = !!m.key.fromMe;
      const ts = Number(m.messageTimestamp || now());
      // 'append' traz mensagens enviadas pelo telemóvel; ignora histórico antigo
      if (type !== 'notify' && !(fromMe && now() - ts < 120)) continue;
      const ex = extractText(m);
      if (!ex) continue;
      const isGroup = jid.endsWith('@g.us');
      const sender = m.key.participant || (fromMe ? wa.me : jid);
      const entry = { id: m.key.id, fromMe, text: ex.text, type: ex.type, ts, name: m.pushName || '', sender };
      const chat = storeMessage(jid, entry, m.pushName);
      if (!chat) continue;
      broadcast('message', { jid, entry, chat });

      if ((!fromMe || WEBHOOK_FROM_ME) && (!isGroup || WEBHOOK_GROUPS)) {
        fireWebhook({
          event: 'message', id: entry.id, chat: jid, chatName: chat.name, from: sender,
          name: entry.name, fromMe, text: entry.text, type: ex.type, timestamp: ts, isGroup,
        });
      }
    }
  });
}

function toJid(to) {
  to = String(to).trim();
  if (to.includes('@')) return to;
  const digits = to.replace(/\D/g, '');
  if (digits.length < 8) throw new Error('Número inválido: use o formato internacional, ex. 351912345678');
  return `${digits}@s.whatsapp.net`;
}

// ---------- HTTP ----------
const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));
app.use((_req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' });
  next();
});

const tokenBuf = Buffer.from(API_TOKEN);
function auth(req, res, next) {
  const h = req.headers.authorization || '';
  const given = Buffer.from(h.startsWith('Bearer ') ? h.slice(7) : String(req.query.token || ''));
  if (given.length !== tokenBuf.length || !crypto.timingSafeEqual(given, tokenBuf)) {
    return res.status(401).json({ error: 'Token inválido' });
  }
  next();
}

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

// Sem token: só para systemd / monitorização
app.get('/health', (_req, res) => res.json({ ok: true, status: wa.status }));

app.get('/api/events', auth, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  res.write(`event: status\ndata: ${JSON.stringify(wa)}\n\n`);
  clients.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(ping); clients.delete(res); });
});

app.get('/api/status', auth, (_req, res) => {
  const { qr, ...rest } = wa;
  res.json({ ...rest, chats: chats.size, memoryMB: Math.round(process.memoryUsage().rss / 1048576) });
});

app.get('/api/chats', auth, (_req, res) => res.json([...chats.values()].sort((a, b) => b.ts - a.ts)));

app.get('/api/messages/:jid', auth, (req, res) => res.json(messages.get(req.params.jid) || []));

// Marca a conversa como lida (na UI e no telemóvel)
app.post('/api/read/:jid', auth, async (req, res) => {
  const jid = req.params.jid;
  const chat = chats.get(jid);
  if (!chat) return res.json({ ok: true });
  const pending = chat.unread || 0;
  chat.unread = 0;
  scheduleSave();
  broadcast('chat', chat);
  if (pending && wa.status === 'connected') {
    const keys = (messages.get(jid) || []).filter((m) => !m.fromMe).slice(-pending)
      .map((m) => ({ remoteJid: jid, id: m.id, participant: jid.endsWith('@g.us') ? m.sender : undefined }));
    sock.readMessages(keys).catch(() => {});
  }
  res.json({ ok: true });
});

// Enviar mensagem (UI e n8n). Corpo: { to, text } ou { to, image|document: url, caption, fileName }
app.post('/api/send', auth, async (req, res) => {
  const { to, text, image, document, caption, fileName } = req.body || {};
  if (!to || !(text || image || document)) return res.status(400).json({ error: 'Indique "to" e "text" (ou "image"/"document" com URL)' });
  if (wa.status !== 'connected') return res.status(503).json({ error: 'WhatsApp não está conectado' });
  try {
    const jid = toJid(to);
    let content, label, type = 'text';
    if (image) { content = { image: { url: image }, caption }; label = caption || '📷 Imagem'; type = 'image'; }
    else if (document) {
      content = { document: { url: document }, fileName: fileName || 'documento', mimetype: 'application/octet-stream', caption };
      label = `📄 ${fileName || 'Documento'}`; type = 'document';
    } else { content = { text: String(text) }; label = String(text); }

    const sent = await sock.sendMessage(jid, content);
    const entry = { id: sent.key.id, fromMe: true, text: label, type, ts: now(), name: '', sender: wa.me };
    const chat = storeMessage(jid, entry);
    if (chat) broadcast('message', { jid, entry, chat });
    res.json({ ok: true, id: sent.key.id, to: jid });
  } catch (e) {
    res.status(e.message.startsWith('Número') ? 400 : 500).json({ error: e.message });
  }
});

app.post('/api/logout', auth, async (_req, res) => {
  try { await sock?.logout(); } catch {}
  res.json({ ok: true });
});

app.listen(PORT, HOST, () => console.log(`WA Lite em http://${HOST}:${PORT}`));
startSock().catch((e) => { console.error(e); process.exit(1); });

for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => { saveNow(); process.exit(0); });
