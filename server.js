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
  downloadMediaMessage,
  generateWAMessageFromContent,
  proto,
} from '@whiskeysockets/baileys';

// ---------- Config ----------
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_DIR = path.join(__dirname, 'data');
const SESS_DIR = path.join(DATA_DIR, 'sessions');
const REGISTRY = path.join(DATA_DIR, 'sessions.json');
fs.mkdirSync(SESS_DIR, { recursive: true });

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
const MAX_SESSIONS = Number(env.MAX_SESSIONS || 5);
// Anexos recebidos (PDF, imagens) guardados por pouco tempo para o n8n os ir buscar
const MEDIA_FORWARD = env.MEDIA_FORWARD === 'true';
const MEDIA_MAX_MB = Number(env.MEDIA_MAX_MB || 10);
const MEDIA_TTL_MIN = Number(env.MEDIA_TTL_MIN || 60);
const MEDIA_DIR = path.join(DATA_DIR, 'media');
const MEDIA_TYPES = { 'application/pdf': 'pdf', 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document': 'docx' };
if (MEDIA_FORWARD) fs.mkdirSync(MEDIA_DIR, { recursive: true });
// Botões de link (cta_url). WA_BUTTONS=false envia o link no texto (mais compatível).
const WA_BUTTONS = env.WA_BUTTONS !== 'false';

if (!API_TOKEN || API_TOKEN.length < 12) {
  console.error('Defina um API_TOKEN com pelo menos 12 caracteres no .env.');
  process.exit(1);
}

const log = pino({ level: env.LOG_LEVEL || 'silent' });
const now = () => Math.floor(Date.now() / 1000);

// ---------- Eventos em tempo real (SSE) ----------
const clients = new Set();
function broadcast(event, data) {
  const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
  for (const res of clients) res.write(payload);
}

// ---------- Webhook ----------
async function fireWebhook(url, payload, attempt = 1) {
  if (!url) return;
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(WEBHOOK_SECRET ? { 'X-Webhook-Secret': WEBHOOK_SECRET } : {}) },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10000),
    });
    if (!r.ok) throw new Error('HTTP ' + r.status);
  } catch (e) {
    if (attempt < 3) return setTimeout(() => fireWebhook(url, payload, attempt + 1), attempt * 3000);
    console.error(`Webhook falhou (${payload.session}):`, e.message);
  }
}

// Descarrega um anexo (documento ou imagem) e devolve { url, mimetype, fileName, size } ou null.
async function saveMedia(session, m, type) {
  if (!MEDIA_FORWARD || !['document', 'image'].includes(type)) return null;
  let msg = m.message || {};
  msg = msg.ephemeralMessage?.message || msg.viewOnceMessage?.message || msg.viewOnceMessageV2?.message
    || msg.documentWithCaptionMessage?.message || msg;
  const node = msg.documentMessage || msg.imageMessage;
  if (!node) return null;
  const mimetype = String(node.mimetype || '').split(';')[0];
  const ext = MEDIA_TYPES[mimetype];
  const size = Number(node.fileLength || 0);
  if (!ext) return { skipped: 'tipo não suportado', mimetype };
  if (size > MEDIA_MAX_MB * 1048576) return { skipped: `acima de ${MEDIA_MAX_MB} MB`, mimetype, size };
  try {
    const buf = await downloadMediaMessage(m, 'buffer', {}, { logger: log, reuploadRequest: session.sock.updateMediaMessage });
    if (buf.length > MEDIA_MAX_MB * 1048576) return { skipped: `acima de ${MEDIA_MAX_MB} MB`, mimetype, size: buf.length };
    const file = `${session.id}-${crypto.randomBytes(12).toString('hex')}.${ext}`;
    fs.writeFileSync(path.join(MEDIA_DIR, file), buf);
    return { url: `/api/media/${file}`, mimetype, fileName: node.fileName || `anexo.${ext}`, size: buf.length };
  } catch (e) {
    console.error(`Falha a descarregar anexo (${session.id}):`, e.message);
    return { skipped: 'falha no download', mimetype };
  }
}

// apaga anexos com mais de MEDIA_TTL_MIN minutos
if (MEDIA_FORWARD) setInterval(() => {
  const limit = Date.now() - MEDIA_TTL_MIN * 60000;
  for (const f of fs.readdirSync(MEDIA_DIR)) {
    const p = path.join(MEDIA_DIR, f);
    try { if (fs.statSync(p).mtimeMs < limit) fs.unlinkSync(p); } catch {}
  }
}, 5 * 60000).unref();

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

let waVersion = null;
async function getVersion() {
  if (waVersion) return waVersion;
  const r = await fetchLatestBaileysVersion().catch(() => ({}));
  if (r.version) waVersion = r.version;
  return waVersion || undefined;
}

// ---------- Sessão: um número de WhatsApp por cliente ----------
class Session {
  constructor(meta) {
    this.meta = meta; // { id, name, webhook, createdAt }
    this.dir = path.join(SESS_DIR, meta.id);
    this.authDir = path.join(this.dir, 'auth');
    this.storeFile = path.join(this.dir, 'store.json');
    fs.mkdirSync(this.dir, { recursive: true });
    this.chats = new Map();
    this.messages = new Map();
    this.groupNames = new Map();
    this.sock = null;
    this.status = 'idle'; // idle | starting | qr | connected | reconnecting
    this.qr = null; this.me = null; this.since = null;
    this.retries = 0; this.stopped = true; this.saveTimer = null;
    try {
      const saved = JSON.parse(fs.readFileSync(this.storeFile, 'utf8'));
      for (const c of saved.chats || []) this.chats.set(c.jid, c);
      for (const [jid, arr] of Object.entries(saved.messages || {})) this.messages.set(jid, arr);
    } catch {}
  }

  get id() { return this.meta.id; }
  get paired() { return fs.existsSync(path.join(this.authDir, 'creds.json')); }

  info() {
    let unread = 0;
    for (const c of this.chats.values()) unread += c.unread || 0;
    return {
      id: this.id, name: this.meta.name, webhook: this.meta.webhook || '', status: this.status,
      qr: this.qr, me: this.me, since: this.since, chats: this.chats.size, unread, createdAt: this.meta.createdAt,
    };
  }
  set(patch) { Object.assign(this, patch); broadcast('session', this.info()); }

  snapshot() { return JSON.stringify({ chats: [...this.chats.values()], messages: Object.fromEntries(this.messages) }); }
  scheduleSave() {
    if (this.saveTimer) return;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      const tmp = this.storeFile + '.tmp';
      fs.writeFile(tmp, this.snapshot(), (err) => { if (!err) fs.rename(tmp, this.storeFile, () => {}); });
    }, 5000);
  }
  saveNow() { try { fs.writeFileSync(this.storeFile, this.snapshot()); } catch {} }

  ensureChat(jid) {
    let chat = this.chats.get(jid);
    if (!chat) {
      chat = { jid, name: jid.split('@')[0], last: '', ts: now(), unread: 0 };
      this.chats.set(jid, chat);
      if (jid.endsWith('@g.us')) this.resolveGroupName(jid);
    }
    return chat;
  }

  storeMessage(jid, entry, pushName) {
    const arr = this.messages.get(jid) || [];
    if (arr.some((x) => x.id === entry.id)) return null;
    const chat = this.ensureChat(jid);
    if (pushName && !entry.fromMe && !jid.endsWith('@g.us')) chat.name = pushName;
    chat.last = (entry.fromMe ? 'Você: ' : '') + entry.text.slice(0, 80);
    chat.ts = entry.ts;
    if (!entry.fromMe) chat.unread = (chat.unread || 0) + 1;
    arr.push(entry);
    if (arr.length > MAX_MSGS) arr.splice(0, arr.length - MAX_MSGS);
    this.messages.set(jid, arr);
    if (this.chats.size > MAX_CHATS) {
      const old = [...this.chats.values()].sort((a, b) => b.ts - a.ts).slice(MAX_CHATS);
      for (const c of old) { this.chats.delete(c.jid); this.messages.delete(c.jid); }
    }
    this.scheduleSave();
    return chat;
  }

  async resolveGroupName(jid) {
    if (this.groupNames.has(jid) || !this.sock || this.status !== 'connected') return;
    this.groupNames.set(jid, null);
    try {
      const meta = await this.sock.groupMetadata(jid);
      if (meta?.subject) {
        this.groupNames.set(jid, meta.subject);
        const chat = this.chats.get(jid);
        if (chat) { chat.name = meta.subject; this.scheduleSave(); broadcast('chat', { session: this.id, chat }); }
      }
    } catch { this.groupNames.delete(jid); }
  }

  async start() {
    if (this.sock) return;
    this.stopped = false;
    this.set({ status: 'starting', qr: null });
    const { state, saveCreds } = await useMultiFileAuthState(this.authDir);
    const sock = makeWASocket({
      version: await getVersion(),
      auth: state,
      logger: log,
      browser: ['WA Lite', 'Chrome', '3.0.0'],
      syncFullHistory: false,
      markOnlineOnConnect: false,
      generateHighQualityLinkPreview: false,
      shouldSyncHistoryMessage: () => false,
    });
    this.sock = sock;
    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async ({ connection, lastDisconnect, qr }) => {
      if (sock !== this.sock) return; // socket antigo
      if (qr) this.set({ status: 'qr', qr: await QRCode.toDataURL(qr, { margin: 1, width: 320 }) });

      if (connection === 'open') {
        this.retries = 0;
        this.set({ status: 'connected', qr: null, me: sock.user?.id || null, since: now() });
        console.log(`[${this.meta.name}] conectado:`, this.me);
        for (const jid of this.chats.keys()) if (jid.endsWith('@g.us')) this.resolveGroupName(jid);
      }

      if (connection === 'close') {
        const code = lastDisconnect?.error?.output?.statusCode;
        this.sock = null;
        if (this.stopped) return this.set({ status: 'idle', qr: null });
        if (code === DisconnectReason.loggedOut) {
          fs.rmSync(this.authDir, { recursive: true, force: true });
          console.log(`[${this.meta.name}] sessão terminada no telemóvel.`);
          return this.set({ status: 'idle', qr: null, me: null, since: null });
        }
        // depois de ler o QR o WhatsApp pede um reinício imediato
        if (code === DisconnectReason.restartRequired) return this.start().catch(console.error);
        // QR expirou sem ser lido: fica parado até o utilizador pedir outro
        if (!state.creds.me) return this.set({ status: 'idle', qr: null });
        const wait = Math.min(60000, 2000 * 2 ** this.retries++);
        this.set({ status: 'reconnecting', qr: null });
        setTimeout(() => { if (!this.stopped) this.start().catch(console.error); }, wait);
      }
    });

    sock.ev.on('messages.upsert', ({ messages: msgs, type }) => {
      for (const m of msgs) {
        const jid = m.key.remoteJid;
        if (!jid || jid === 'status@broadcast' || jid.endsWith('@newsletter')) continue;
        const fromMe = !!m.key.fromMe;
        const ts = Number(m.messageTimestamp || now());
        if (type !== 'notify' && !(fromMe && now() - ts < 120)) continue;
        const ex = extractText(m);
        if (!ex) continue;
        const isGroup = jid.endsWith('@g.us');
        const sender = m.key.participant || (fromMe ? this.me : jid);
        const entry = { id: m.key.id, fromMe, text: ex.text, type: ex.type, ts, name: m.pushName || '', sender };
        const chat = this.storeMessage(jid, entry, m.pushName);
        if (!chat) continue;
        broadcast('message', { session: this.id, jid, entry, chat });

        if ((!fromMe || WEBHOOK_FROM_ME) && (!isGroup || WEBHOOK_GROUPS)) {
          const payload = {
            event: 'message', session: this.id, sessionName: this.meta.name, sessionNumber: num(this.me),
            id: entry.id, chat: jid, chatName: chat.name, from: sender, name: entry.name,
            fromMe, text: entry.text, type: ex.type, timestamp: ts, isGroup,
          };
          const url = this.meta.webhook || WEBHOOK_URL;
          if (!fromMe && !isGroup && MEDIA_FORWARD && ['document', 'image'].includes(ex.type)) {
            saveMedia(this, m, ex.type).then((media) => fireWebhook(url, { ...payload, media }));
          } else {
            fireWebhook(url, payload);
          }
        }
      }
    });
  }

  async stop() {
    this.stopped = true;
    const s = this.sock; this.sock = null;
    try { s?.end(undefined); } catch {}
    this.set({ status: 'idle', qr: null });
  }

  async logout() {
    this.stopped = true;
    const s = this.sock; this.sock = null;
    try { await s?.logout(); } catch {}
    fs.rmSync(this.authDir, { recursive: true, force: true });
    this.set({ status: 'idle', qr: null, me: null, since: null });
  }
}

const num = (jid) => (jid || '').split('@')[0].split(':')[0];

// ---------- Registo de clientes ----------
const sessions = new Map();
const saveRegistry = () => fs.writeFileSync(REGISTRY, JSON.stringify([...sessions.values()].map((s) => s.meta), null, 2));

function slug(name) {
  const base = name.normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 24) || 'cliente';
  let id = base, i = 2;
  while (sessions.has(id)) id = `${base}-${i++}`;
  return id;
}

function migrateV2() {
  // v2 tinha uma única sessão em data/auth e data/store.json
  const oldAuth = path.join(DATA_DIR, 'auth');
  const oldStore = path.join(DATA_DIR, 'store.json');
  if (!fs.existsSync(oldAuth) && !fs.existsSync(oldStore)) return [];
  const meta = { id: 'principal', name: 'Principal', webhook: '', createdAt: now() };
  const dir = path.join(SESS_DIR, meta.id);
  fs.mkdirSync(dir, { recursive: true });
  if (fs.existsSync(oldAuth)) fs.renameSync(oldAuth, path.join(dir, 'auth'));
  if (fs.existsSync(oldStore)) fs.renameSync(oldStore, path.join(dir, 'store.json'));
  console.log('Sessão anterior migrada para o cliente "Principal".');
  return [meta];
}

let registry = [];
try { registry = JSON.parse(fs.readFileSync(REGISTRY, 'utf8')); } catch { registry = migrateV2(); }
for (const meta of registry) sessions.set(meta.id, new Session(meta));
saveRegistry();

function findSession(ref) {
  if (!ref) return sessions.values().next().value || null;
  const r = String(ref).toLowerCase();
  const d = String(ref).replace(/\D/g, '');
  return sessions.get(String(ref)) || [...sessions.values()].find((s) =>
    s.meta.name.toLowerCase() === r || (d.length >= 8 && s.me && num(s.me) === d)) || null;
}

function toJid(to) {
  to = String(to).trim();
  if (to.includes('@')) return to;
  const digits = to.replace(/\D/g, '');
  if (digits.length < 8) throw Object.assign(new Error('Número inválido: use o formato internacional, ex. 351912345678'), { status: 400 });
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
// resolve :sid, ?session= ou body.session
function withSession(req, res, next) {
  const ref = req.params.sid || req.query.session || req.body?.session;
  const s = findSession(ref);
  if (!s) return res.status(404).json({ error: ref ? `Cliente "${ref}" não existe` : 'Ainda não há clientes. Crie um primeiro.' });
  req.sess = s;
  next();
}
const wrap = (fn) => async (req, res) => {
  try { await fn(req, res); } catch (e) { res.status(e.status || 500).json({ error: e.message }); }
};

app.use(express.static(path.join(__dirname, 'public'), { maxAge: '1h' }));

app.get('/health', (_req, res) => res.json({
  ok: true, sessions: [...sessions.values()].map((s) => ({ id: s.id, status: s.status })),
}));

app.get('/api/events', auth, (req, res) => {
  res.set({ 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
  res.flushHeaders();
  res.write(`event: sessions\ndata: ${JSON.stringify([...sessions.values()].map((s) => s.info()))}\n\n`);
  clients.add(res);
  const ping = setInterval(() => res.write(': ping\n\n'), 25000);
  req.on('close', () => { clearInterval(ping); clients.delete(res); });
});

app.get('/api/status', auth, (_req, res) => res.json({
  sessions: [...sessions.values()].map((s) => { const { qr, ...i } = s.info(); return i; }),
  maxSessions: MAX_SESSIONS,
  memoryMB: Math.round(process.memoryUsage().rss / 1048576),
}));

// --- clientes ---
app.get('/api/sessions', auth, (_req, res) => res.json([...sessions.values()].map((s) => s.info())));

app.post('/api/sessions', auth, wrap(async (req, res) => {
  const name = String(req.body?.name || '').trim();
  if (!name) return res.status(400).json({ error: 'Indique o nome do cliente' });
  if (sessions.size >= MAX_SESSIONS) return res.status(400).json({ error: `Limite de ${MAX_SESSIONS} clientes atingido (MAX_SESSIONS no .env)` });
  const webhook = String(req.body?.webhook || '').trim();
  if (webhook && !/^https?:\/\//.test(webhook)) return res.status(400).json({ error: 'O webhook tem de começar por http:// ou https://' });
  const s = new Session({ id: slug(name), name: name.slice(0, 40), webhook, createdAt: now() });
  sessions.set(s.id, s);
  saveRegistry();
  broadcast('session', s.info());
  s.start().catch((e) => console.error(e));
  res.status(201).json(s.info());
}));

app.patch('/api/sessions/:sid', auth, withSession, wrap(async (req, res) => {
  const { name, webhook } = req.body || {};
  if (name !== undefined) {
    if (!String(name).trim()) return res.status(400).json({ error: 'O nome não pode ficar vazio' });
    req.sess.meta.name = String(name).trim().slice(0, 40);
  }
  if (webhook !== undefined) {
    const w = String(webhook).trim();
    if (w && !/^https?:\/\//.test(w)) return res.status(400).json({ error: 'O webhook tem de começar por http:// ou https://' });
    req.sess.meta.webhook = w;
  }
  saveRegistry();
  broadcast('session', req.sess.info());
  res.json(req.sess.info());
}));

app.post('/api/sessions/:sid/start', auth, withSession, wrap(async (req, res) => {
  await req.sess.start();
  res.json(req.sess.info());
}));

app.post('/api/sessions/:sid/logout', auth, withSession, wrap(async (req, res) => {
  await req.sess.logout();
  res.json({ ok: true });
}));

app.delete('/api/sessions/:sid', auth, withSession, wrap(async (req, res) => {
  const s = req.sess;
  await s.logout();
  clearTimeout(s.saveTimer);
  sessions.delete(s.id);
  fs.rmSync(s.dir, { recursive: true, force: true });
  saveRegistry();
  broadcast('session-removed', { id: s.id });
  res.json({ ok: true });
}));

// --- conversas (por cliente; sem :sid usa ?session= ou o primeiro cliente) ---
const listChats = (req, res) => res.json([...req.sess.chats.values()].sort((a, b) => b.ts - a.ts));
const listMsgs = (req, res) => res.json(req.sess.messages.get(req.params.jid) || []);
const markRead = (req, res) => {
  const s = req.sess, jid = req.params.jid, chat = s.chats.get(jid);
  if (!chat) return res.json({ ok: true });
  const pending = chat.unread || 0;
  chat.unread = 0;
  s.scheduleSave();
  broadcast('chat', { session: s.id, chat });
  if (pending && s.status === 'connected') {
    const keys = (s.messages.get(jid) || []).filter((m) => !m.fromMe).slice(-pending)
      .map((m) => ({ remoteJid: jid, id: m.id, participant: jid.endsWith('@g.us') ? m.sender : undefined }));
    s.sock.readMessages(keys).catch(() => {});
  }
  res.json({ ok: true });
};

// ---------- Botões de link ----------
function cleanButtons(list) {
  if (!Array.isArray(list)) return [];
  return list.filter((b) => b && /^https:\/\//.test(String(b.url || '')) && String(b.label || '').trim())
    .slice(0, 3).map((b) => ({ label: String(b.label).trim().slice(0, 20), url: String(b.url) }));
}

// Texto com o link escrito por baixo (quando os botões estão desligados ou falham)
const withLinks = (text, buttons) => [String(text || '').trim(), ...buttons.map((b) => `👉 *${b.label}*\n${b.url}`)]
  .filter(Boolean).join('\n\n');

async function sendButtons(s, jid, text, buttons, footer) {
  const msg = generateWAMessageFromContent(jid, {
    viewOnceMessage: {
      message: {
        messageContextInfo: { deviceListMetadata: {}, deviceListMetadataVersion: 2 },
        interactiveMessage: proto.Message.InteractiveMessage.create({
          body: { text: String(text || '') },
          ...(footer ? { footer: { text: String(footer).slice(0, 60) } } : {}),
          header: { title: '', hasMediaAttachment: false },
          nativeFlowMessage: {
            buttons: buttons.map((b) => ({
              name: 'cta_url',
              buttonParamsJson: JSON.stringify({ display_text: b.label, url: b.url, merchant_url: b.url }),
            })),
            messageParamsJson: '',
          },
        }),
      },
    },
  }, { userJid: s.sock.user?.id });
  await s.sock.relayMessage(jid, msg.message, {
    messageId: msg.key.id,
    additionalNodes: [{ tag: 'biz', attrs: {}, content: [{ tag: 'interactive', attrs: { type: 'native_flow', v: '1' },
      content: [{ tag: 'native_flow', attrs: { v: '9', name: 'mixed' } }] }] }],
  });
  return msg.key;
}

// Corpo: { to, text, buttons?: [{label, url}], footer? } ou { to, image|document: url, caption, fileName }; opcional "session"
const send = wrap(async (req, res) => {
  const s = req.sess;
  const { to, image, document, caption, fileName, footer } = req.body || {};
  let { text } = req.body || {};
  const buttons = cleanButtons(req.body?.buttons);
  if (!text && buttons.length) text = ' ';
  if (!to || !(text || image || document)) return res.status(400).json({ error: 'Indique "to" e "text" (ou "image"/"document" com URL)' });
  if (s.status !== 'connected') return res.status(503).json({ error: `O WhatsApp do cliente "${s.meta.name}" não está conectado` });
  const jid = toJid(to);
  let content, label, type = 'text';
  if (image) { content = { image: { url: image }, caption }; label = caption || '📷 Imagem'; type = 'image'; }
  else if (document) {
    const isPdf = /\.pdf$/i.test(fileName || document);
    content = { document: { url: document }, fileName: fileName || 'documento', mimetype: isPdf ? 'application/pdf' : 'application/octet-stream', caption };
    label = `📄 ${fileName || 'Documento'}`; type = 'document';
  } else if (buttons.length) {
    label = withLinks(text, buttons); type = 'buttons';
    if (WA_BUTTONS) {
      try {
        const key = await sendButtons(s, jid, text, buttons, footer);
        const entry = { id: key.id, fromMe: true, text: label, type, ts: now(), name: '', sender: s.me };
        const chat = s.storeMessage(jid, entry);
        if (chat) broadcast('message', { session: s.id, jid, entry, chat });
        return res.json({ ok: true, id: key.id, to: jid, session: s.id, buttons: true });
      } catch (e) {
        console.error(`Botões falharam (${s.id}), envio o link no texto:`, e.message);
      }
    }
    content = { text: label };
  } else { content = { text: String(text) }; label = String(text); }
  const sent = await s.sock.sendMessage(jid, content);
  const entry = { id: sent.key.id, fromMe: true, text: label, type, ts: now(), name: '', sender: s.me };
  const chat = s.storeMessage(jid, entry);
  if (chat) broadcast('message', { session: s.id, jid, entry, chat });
  res.json({ ok: true, id: sent.key.id, to: jid, session: s.id });
});

for (const base of ['/api/sessions/:sid', '/api']) {
  app.get(`${base}/chats`, auth, withSession, listChats);
  app.get(`${base}/messages/:jid`, auth, withSession, listMsgs);
  app.post(`${base}/read/:jid`, auth, withSession, markRead);
  app.post(`${base}/send`, auth, withSession, send);
}

// anexos recebidos (só com MEDIA_FORWARD=true); nome aleatório, apagados após MEDIA_TTL_MIN
app.get('/api/media/:file', auth, (req, res) => {
  if (!MEDIA_FORWARD || !/^[a-z0-9-]+-[a-f0-9]{24}\.(pdf|jpg|png|webp|docx)$/.test(req.params.file)) {
    return res.status(404).json({ error: 'Anexo não encontrado' });
  }
  const p = path.join(MEDIA_DIR, req.params.file);
  if (!fs.existsSync(p)) return res.status(404).json({ error: 'Anexo expirou ou não existe' });
  res.sendFile(p);
});

// compatibilidade com a v2: desliga o primeiro cliente
app.post('/api/logout', auth, withSession, wrap(async (req, res) => { await req.sess.logout(); res.json({ ok: true }); }));

app.listen(PORT, HOST, () => console.log(`WA Lite em http://${HOST}:${PORT} · ${sessions.size} cliente(s)`));

// arranca só os clientes que já têm sessão ligada; os outros esperam pelo QR
for (const s of sessions.values()) if (s.paired) s.start().catch(console.error);

for (const sig of ['SIGTERM', 'SIGINT']) process.on(sig, () => {
  for (const s of sessions.values()) s.saveNow();
  process.exit(0);
});
