#!/usr/bin/env node
// Servidor MCP do WA Lite (stdio). Corre no computador onde está o Claude e fala com o WA Lite por HTTP.
//   WA_LITE_URL    endereço do WA Lite visto deste computador, ex. http://192.168.1.81:3200
//   WA_LITE_TOKEN  o API_TOKEN do .env do WA Lite
//   WA_LITE_N8N_URL (opcional) endereço do WA Lite visto a partir do n8n, se for diferente
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import crypto from 'node:crypto';

const BASE = (process.env.WA_LITE_URL || 'http://localhost:3100').replace(/\/+$/, '');
const TOKEN = process.env.WA_LITE_TOKEN || '';
const N8N_BASE = (process.env.WA_LITE_N8N_URL || BASE).replace(/\/+$/, '');

if (!TOKEN) {
  console.error('Defina WA_LITE_TOKEN (o API_TOKEN do WA Lite).');
  process.exit(1);
}

// ---------- acesso ao WA Lite ----------
async function wa(path, { method = 'GET', body } = {}) {
  let res;
  try {
    res = await fetch(BASE + path, {
      method,
      headers: { Authorization: `Bearer ${TOKEN}`, 'Content-Type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20000),
    });
  } catch (e) {
    throw new Error(`Não consegui falar com o WA Lite em ${BASE}: ${e.message}. Confirme o endereço e se o serviço está a correr.`);
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `WA Lite respondeu HTTP ${res.status}`);
  return data;
}

const text = (obj) => ({ content: [{ type: 'text', text: typeof obj === 'string' ? obj : JSON.stringify(obj, null, 2) }] });
const fail = (e) => ({ isError: true, content: [{ type: 'text', text: e.message }] });
const run = (fn) => async (args) => { try { return text(await fn(args)); } catch (e) { return fail(e); } };

const digits = (s) => String(s).replace(/\D/g, '');
const asJid = (to) => (String(to).includes('@') ? String(to) : `${digits(to)}@s.whatsapp.net`);
const fmtTime = (ts) => new Date(ts * 1000).toLocaleString('pt-PT', { timeZone: 'Europe/Lisbon' });

// Prefixo da API para um cliente (id ou nome). Sem cliente usa o primeiro.
const base = (session) => (session ? `/api/sessions/${encodeURIComponent(session)}` : '/api');
const sessionArg = z.string().optional().describe('Cliente: id ou nome (ver wa_list_sessions). Vazio usa o primeiro cliente.');

// Resolve "Marta", "+351 912 345 678" ou um jid para o jid da conversa
async function resolveChat(ref, session) {
  if (String(ref).includes('@')) return String(ref);
  const chats = await wa(base(session) + '/chats');
  const q = String(ref).trim().toLowerCase();
  const d = digits(ref);
  const hit = chats.find((c) => c.name.toLowerCase() === q)
    || (d.length >= 8 && chats.find((c) => c.jid.startsWith(d)))
    || chats.find((c) => c.name.toLowerCase().includes(q));
  if (hit) return hit.jid;
  if (d.length >= 8) return `${d}@s.whatsapp.net`;
  throw new Error(`Não encontrei nenhuma conversa que corresponda a "${ref}". Use um número internacional, ex. 351912345678.`);
}

// ---------- servidor ----------
const server = new McpServer({ name: 'wa-lite', version: '2.0.0' });

server.registerTool('wa_list_sessions', {
  title: 'Listar clientes',
  description: 'Lista os clientes (um número de WhatsApp cada) com id, nome, número, estado da ligação, conversas e mensagens por ler. Use o id ou o nome no parâmetro "session" das outras ferramentas.',
  inputSchema: {},
}, run(async () => {
  const st = await wa('/api/status');
  return {
    clientes: st.sessions.map((s) => ({
      id: s.id, nome: s.name, numero: s.me ? '+' + s.me.split('@')[0].split(':')[0] : null,
      estado: s.status, conversas: s.chats, por_ler: s.unread, webhook_proprio: s.webhook || null,
    })),
    limite: st.maxSessions, memoriaMB: st.memoryMB,
  };
}));

server.registerTool('wa_status', {
  title: 'Estado do servidor',
  description: 'Mostra o estado de todos os clientes do WA Lite e a memória usada pelo servidor.',
  inputSchema: {},
}, run(async () => wa('/api/status')));

server.registerTool('wa_list_chats', {
  title: 'Listar conversas',
  description: 'Lista as conversas mais recentes (nome, jid, última mensagem, não lidas). Pode filtrar por nome ou número.',
  inputSchema: {
    session: sessionArg,
    search: z.string().optional().describe('Texto a procurar no nome ou número'),
    limit: z.number().int().min(1).max(100).default(20).describe('Máximo de conversas'),
  },
}, run(async ({ session, search, limit }) => {
  let chats = await wa(base(session) + '/chats');
  if (search) { const q = search.toLowerCase(); chats = chats.filter((c) => (c.name + c.jid).toLowerCase().includes(q)); }
  return chats.slice(0, limit).map((c) => ({ jid: c.jid, name: c.name, last: c.last, unread: c.unread, at: fmtTime(c.ts) }));
}));

server.registerTool('wa_get_messages', {
  title: 'Ler mensagens',
  description: 'Devolve as últimas mensagens de uma conversa. "chat" aceita o nome, o número (351912345678) ou o jid. Não marca como lida.',
  inputSchema: {
    session: sessionArg,
    chat: z.string().describe('Nome, número internacional ou jid'),
    limit: z.number().int().min(1).max(150).default(20),
  },
}, run(async ({ session, chat, limit }) => {
  const jid = await resolveChat(chat, session);
  const msgs = await wa(base(session) + '/messages/' + encodeURIComponent(jid));
  return { chat: jid, messages: msgs.slice(-limit).map((m) => ({ at: fmtTime(m.ts), from: m.fromMe ? 'eu' : (m.name || m.sender), type: m.type, text: m.text })) };
}));

server.registerTool('wa_send_text', {
  title: 'Enviar texto',
  description: 'Envia uma mensagem de texto pelo WhatsApp conectado. ATENÇÃO: a mensagem é realmente enviada ao destinatário; confirme com o utilizador antes de a enviar a um contacto real.',
  inputSchema: {
    session: sessionArg,
    to: z.string().describe('Número internacional sem + (351912345678), ou jid de grupo'),
    text: z.string().min(1).max(4000),
  },
  annotations: { destructiveHint: false, openWorldHint: true },
}, run(async ({ session, to, text }) => wa(base(session) + '/send', { method: 'POST', body: { to: asJid(to), text } })));

server.registerTool('wa_send_media', {
  title: 'Enviar imagem ou documento',
  description: 'Envia uma imagem ou um documento a partir de um URL público. A mensagem é realmente enviada; confirme com o utilizador antes.',
  inputSchema: {
    session: sessionArg,
    to: z.string().describe('Número internacional sem + ou jid'),
    kind: z.enum(['image', 'document']),
    url: z.string().url().describe('URL público do ficheiro'),
    caption: z.string().optional(),
    fileName: z.string().optional().describe('Nome do ficheiro (só para documentos)'),
  },
  annotations: { destructiveHint: false, openWorldHint: true },
}, run(async ({ session, to, kind, url, caption, fileName }) =>
  wa(base(session) + '/send', { method: 'POST', body: { to: asJid(to), [kind]: url, caption, fileName } })));

server.registerTool('wa_mark_read', {
  title: 'Marcar como lida',
  description: 'Marca uma conversa como lida, também no telemóvel.',
  inputSchema: { session: sessionArg, chat: z.string().describe('Nome, número ou jid') },
}, run(async ({ session, chat }) => wa(base(session) + '/read/' + encodeURIComponent(await resolveChat(chat, session)), { method: 'POST' })));

// ---------- ajuda para o n8n ----------
const SAMPLE = {
  event: 'message',
  session: 'br4-viagens',
  sessionName: 'BR4 Viagens',
  sessionNumber: '351910000001',
  id: '3EB0A1B2C3D4E5F6A7B8',
  chat: '351912345678@s.whatsapp.net',
  chatName: 'Marta Silva',
  from: '351912345678@s.whatsapp.net',
  name: 'Marta Silva',
  fromMe: false,
  text: 'Bom dia! Quanto custa Lisboa para São Paulo em milhas?',
  type: 'text',
  timestamp: 1760520000,
  isGroup: false,
};

server.registerTool('n8n_webhook_payload', {
  title: 'Payload do webhook',
  description: 'Mostra o JSON que o WA Lite envia ao n8n em cada mensagem recebida e as expressões n8n para aceder a cada campo. Use-o antes de montar um fluxo.',
  inputSchema: {},
}, run(async () => ({
  sample: SAMPLE,
  nota: 'O nó Webhook do n8n coloca o JSON recebido dentro de "body". O campo "session" diz de que cliente veio; envie-o de volta no /api/send para responder pelo mesmo número. Cada cliente pode ter o seu próprio webhook (definições do cliente na interface).',
  expressoes: {
    cliente: '{{ $json.body.session }}',
    texto: '{{ $json.body.text }}',
    numero_para_responder: '{{ $json.body.chat }}',
    nome: '{{ $json.body.chatName }}',
    e_grupo: '{{ $json.body.isGroup }}',
    enviada_por_mim: '{{ $json.body.fromMe }}',
    tipo: '{{ $json.body.type }}',
  },
  envio: { metodo: 'POST', url: `${N8N_BASE}/api/send`, header: 'Authorization: Bearer <API_TOKEN>', corpo: { session: 'br4-viagens', to: '351912345678', text: 'Olá' } },
})));

const uid = () => crypto.randomUUID();

const jsx = (v) => (String(v).startsWith('=') ? String(v).replace(/^=\{\{\s*|\s*\}\}$/g, '') : JSON.stringify(v));
function httpSendNode({ to = '={{ $json.body.chat }}', message = 'Olá!', session = '={{ $json.body.session }}', position = [680, 300], name = 'Enviar WhatsApp' }) {
  return {
    id: uid(), name, type: 'n8n-nodes-base.httpRequest', typeVersion: 4.2, position,
    parameters: {
      method: 'POST',
      url: `${N8N_BASE}/api/send`,
      authentication: 'genericCredentialType',
      genericAuthType: 'httpHeaderAuth',
      sendBody: true,
      specifyBody: 'json',
      jsonBody: `={{ JSON.stringify({ session: ${jsx(session)}, to: ${jsx(to)}, text: ${jsx(message)} }) }}`,
      options: {},
    },
    credentials: { httpHeaderAuth: { id: 'TROCAR', name: 'WA Lite token' } },
    retryOnFail: true, maxTries: 3, waitBetweenTries: 2000,
  };
}

server.registerTool('n8n_send_node', {
  title: 'Nó n8n para enviar WhatsApp',
  description: 'Gera o JSON de um nó "HTTP Request" do n8n já configurado para enviar mensagens pelo WA Lite. Pode colar-se no canvas do n8n. Requer uma credencial "Header Auth" com Name=Authorization e Value=Bearer <API_TOKEN>.',
  inputSchema: {
    session: z.string().default('={{ $json.body.session }}').describe('Cliente que envia: id fixo (ex. br4-viagens) ou expressão n8n. Por defeito responde pelo cliente que recebeu.'),
    to: z.string().default('={{ $json.body.chat }}').describe('Destino: número fixo ou expressão n8n começada por ='),
    message: z.string().default('Olá!').describe('Texto: fixo ou expressão n8n começada por ='),
  },
}, run(async ({ session, to, message }) => ({
  passos: [
    'No n8n: Credentials > New > Header Auth. Name = Authorization, Value = Bearer <API_TOKEN>. Guarde como "WA Lite token".',
    'Cole o JSON abaixo no canvas (Ctrl+V) e escolha essa credencial no nó.',
  ],
  nodes: [httpSendNode({ session, to, message })],
  connections: {},
})));

function workflow(name, nodes, connections) {
  return { name, nodes, connections, settings: { executionOrder: 'v1' } };
}
const webhookNode = (path) => ({
  id: uid(), name: 'Mensagem recebida', type: 'n8n-nodes-base.webhook', typeVersion: 2, position: [0, 300],
  webhookId: uid(), parameters: { httpMethod: 'POST', path, options: {} },
});
const ifNode = (name, id, left, op, right, pos) => ({
  id: uid(), name, type: 'n8n-nodes-base.if', typeVersion: 2.2, position: pos,
  parameters: {
    conditions: {
      options: { caseSensitive: false, leftValue: '', typeValidation: 'loose', version: 2 },
      conditions: [{ id, leftValue: left, rightValue: right, operator: { type: 'string', operation: op } }],
      combinator: 'and',
    },
    options: {},
  },
});

server.registerTool('n8n_starter_workflow', {
  title: 'Fluxo n8n inicial',
  description: 'Gera um fluxo n8n completo, pronto a importar (Workflows > Import from file/URL ou colar no canvas). As respostas saem sempre pelo mesmo cliente (número) que recebeu a mensagem. Modelos: "auto_reply" (responde com um texto fixo), "keyword_router" (responde conforme palavras-chave) e "echo_test" (devolve o que recebeu, para testar a ligação).',
  inputSchema: {
    template: z.enum(['auto_reply', 'keyword_router', 'echo_test']),
    webhookPath: z.string().default('wa-lite').describe('Caminho do webhook, ex. wa-lite'),
    reply: z.string().default('Olá! Recebemos a sua mensagem e já respondemos.').describe('Texto de resposta (auto_reply)'),
    keywords: z.record(z.string()).default({ milhas: 'Para cotar em milhas preciso da origem, destino e datas.', preço: 'Diga-me o trajeto e as datas e envio o valor.' })
      .describe('Palavra-chave para resposta (keyword_router)'),
  },
}, run(async ({ template, webhookPath, reply, keywords }) => {
  const hook = webhookNode(webhookPath);
  const notFromMe = ifNode('Não é minha, nem grupo?', uid(), '={{ $json.body.fromMe }}', 'false', '', [240, 300]);
  // fromMe e isGroup são booleanos; usa duas condições booleanas
  notFromMe.parameters.conditions = {
    options: { caseSensitive: true, leftValue: '', typeValidation: 'strict', version: 2 },
    conditions: [
      { id: uid(), leftValue: '={{ $json.body.fromMe }}', rightValue: '', operator: { type: 'boolean', operation: 'false', singleValue: true } },
      { id: uid(), leftValue: '={{ $json.body.isGroup }}', rightValue: '', operator: { type: 'boolean', operation: 'false', singleValue: true } },
    ],
    combinator: 'and',
  };
  notFromMe.name = 'Só conversas privadas recebidas';

  if (template === 'echo_test') {
    const send = httpSendNode({ message: '={{ "Recebi: " + $json.body.text }}', position: [480, 280] });
    return {
      aviso: 'Depois de importar, escolha a credencial "WA Lite token" no nó de envio e ative o fluxo. Copie o URL de PRODUÇÃO do nó Webhook para o N8N_WEBHOOK_URL do WA Lite.',
      workflow: workflow('WA Lite - Eco de teste', [hook, notFromMe, send], {
        [hook.name]: { main: [[{ node: notFromMe.name, type: 'main', index: 0 }]] },
        [notFromMe.name]: { main: [[{ node: send.name, type: 'main', index: 0 }], []] },
      }),
    };
  }

  if (template === 'auto_reply') {
    const send = httpSendNode({ message: reply, position: [480, 280] });
    return {
      aviso: 'Depois de importar, escolha a credencial "WA Lite token" no nó de envio e ative o fluxo. Copie o URL de PRODUÇÃO do nó Webhook para o N8N_WEBHOOK_URL do WA Lite.',
      workflow: workflow('WA Lite - Resposta automática', [hook, notFromMe, send], {
        [hook.name]: { main: [[{ node: notFromMe.name, type: 'main', index: 0 }]] },
        [notFromMe.name]: { main: [[{ node: send.name, type: 'main', index: 0 }], []] },
      }),
    };
  }

  // keyword_router: um Code node escolhe a resposta; um IF verifica se há correspondência
  const entries = Object.entries(keywords);
  const code = {
    id: uid(), name: 'Escolher resposta', type: 'n8n-nodes-base.code', typeVersion: 2, position: [480, 280],
    parameters: {
      mode: 'runOnceForEachItem',
      jsCode:
`const regras = ${JSON.stringify(Object.fromEntries(entries), null, 2)};
const texto = ($json.body.text || '').toLowerCase();
const chave = Object.keys(regras).find((k) => texto.includes(k.toLowerCase()));
return { json: { ...$json, resposta: chave ? regras[chave] : '' } };`,
    },
  };
  const hasReply = {
    id: uid(), name: 'Há resposta?', type: 'n8n-nodes-base.if', typeVersion: 2.2, position: [720, 280],
    parameters: {
      conditions: {
        options: { caseSensitive: true, leftValue: '', typeValidation: 'strict', version: 2 },
        conditions: [{ id: uid(), leftValue: '={{ $json.resposta }}', rightValue: '', operator: { type: 'string', operation: 'notEmpty', singleValue: true } }],
        combinator: 'and',
      },
      options: {},
    },
  };
  const send = httpSendNode({ to: '={{ $json.body.chat }}', message: '={{ $json.resposta }}', position: [960, 260] });
  return {
    aviso: 'Edite o objeto "regras" no nó "Escolher resposta" para mudar palavras-chave e respostas. Escolha a credencial "WA Lite token" no nó de envio e ative o fluxo.',
    workflow: workflow('WA Lite - Respostas por palavra-chave', [hook, notFromMe, code, hasReply, send], {
      [hook.name]: { main: [[{ node: notFromMe.name, type: 'main', index: 0 }]] },
      [notFromMe.name]: { main: [[{ node: code.name, type: 'main', index: 0 }], []] },
      [code.name]: { main: [[{ node: hasReply.name, type: 'main', index: 0 }]] },
      [hasReply.name]: { main: [[{ node: send.name, type: 'main', index: 0 }], []] },
    }),
  };
}));

await server.connect(new StdioServerTransport());
console.error(`wa-lite MCP pronto (${BASE})`);
