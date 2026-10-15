# WA Lite

WhatsApp leve para correr no DietPi: liga por QR code, interface web própria e ligação ao n8n.
Usa o Baileys (WebSocket direto), sem Chromium.

## Instalar
```bash
cd ~/wa-lite
cp .env.example .env          # defina API_TOKEN (openssl rand -hex 24) e N8N_WEBHOOK_URL
npm install                   # o .npmrc evita instalar o sharp e outras dependências pesadas
npm start
```
Abra `http://IP-DO-DIETPI:3100`, entre com o token e escaneie o QR.

## Arrancar sozinho no boot
```bash
sudo cp wa-lite.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wa-lite
journalctl -u wa-lite -f      # ver logs
```
Ajuste `User` e `WorkingDirectory` no ficheiro se a pasta não for `/home/dietpi/wa-lite`.

## n8n
- **Receber:** nó Webhook (POST) no URL definido em `N8N_WEBHOOK_URL`. Campos: `chat`, `chatName`, `from`, `name`, `text`, `type`, `isGroup`, `timestamp`. Com `WEBHOOK_SECRET`, chega o header `X-Webhook-Secret`.
- **Enviar:** nó HTTP Request, `POST http://IP:3100/api/send`, header `Authorization: Bearer <API_TOKEN>`.
  - Texto: `{ "to": "351912345678", "text": "Olá" }`
  - Imagem: `{ "to": "351912345678", "image": "https://…/foto.jpg", "caption": "…" }`
  - Documento: `{ "to": "…", "document": "https://…/ficheiro.pdf", "fileName": "cotacao.pdf" }`

## MCP (opcional)
A pasta `mcp/` tem um servidor MCP que liga o Claude ao WA Lite e gera fluxos n8n. Corre no seu computador, não no DietPi. Veja `mcp/README.md`.

## Rotas
| Rota | Uso |
|---|---|
| `GET /health` | Estado, sem token (monitorização) |
| `GET /api/status` | Estado, número, memória |
| `GET /api/chats` · `GET /api/messages/:jid` | Conversas guardadas |
| `POST /api/read/:jid` | Marca como lida (também no telemóvel) |
| `POST /api/send` | Enviar mensagem |
| `POST /api/logout` | Termina a sessão |

## Dados
`data/auth` guarda a sessão (não apague, senão pede QR de novo). `data/store.json` guarda as últimas conversas, com os limites do `.env`.

> O Baileys não é a API oficial do WhatsApp. Evite envios em massa; para começar, use um número secundário.
