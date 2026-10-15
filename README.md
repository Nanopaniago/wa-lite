# WA Lite

WhatsApp leve para correr no DietPi, com vários números (um por cliente), interface web própria e ligação ao n8n.
Usa o Baileys (WebSocket direto), sem Chromium.

## Instalar
```bash
cd ~/wa-lite
cp .env.example .env          # defina API_TOKEN (openssl rand -hex 24) e N8N_WEBHOOK_URL
npm install                   # o .npmrc evita instalar o sharp e outras dependências pesadas
npm start
```
Abra `http://IP-DO-DIETPI:3100`, entre com o token, clique em **+** para adicionar um cliente e escaneie o QR com o WhatsApp desse cliente.

## Vários clientes
- Cada cliente tem o seu número, as suas conversas e, se quiser, o seu próprio webhook do n8n.
- O limite é definido por `MAX_SESSIONS` no `.env` (5 por defeito). Cada número ligado gasta memória extra, por isso não exagere num Raspberry com pouca RAM.
- Ao atualizar da versão anterior, o número que já estava ligado passa para o cliente **Principal**, sem novo QR.

## Arrancar sozinho no boot
```bash
sudo cp wa-lite.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now wa-lite
journalctl -u wa-lite -f      # ver logs
```
Ajuste `User` e `WorkingDirectory` no ficheiro se a pasta não for `/home/dietpi/wa-lite`.

## n8n
- **Receber:** nó Webhook (POST) no URL do cliente ou no `N8N_WEBHOOK_URL` geral. Campos: `session`, `sessionName`, `sessionNumber`, `chat`, `chatName`, `from`, `name`, `text`, `type`, `isGroup`, `timestamp`. Com `WEBHOOK_SECRET`, chega o header `X-Webhook-Secret`.
- **Enviar:** nó HTTP Request, `POST http://IP:3100/api/send`, header `Authorization: Bearer <API_TOKEN>`.
  - Texto: `{ "session": "br4-viagens", "to": "351912345678", "text": "Olá" }`
  - Para responder pelo mesmo número que recebeu: `"session": "{{ $json.body.session }}"`. Sem `session`, usa o primeiro cliente.
  - Imagem: `{ "to": "351912345678", "image": "https://…/foto.jpg", "caption": "…" }`
  - Documento: `{ "to": "…", "document": "https://…/ficheiro.pdf", "fileName": "cotacao.pdf" }`

## MCP (opcional)
A pasta `mcp/` tem um servidor MCP que liga o Claude ao WA Lite e gera fluxos n8n. Corre no seu computador, não no DietPi. Veja `mcp/README.md`.

## Rotas
| Rota | Uso |
|---|---|
| `GET /health` | Estado, sem token (monitorização) |
| `GET /api/status` | Estado de todos os clientes e memória |
| `GET /api/sessions` · `POST /api/sessions` | Listar / criar cliente (`{ name, webhook }`) |
| `PATCH /api/sessions/:id` · `DELETE /api/sessions/:id` | Editar / remover cliente |
| `POST /api/sessions/:id/start` · `/logout` | Gerar QR / desligar número |
| `GET /api/sessions/:id/chats` · `/messages/:jid` | Conversas do cliente |
| `POST /api/sessions/:id/read/:jid` | Marca como lida (também no telemóvel) |
| `POST /api/send` ou `/api/sessions/:id/send` | Enviar mensagem |

`:id` aceita o id ou o nome do cliente.

## Dados
`data/sessions.json` lista os clientes. Cada cliente tem uma pasta em `data/sessions/<id>/` com a sessão (`auth/`, não apague senão pede QR de novo) e as últimas conversas (`store.json`).

> O Baileys não é a API oficial do WhatsApp. Evite envios em massa; para começar, use um número secundário.
