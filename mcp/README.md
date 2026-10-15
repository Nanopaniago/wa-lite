# WA Lite MCP

Liga o Claude (ou qualquer cliente MCP) ao seu WA Lite. Permite ler conversas, enviar mensagens
e gerar nós e fluxos do n8n já configurados para o WA Lite.

Corre **no computador onde usa o Claude**, não no DietPi. Fala com o WA Lite pela rede local.

## Instalar (no computador)
```bash
git clone https://github.com/Nanopaniago/wa-lite.git
cd wa-lite/mcp && npm install
```
Precisa de Node 20 ou mais recente.

## Configurar

**Claude Code**
```bash
claude mcp add wa-lite \
  -e WA_LITE_URL=http://192.168.1.81:3200 \
  -e WA_LITE_TOKEN=SEU_API_TOKEN \
  -- node /caminho/para/wa-lite/mcp/server.js
```

**Claude Desktop** (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "wa-lite": {
      "command": "node",
      "args": ["C:/caminho/para/wa-lite/mcp/server.js"],
      "env": {
        "WA_LITE_URL": "http://192.168.1.81:3200",
        "WA_LITE_TOKEN": "SEU_API_TOKEN"
      }
    }
  }
}
```
Reinicie o Claude depois de guardar.

| Variável | Uso |
|---|---|
| `WA_LITE_URL` | Endereço do WA Lite, visto do seu computador |
| `WA_LITE_TOKEN` | O `API_TOKEN` do `.env` do WA Lite |
| `WA_LITE_N8N_URL` | Opcional. Endereço do WA Lite visto a partir do n8n, se for diferente (ex. `http://localhost:3200` com o n8n no mesmo DietPi) |

## Ferramentas
| Ferramenta | O que faz |
|---|---|
| `wa_list_sessions` | Lista os clientes (números) e o estado de cada um |
| `wa_status` | Estado do servidor e memória |
| `wa_list_chats` | Lista e pesquisa conversas |
| `wa_get_messages` | Lê as últimas mensagens (por nome, número ou jid) |
| `wa_send_text` | Envia texto |
| `wa_send_media` | Envia imagem ou documento por URL |
| `wa_mark_read` | Marca como lida |
| `n8n_webhook_payload` | Mostra o JSON que o n8n recebe e as expressões para cada campo |
| `n8n_send_node` | Gera o nó HTTP Request que envia WhatsApp |
| `n8n_starter_workflow` | Gera um fluxo completo: `echo_test`, `auto_reply` ou `keyword_router` |

As mensagens enviadas por `wa_send_text` e `wa_send_media` são reais. O Claude deve pedir confirmação antes de as enviar.

Todas as ferramentas `wa_*` aceitam `session` (id ou nome do cliente). Sem ele, usam o primeiro cliente. Os fluxos e nós gerados respondem sempre pelo mesmo cliente que recebeu a mensagem.

## Exemplos de pedidos
- "Que clientes estão ligados? Mostra as últimas conversas da BR4 Viagens."
- "Cria um fluxo n8n que responde por palavra-chave a perguntas sobre milhas."
- "Lê as últimas mensagens da Marta e resume o que ela pediu."

## Importar um fluxo no n8n
1. Em Credentials, crie uma credencial **Header Auth**: Name `Authorization`, Value `Bearer SEU_API_TOKEN`, com o nome "WA Lite token".
2. Cole o JSON do fluxo no canvas do n8n (Ctrl+V) e escolha essa credencial no nó "Enviar WhatsApp".
3. Copie o URL de **produção** do nó Webhook para o `N8N_WEBHOOK_URL` do WA Lite e reinicie o serviço.
4. Ative o fluxo.

Se o Claude também tiver o MCP do próprio n8n ligado, pode criar e testar os fluxos diretamente.
