# MCP local de leitura autorizada

O pacote público [`packages/mcp`](../packages/mcp/README.md) conecta um host MCP
às APIs REST de uma instalação Wappie. Ele oferece consulta de números,
conversas, mensagens e revisões, sem depender do app comercial.

## Configuração e identidade

- A instalação e o workspace ficam fixos em um arquivo local privado.
- Use uma sessão existente do CLI para pessoa ou uma API key para automação.
- O padrão consulta metadados e apresenta o conteúdo selado como `locked`.
- Para abrir texto, autorize `allow_plaintext` e forneça uma senha em arquivo
  privado para a sessão, ou a chave privada de uma conta de serviço para a API key.
- A chave de serviço mantém exatamente o formato base64url de `wsctl service-key`.
- A lista opcional de números reduz o escopo além das permissões do servidor.
- O modelo não pode escolher outra instalação, workspace, credencial ou caminho.

O texto aberto é enviado ao host MCP/modelo escolhido pelo usuário. As chaves
permanecem no processo local, sem cache persistente, e os grants atuais continuam
obrigatórios. A revogação ou a mudança de workspace não é contornada por uma
chave que exista no computador. Arquivos de credenciais privados e TLS continuam
necessários.

## Contrato desta primeira versão

`list_numbers`, `list_chats`, `list_messages`, `get_message` e `list_revisions`
usam somente leituras do acervo persistido. Não há envio, chamada, confirmação de
leitura, download de mídia ou sincronização histórica. A listagem de mensagens
preserva o cursor timestamp/sequência fornecido pelo servidor. Conversas e
revisões podem retornar truncamento explícito; ainda não há cursor para esses
diretórios. Payloads estruturados e anexos não são abertos por esta entrega.

Limites, exemplos completos, preparação das identidades e configuração do host:
[guia do pacote MCP](../packages/mcp/README.md).

O SDK [`ArchiveClient`](../packages/client/README.md#read-only-rest-client)
também permite implementar clientes HTTP próprios com origem/workspace fixos,
os mesmos envelopes selados e decriptação local pelo `Opener` público.
