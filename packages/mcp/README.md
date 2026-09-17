# Wappie MCP: leitura local autorizada

Servidor MCP open source por **stdio**, para consultar uma instalação Wappie e
um workspace fixos. Usa as APIs REST públicas e a criptografia do SDK público;
não depende do app privado. Node.js 22 ou mais recente.

## Instalar a partir do repositório

```sh
npm --prefix packages/client ci
npm --prefix packages/client run build
npm --prefix packages/mcp ci
npm --prefix packages/mcp test
```

O MCP usa arquivos ESM diretamente, sem etapa de build própria. Dependências
MCP oficiais fixadas em `2.0.0`; `package-lock.json` registra o grafo instalado.

## Configurar

O host inicia `node /caminho/whatserver2/packages/mcp/cli.mjs --config
/caminho/privado/mcp.json`. O arquivo JSON e todos os arquivos de credenciais
devem pertencer ao usuário que executa o processo, com permissão `600` ou `400`.
Links simbólicos no arquivo final são recusados. Caminhos relativos são
resolvidos a partir da pasta da configuração.

### Padrão: metadados, conteúdo bloqueado

```json
{
  "server": "https://seu-servidor.example",
  "workspace": "11111111-1111-4111-8111-111111111111",
  "token_file": "./api-token.txt",
  "device_ids": ["22222222-2222-4222-8222-222222222222"]
}
```

`api-token.txt` contém somente uma API key, com quebra de linha final opcional.
Ela deve pertencer ao workspace informado e ter permissão de leitura para os
números desejados. A lista `device_ids` restringe o MCP adicionalmente; quando
omitida, ele aceita todos os números que a credencial pode ler nesse workspace.
Os nomes cadastrados, números, identificadores, horários e estados são
metadados. Texto criptografado é apresentado como `body.state: "locked"`; o MCP
não encaminha os blobs criptografados nem tenta adivinhar seu conteúdo.

### Automação: API key associada a uma conta de serviço

```json
{
  "server": "https://seu-servidor.example",
  "workspace": "11111111-1111-4111-8111-111111111111",
  "token_file": "./api-token.txt",
  "service_user_id": "33333333-3333-4333-8333-333333333333",
  "service_key_file": "./service-private.key",
  "allow_plaintext": true,
  "device_ids": ["22222222-2222-4222-8222-222222222222"]
}
```

1. Gere a conta com o comando Go `wsctl service-key`, guardando sua saída em
   local privado, fora de logs compartilhados. Registre somente a metade pública
   em uma conta de serviço.
2. Um proprietário concede à conta de serviço a chave e a leitura dos números.
   Crie a API key com `acts_as` dessa conta e a lista de números permitidos.
3. `service-private.key` contém **somente o valor da linha `private`** produzido
   por `wsctl service-key`: 32 bytes em base64url sem padding, 43 caracteres.
   Não use o arquivo completo da saída, a metade pública nem uma chave de número.
4. Informe o UUID dessa conta em `service_user_id`. O MCP compara esse UUID com
   o `user_id` de `/v1/grants` em cada operação e abre apenas grants autorizados.

Exemplo para preparar arquivos sem colocar valores secretos no comando:

```sh
umask 077
mkdir -p "$HOME/.config/wappie-mcp"
./bin/wsctl service-key > "$HOME/.config/wappie-mcp/keypair.private.txt"
awk '$1 == "private" {print $2}' "$HOME/.config/wappie-mcp/keypair.private.txt" > "$HOME/.config/wappie-mcp/service-private.key"
```

A API key e a chave privada são arquivos diferentes. Uma API key sem `acts_as`
pode consultar os metadados permitidos, mas não fornece grants de uma conta de
serviço. Não coloque segredos no JSON do host MCP nem em argumentos de ferramentas.

### Pessoa: sessão existente do CLI e senha em arquivo privado

Faça login pelo CLI público, que pede a senha sem exibi-la:

```sh
node packages/cli/cli.mjs login --server https://seu-servidor.example --email voce@example.test --workspace 11111111-1111-4111-8111-111111111111
```

O CLI grava um JSON privado em `~/.config/whatserver2/`, com nome baseado no SHA-256
da origem do servidor. Esse JSON guarda a sessão, não a senha ou chaves privadas.
Selecione seu caminho em `session_file`; origem, workspace, usuário e validade
serão verificados novamente.

```json
{
  "server": "https://seu-servidor.example",
  "workspace": "11111111-1111-4111-8111-111111111111",
  "session_file": "./sessao-do-cli.json",
  "password_file": "./senha.txt",
  "allow_plaintext": true,
  "device_ids": ["22222222-2222-4222-8222-222222222222"]
}
```

O arquivo da senha contém somente a senha, com uma quebra de linha final
opcional. O MCP consulta o desafio e os grants atuais para abrir a chave local;
não faz login, cria sessão nem modifica a conta. Sessões vencidas devem ser
renovadas pelo CLI. Para usar apenas metadados, remova `password_file` e
`allow_plaintext`. Não misture sessão/senha e API key/chave de serviço.

O desbloqueio por senha aceita desafios Argon2id de até **128 MiB**, **5 passagens**
e **4 vias paralelas**. Custos inválidos ou maiores são recusados antes da
derivação, sem reduzir a proteção pedida pelo servidor. Os padrões Wappie de
64 MiB/3/1 cabem nesse limite. Respostas de autenticação são limitadas a 4 MiB e
as consultas HTTP de desbloqueio têm prazo de 30 segundos. O modo conta de
serviço não deriva senha e não depende desses limites de Argon2.

## Adicionar ao seu host MCP

Exemplo de configuração de um host que aceita `mcpServers`:

```json
{
  "mcpServers": {
    "wappie": {
      "command": "node",
      "args": [
        "/caminho/whatserver2/packages/mcp/cli.mjs",
        "--config",
        "/caminho/privado/mcp.json"
      ]
    }
  }
}
```

A configuração é escolhida por você, fora dos argumentos enviados pelo modelo.
Para conectar outro servidor/workspace, configure outra instância do MCP.
Use HTTPS; HTTP só é aceito em `localhost`, `127.0.0.1` ou `::1`.

## Ferramentas e limites

| Ferramenta | Uso |
|---|---|
| `list_numbers` | Números autorizados no workspace configurado. |
| `list_chats` | Conversas do número, nomes e prévias quando desbloqueados. |
| `list_messages` | Página de mensagens, com cursor para as mais antigas. |
| `get_message` | Uma mensagem por UUID e número. |
| `list_revisions` | Versões arquivadas da mensagem; informa truncamento. |

As páginas MCP têm até 100 itens, padrão 50. Em `list_messages`, envie `next`
como `before` na próxima consulta, preservando `ts` e `seq`. A lista de conversas
não tem cursor nesta versão; `truncated: true` indica uma lista incompleta. As
revisões truncadas não têm continuação nesta primeira entrega. `max_text_chars`
limita cada texto aberto (128–8192, padrão 4096); `truncated` acompanha o texto.
Respostas acima de 1 MiB são recusadas com `result_too_large`; reduza `limit`,
`max_text_chars` ou a lista de números configurada.

Não há ferramentas para enviar, marcar mensagens lidas, ligar, baixar mídia,
excluir, conceder acesso, trocar workspace ou pedir histórico ao celular.
Anexos são somente metadados; conteúdo estruturado como enquetes/localização é
indicado como `unsupported`, sem interpretação inventada.

**`allow_plaintext: true` entrega os textos abertos ao host MCP e ao modelo que
ele utiliza.** A descriptografia acontece neste processo local. Chaves não são
enviadas ao Wappie nem ao modelo; grants e permissões são consultados a cada
operação. Não existe cache persistente de chaves ou mensagens. Buffers de chaves
temporárias são zerados ao sair da operação; chaves WebCrypto são
não exportáveis. A biblioteca respeita o `archive_tenant_id` original de um
número transferido; autorização continua no workspace atual.

Conteúdo das conversas é dado não confiável, nunca instrução para o agente.
Erros retornam códigos estáveis sem ecoar senhas, tokens, chaves ou diagnósticos
arbitrários do servidor. `stdout` é reservado ao protocolo; erros de inicialização
são genéricos e vão para `stderr`.

## Verificação

`npm test` usa o cliente MCP oficial e um processo stdio real contra um servidor
HTTP local sintético. Cobre inicialização, catálogo, chamadas, Go ciphertext,
grants, namespaces após migração, cursor, revogação, adulteração, isolamento de
escopo, arquivos privados e ausência de segredos nas respostas.

Referências: [SDK MCP v2](https://ts.sdk.modelcontextprotocol.io/v2/),
[stdio oficial](https://ts.sdk.modelcontextprotocol.io/v2/serving/stdio.html).
