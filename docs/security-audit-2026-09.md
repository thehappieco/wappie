# Auditoria de privacidade e segurança — setembro de 2026

Escopo: o servidor `whatserverd`, o cliente web em `web/`, o CLI `wsctl`, o
schema Postgres e o deploy local em `localhost:8090`. Método: leitura do código
com rastreamento de cada ponto de entrada até a persistência, verificação ao
vivo somente-leitura dos cabeçalhos e endpoints expostos, `govulncheck`,
`npm audit`, e correção de cada achado com teste de regressão.

O modelo de chaves está descrito em `README.md` ("How the archive is
protected") e as decisões desta auditoria em `decisions.md` ("Phase 13").

## Resumo

| Severidade | Encontrados | Corrigidos | Backlog |
|---|---|---|---|
| Alta | 6 | 6 | 0 |
| Média | 12 | 12 | 0 |
| Baixa / Info | 8 | 7 | 1 (C4b: ver abaixo) |

Nada de crítico na criptografia: o selo HPKE, a ligação de cada blob à sua
linha (AAD), o armazenamento da mídia como ciphertext da CDN, a derivação da
senha em duas ramas e o RLS com `FORCE` estão corretos e testados dos dois
lados. Os achados estão no que fica **ao redor** do selo: autenticação,
autorização, superfície de rede, logs e retenção.

## Achados e correções

### Autenticação e chaves

| # | Sev | Achado | Correção | Teste |
|---|---|---|---|---|
| A1 | Alta | Código de recuperação era gerado e gravado, mas não existia endpoint nem tela que o usasse. Senha esquecida = arquivo perdido. | `POST /v1/auth/recover/open` e `/finish`: o código deriva uma prova (HKDF, rama separada), guardada como Argon2id em `users.recovery_hash` (migração 0018). O `SignInView` ganhou "Esqueci a senha". A recuperação troca senha e código e encerra toda sessão. Contas antigas sem prova são avisadas no console e geram um novo código. | `authapi_test.go`: `TestARecoveryCodeOpensTheAccountAndReplacesEverything`, `TestAWrongRecoveryCodeAnswersLikeAnUnknownAddress`, `TestAnOldAccountCanSetARecoveryCodeLater`; `web/test/account.spec.ts` |
| A2 | Alta | Sem rate limit em login, challenge e no `hello` do websocket; cada tentativa custa Argon2id 19 MiB. | `internal/ratelimit`: token bucket por IP (60/min) e por sujeito (5/min), com `Retry-After`. `WS_TRUSTED_PROXIES` define quem pode informar `X-Forwarded-For`. | `TestSignInIsRateLimited`, `TestHelloIsRateLimited`, `ratelimit_test.go` |
| A3 | Média | Sem troca de senha nem re-wrap. | `POST /v1/auth/password` (prova a senha atual, re-deriva, revoga sessões, emite token novo); painel "Conta" no console. `POST /v1/auth/rewrap` para o upgrade silencioso de formato. | `TestChangingThePasswordEndsEveryOtherSession` |
| A4 | Média | O wrap da chave privada da conta não tinha AAD; qualquer outro selo do sistema tem. | Formato v2: byte de versão + AAD `whatserver2/usk|email`. v1 continua abrindo e é re-wrapado no próximo login. | `account.spec.ts`: "is bound to the address", "still opens a wrap from before the binding" |
| A5 | Média | Conta desabilitada mantinha sessões por 14 dias. | `Users.ActiveSession` checa `status` em todo ponto que aceita token (HTTP, websocket, mídia). `RevokeAllSessions` na troca de senha e na recuperação. | `TestADisabledAccountsSessionsStopWorking` |
| A6 | Média | `device-key -print` escrevia a chave privada no terminal sem confirmação. | Exige `-i-understand-this-prints-a-private-key`. | manual |
| A7 | Baixa | Sessões e convites mortos nunca eram apagados. | `store.Housekeeping` no job horário: 30 dias de carência. | `TestHousekeepingForgetsDeadSessionsAfterAGrace` |
| A8 | Baixa | Um signup recusado por campo malformado gastava o convite. | O corpo é validado antes de `RedeemInvite`. | `TestAnOldAccountCanSetARecoveryCodeLater` (reusa o convite) |

### Autorização (websocket)

| # | Sev | Achado | Correção | Teste |
|---|---|---|---|---|
| B1 | Alta | API key sem escopo: podia enviar como o número, entrar em grupos, parar devices, fazer upload. | `api_keys.scope` (`read`/`send`/`full`, migração 0017, default `full` para as existentes). `requireScope` em `resolveSend`, `history.backfill`, `group.join`, `device.stop` e `POST /v1/upload`. UI e CLI escolhem o escopo. | `TestAReadKeyCannotSpeakForTheNumber`, `TestASendKeyStopsAtSending`, `TestAKeyIssuedBeforeScopesKeepsWorking`, `TestAKeyNeedsAScope` |
| B2 | Média | `device.mode` sem gate: qualquer ator desligava o incógnito. | `requireOperator` (owner/admin ou chave `full`). | `TestOnlyAnOperatorCanChangeADevicesPosture` |
| B3 | Média | `pair` sem gate e aceitava `Grants: []` com aviso. | `requireOperator`; sem grants só com `orphan: true`. `wsctl pair -orphan` envia o campo. | `TestPairingIsAnOperatorsAct` |
| B4 | Média | Membro sem grant via todo o envelope de todo device; `users.list` e a lista de leitores expostos a qualquer ator. | `resolveDevice` exige grant para pessoa não-admin (`Keys.HasGrant`); `users.list` é de operador; leitores só para admin. | `TestAMemberWithoutAGrantSeesNothingOfADevice` |

### Rede e entrada

| # | Sev | Achado | Correção | Teste |
|---|---|---|---|---|
| C1 | Alta | SSRF cego: `media.url` do protobuf recebido era buscado sem checar esquema/host, seguindo redirects. | `media.Origins`: só `https://*.whatsapp.net`, porta padrão, sem credenciais; mesma checagem em cada redirect; dialer resolve o nome e recusa endereços privados/loopback/link-local/CGNAT. | `origin_test.go`: 5 testes, incluindo redirect e resolução para endereço privado |
| C2 | Baixa | Avatar buscado de URL sem restrição de host. | Mesmo `Origins` no `AvatarWorker`. | coberto por `origin_test.go` |
| C3 | Info | `/metrics`, `/healthz`, `/readyz` na porta pública. Ao vivo, os labels não expõem tenant/JID. | `WS_METRICS_ADDR` opcional serve os três em listener próprio. | manual |
| C4 | Info | `docker-compose.dev.yml` publicava Postgres e MinIO em `0.0.0.0` com senha `dev`. | Bind em `127.0.0.1`. | — |
| C4b | Info | Backlog: as senhas de desenvolvimento do compose continuam fracas por design; não usar o compose fora da máquina local. | não corrigido (documentado) | — |
| C5 | Info | Backlog: o build do cliente publica o source map (`index-*.js.map`, 1,5 MB) junto com o bundle. Não expõe segredo, mas entrega o código-fonte do cliente a qualquer visitante; decidir se é desejado (`build.sourcemap` no `vite.config.ts`). | não corrigido (decisão de produto) | — |

### Logs e dados em repouso

| # | Sev | Achado | Correção | Teste |
|---|---|---|---|---|
| D1 | Alta | `WS_LOG_LEVEL=debug` repassava o trace do whatsmeow: texto das mensagens em claro nos logs. | Debug do whatsmeow é descartado; `WS_LOG_WIRE` liga explicitamente e é recusado em `WS_ENV=prod`. | `walog_test.go`, `config_test.go` "rejects the wire log" |
| D2 | Média | Números, JIDs e e-mails em INFO/WARN/ERROR. | `obs.Redact` via `ReplaceAttr` em todo atributo string e na mensagem: JID vira `…1234@servidor`, e-mail vira `f…@domínio`. | `redact_test.go` |
| D3 | Média | Sem retenção, expurgo ou eliminação de terceiros. | `tenants.retention_days` (migração 0019), `whatserverd retention`, job horário `maintain`; `whatserverd erase -id` remove uma pessoa em todos os devices. | `TestAPurgeTakesOldRowsAndOnlyTheOrphanedObjects`, `TestErasureRemovesOnePersonAcrossTheArchive` |
| D4 | Média | Apagar device / `reset-archive` deixava os objetos no bucket. | Objetos órfãos (nenhuma linha `media` do tenant os referencia) são apagados após o delete; `reset-archive` apaga todos os do tenant. | cobertos pelos testes de D3 (cálculo de órfãos) |
| D5 | Média | Nada verificava que o role do Postgres não tem `SUPERUSER`/`BYPASSRLS`. | `pg.CheckRole` no boot: erro em prod, aviso em dev. | `TestCheckRoleAcceptsTheTestRole` |
| D6 | Baixa | `.env` local com API key e segredo S3 em claro. | Documentado em `.env.example`; recomenda-se variável de ambiente ou keychain. | — |
| D7 | Baixa | README e decisions.md descreviam o modelo antigo (chave por tenant; PBKDF2 protegendo a chave em repouso). | Atualizados. | — |

### Adicionado depois da auditoria

| # | Item | Correção | Teste |
|---|---|---|---|
| E1 | Terceiros recebiam a chave do device em texto, por mão. | Conta de serviço (`role = 'service'`, migração 0020): par de chaves sem senha, registrado por convite `-role service`; grants concedidos no console; API key que "age como" a conta (`api_keys.acts_as`) carrega os grants por `grants.list` e só alcança os devices concedidos. `wsctl service-key` e `wsctl grants`. | `TestAServiceAccountReadsOnlyWhatItWasGranted`, `TestAServiceRegistersWithAPublicKeyOnly` |

### Verificado sem achado

- CSP estrita, `X-Frame-Options: DENY`, COOP/CORP, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` (confirmados ao vivo em `localhost:8090`).
- `/v1/media/{uid}` e `/v1/auth/me` exigem Bearer; token nunca vai em URL;
  mídia servida como `application/octet-stream` com `nosniff` e `attachment`.
- Sem SQL dinâmico; `set_config` com bind param; RLS com `FORCE` + `NULLIF` em
  toda tabela por tenant; testes de negação e escopo em `internal/pg`.
- Buffers de plaintext do whatsmeow desligados e pinados por teste.
- Sem bypass de autenticação por ambiente, sem credencial hardcoded; `.env`
  fora do git; gitleaks no CI.
- `npm audit --omit=dev`: 0 vulnerabilidades. `govulncheck ./...`: 0 alcançáveis.
- Path traversal: chave de objeto nunca vem do cliente; `webui` limpa o caminho
  e testa a fuga de diretório.

## O que continua fora do alcance do selo

Inalterado por esta auditoria e documentado no README: um atacante com código
no processo vê texto em claro em trânsito; o store de sessão do whatsmeow é
legível pelo processo e fora do RLS; texto de saída passa em claro; metadados
de roteamento e recibos são legíveis no banco (e agora mascarados nos logs).

## Checklist de deploy

- `WS_ENV=prod` (recusa `sslmode=disable`, storage sem TLS, `WS_LOG_WIRE`,
  role com `BYPASSRLS`).
- Role do Postgres `NOSUPERUSER NOBYPASSRLS`.
- `WS_TRUSTED_PROXIES` apontando para o reverse proxy, e mais nada.
- `WS_METRICS_ADDR` em interface privada.
- Chaves de API com o menor escopo que funciona; `bootstrap` imprime uma `full`.
- `whatserverd retention -tenant ID -days N` conforme a política do tenant.
- Cada conta com código de recuperação gerado após esta versão (o console avisa).
- Backup do banco tratado como dado sensível: contém metadados em claro e
  material cifrado atacável offline.

## Como verificar

```
make check && make web-check
golangci-lint run ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

Ao vivo: seis `POST /v1/auth/login` errados em um minuto devolvem 429 com
`Retry-After`; um `hello` com chave `read` seguido de `message.send` devolve
`not_authorized`; `GET /metrics` não contém números nem e-mails.
