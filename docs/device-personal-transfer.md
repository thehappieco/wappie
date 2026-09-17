# Mover um número de Team para Personal

No console, abra os detalhes do número e escolha **Migrar para Pessoal**. A prévia informa o destino e o espaço necessário; **Confirmar migração** executa a mudança.

## Requisitos e resultado

- Você precisa ser o único proprietário do Team e ter as chaves de todo o histórico do número.
- O destino é seu próprio Personal, ativo, com vínculo e armazenamento disponíveis.
- Histórico, anexos, identidade WhatsApp e chaves são preservados. As permissões dos outros membros e das chaves de API do Team são removidas.
- O número fica pausado ao concluir. Use **Abrir workspace Pessoal**, confira o histórico e escolha **Retomar sincronização** nos detalhes do número.
- A assinatura do Team não é transferida: a operação utiliza a capacidade já disponível no Personal. Não há compra automática.
- Em uma instalação externa, o app tenta substituir o vínculo comercial pelo mesmo número no workspace remoto Personal. Se a atualização da licença falhar, a migração operacional permanece concluída; use **Tentar atualizar licença novamente** ou a substituição de vínculo em **Instalações e licenças**.

A mudança não apaga conteúdo que alguém já tenha exportado ou chaves que já tenha obtido. Ela encerra o acesso futuro pelo Team.

## Garantias do servidor

A troca ocorre em uma transação que bloqueia ambos os workspaces e a supervisão WhatsApp. Verificações de proprietário, capacidade e chaves são repetidas dentro dessa transação. Uma falha mantém o acervo no Team; o número pode permanecer pausado, permitindo nova tentativa ou retomada.

`devices.archive_tenant_id` preserva o domínio criptográfico original. A autorização e o faturamento continuam usando `tenant_id`. Clientes devem utilizar o domínio anunciado em dispositivos, grants e chaves; os SDKs e CLIs desta versão já fazem isso. Atualize clientes antigos antes de abrir arquivos de um número movido.

Os objetos não são regravados. Cada workspace tem seu próprio registro de uso; um índice interno de proprietários físicos impede a exclusão de um objeto enquanto outro workspace ainda depende dele. O histórico de transferências registra autor, origem, destino e horário. Sequências de mensagens e eventos são realocadas sem modificar identificadores ou envelopes criptografados.

## Atualização e reversão

Pare os processos antigos de API, captura e manutenção antes de aplicar as migrações 36 e 37. Um coletor de objetos antigo não conhece os proprietários físicos compartilhados.

Mantenha backup do banco, objetos e artefatos anteriores. Depois de uma transferência, uma reversão de frontend pode manter o backend atual; não execute um backend anterior às migrações contra esse banco nem contorne a verificação de versão. Uma restauração completa precisa ser coordenada para preservar também as mensagens recebidas desde o backup.
