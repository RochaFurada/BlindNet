# Roteiro Granular do Site Interativo BlindNet

## Objetivo

Criar uma apresentacao interativa, acessivel pelo celular, que explique a BlindNet como uma arquitetura de seguranca em camadas. A experiencia deve comecar em uma rede IoT comum, mostrar os ataques possiveis, adicionar uma defesa por vez e terminar no prototipo real funcionando com Guardians, BLE, Action Pills, membrane, broker local e dispositivos IoT simples.

A pergunta central da apresentacao e:

> O que precisa ser verdade para um LED acender?

Na BlindNet, acender um LED deixa de ser apenas publicar `TOGGLE` em um topico MQTT. O comando precisa provar autoria, integridade, novidade, destino, segredo e permissao antes de chegar ao dispositivo.

## Mensagem Principal

BlindNet transforma uma rede IoT exposta em uma rede de intencoes verificaveis por Guardians.

O dispositivo IoT continua simples. Ele nao precisa entender assinatura, criptografia assimetrica, relay G2G, anti-replay ou politica de comandos. A complexidade de seguranca fica no Guardian.

## Como o Site Deve Ser Organizado

O site nao deve ser apenas uma pagina explicando conceitos. Ele deve parecer uma simulacao guiada:

1. Uma rede IoT comum aparece primeiro.
2. O usuario ativa ataques simples.
3. Uma camada de defesa entra em cena.
4. O site mostra o que aquela camada bloqueia.
5. O site mostra o que ainda continua vulneravel.
6. A proxima camada entra.
7. No final, resta principalmente o problema de disponibilidade, como bombardeamento BLE/DoS.

Controles sugeridos:

- `Atacar`
- `Adicionar camada`
- `Ver pacote`
- `Enviar Action Pill`
- `Mostrar por dentro`
- `Ver decisao do Guardian`
- `Ver o que ainda falha`

Cada tela deve responder quatro perguntas:

- O que esta acontecendo?
- Que ataque isso evita?
- Por que esse componente existe?
- O que ainda falta resolver?

## Glossario Visual

Esses termos devem aparecer como pecas clicaveis no site:

- `Guardian`: ESP32 que protege uma zona e decide se uma intencao pode virar comando.
- `Action Pill`: pacote completo enviado pelo usuario/app.
- `CP / Capsule Pill`: envelope publico e assinado da Action Pill.
- `AS / Active Substance`: conteudo criptografado da Action Pill, onde fica a intencao real.
- `Ribosome Table`: tabela local do Guardian com dispositivos, segredos e RNA/template.
- `Device Secret`: segredo simetrico usado pelo Guardian para abrir o AS de um dispositivo.
- `RNA/RNS Template`: perfil de comportamento permitido para uma classe de dispositivo.
- `Amino Acid`: verbo normalizado de comando, como `ON`, `OFF`, `TOGGLE`.
- `Membrane`: filtro final que decide se a intencao e permitida.
- `G2G`: comunicacao Guardian-to-Guardian via BLE.
- `Broker Local`: MQTT interno da zona, usado apenas depois da validacao.

Observacao: no firmware o nome usado e `RNA`. Se na apresentacao voce quiser chamar a camada de regras de `RNS`, o site pode mostrar como "RNA/RNS: a linguagem de permissoes da zona".

## Fluxo Macro

Fluxo que deve aparecer como trilha principal:

1. Usuario cria uma Action Pill.
2. Action Pill e enviada por BLE.
3. Guardian recebe fragmentos G2G.
4. Guardian verifica cache anti-replay.
5. Guardian repassa para outros Guardians se necessario.
6. Guardian valida assinatura do Capsule Pill.
7. Guardian tenta descriptografar Active Substance com os device secrets locais.
8. Guardian encontra o dispositivo certo no Ribosome.
9. Membrane verifica se o amino acid e permitido pelo RNA.
10. Guardian publica no broker MQTT local.
11. Dispositivo simples recebe e acende o LED.

Frase curta:

> A Action Pill nao diz apenas "acenda". Ela prova que merece chegar ate o LED.

## Etapa 1: Rede IoT Comum

### Cena

Um app publica `TOGGLE` em um broker MQTT. Uma lampada assina o topico e acende.

### Ataques demonstrados

- Scan encontra o dispositivo.
- Scan encontra broker e portas abertas.
- O topico MQTT pode ser inferido.
- Um atacante tenta publicar no mesmo topico.
- O dispositivo IoT precisa confiar demais na rede.

### Por que essa etapa existe

Ela mostra o problema original: em muitas redes IoT, descobrir a rede e se aproximar do controle sao quase a mesma coisa.

### Mensagem

Em uma rede comum, se o atacante entende topicos, broker e dispositivos, ele ja esta perto demais do comando.

## Etapa 2: Entrada do Guardian

### Cena

O dispositivo IoT sai da rede principal e passa a conectar no AP local do Guardian. O broker MQTT tambem fica local ao Guardian.

### Protecao adicionada

- O dispositivo real nao aparece diretamente na rede principal.
- O broker local fica atras do Guardian.
- O Guardian vira o ponto de decisao.
- A rede principal deixa de ser o lugar onde comandos sao aceitos diretamente.

### Ataques bloqueados

- Scan direto do dispositivo na rede principal.
- Tratar cada lampada como um pequeno servidor exposto.
- Publicar comandos diretamente no dispositivo pela rede principal.

### O que ainda falta

- Ainda e preciso proteger a entrada do Guardian.
- Ainda e preciso impedir comandos falsos.
- Ainda e preciso proteger a intencao do comando.

### Mensagem

O dispositivo sai do campo de batalha. O atacante passa a enxergar o Guardian, nao a logica real do dispositivo.

## Etapa 3: Por Que BLE Como Plano de Controle

### Cena

O site mostra tres caminhos possiveis para enviar comando ao Guardian:

- Rede local/IP.
- ESP-NOW.
- BLE/G2G.

O caminho BLE e escolhido como plano de controle.

### Por que nao rede local/IP

- Usar IP local aumenta a dependencia do roteador e da topologia da rede.
- Portas e servicos ficam mais faceis de sondar.
- O atacante pode misturar descoberta de rede com tentativa de controle.
- A rede local vira parte do caminho critico de comando.

### Por que nao ESP-NOW no prototipo principal

- ESP-NOW e forte entre ESPs, mas e mais especifico do ecossistema Espressif.
- E menos natural para interacao direta com celular/notebook comum.
- Depende mais do canal Wi-Fi e da coordenacao do radio.
- Para a demo, BLE e mais simples de usar como porta de entrada externa.

### Por que BLE

- BLE funciona como plano de controle separado do MQTT/IP.
- Permite descoberta de Guardians como caixas pretas.
- Funciona bem para pacotes pequenos e fragmentados.
- Permite GATT write para entregar fragmentos de Action Pill.
- Nao exige que o emissor esteja dentro do AP do Guardian.

### Limite honesto

BLE nao resolve disponibilidade sozinho. Ele ainda pode sofrer com ruido, disputa de radio e bombardeamento. Isso deve aparecer no final como trabalho futuro.

### Mensagem

BLE nao foi escolhido por ser magicamente mais seguro. Ele foi escolhido para separar o canal de intencao do canal local dos dispositivos.

## Etapa 4: Action Pill Como Unidade de Intencao

### Cena

O comando deixa de ser `TOGGLE` visivel e vira uma Action Pill.

Visualmente:

```text
Action Pill
├── CP: Capsule Pill
└── AS: Active Substance
```

### Por que Action Pill existe

Uma mensagem comum responde apenas "o que fazer". A Action Pill responde:

- Quem autorizou?
- Quando foi emitida?
- Ela ja foi vista?
- O conteudo foi alterado?
- Qual conteudo criptografado pertence a esse envelope?
- Qual Guardian consegue digerir?
- O comando final e permitido?

### Protecoes adicionadas

- O comando real nao trafega como texto simples.
- O pacote vira uma estrutura validavel.
- A intencao pode atravessar Guardians sem revelar o destino.
- O pacote pode ser rejeitado antes de executar qualquer comando.

### Mensagem

Action Pill e a intencao embalada como objeto de seguranca, nao como mensagem solta.

## Etapa 5: CP / Capsule Pill

### Cena

O usuario clica na Action Pill e abre o CP. O site mostra que o CP e a parte publica, verificavel e assinada.

### Por que CP existe

O CP existe para validar a casca da intencao sem revelar o comando real. Ele permite ao Guardian fazer verificacoes de integridade, autoria e replay antes de confiar no conteudo interno.

### O CP nao deve revelar

- Qual dispositivo exato sera acionado.
- Qual topico MQTT sera usado.
- Qual comando final sera executado.
- Qual payload real esta dentro.

### O CP deve revelar o minimo necessario

- Versao do protocolo.
- Classe generica da acao.
- Validade temporal.
- Hash do AS.
- Identidade da chave emissora.
- Assinatura.

### Mensagem

O CP e o lacre da capsula. Ele nao e o comando, mas prova que a capsula nao foi adulterada.

## Etapa 6: Campo por Campo do CP

### Tabela para o site

| Campo | Por que existe | O que evita |
| --- | --- | --- |
| `version` | Permite evoluir o protocolo e rejeitar formatos antigos/incompativeis. | Interpretar pacote errado como valido. |
| `flags` | Reserva comportamento futuro sem quebrar o formato. | Mudancas bruscas no protocolo. |
| `action_class` | Diz a classe geral, como MQTT/GPIO/POLICY, sem revelar a intencao final. | Expor detalhes do comando cedo demais. |
| `issued_ms` | Marca quando a Action Pill foi emitida. | Pacotes sem contexto temporal. |
| `expires_ms` | Define uma janela de validade. | Reuso tardio de comandos antigos. |
| `network_id` | Campo de escopo/zona/rede para contextualizar a Action Pill. | Misturar intencoes de contextos diferentes. |
| `nonce` | Valor unico por pacote. | Repeticao e colisao de mensagens. |
| `active_hash` | Hash do Active Substance. | Trocar o conteudo criptografado depois da assinatura. |
| `issuer_key_id` | Identifica qual chave publica deve validar a assinatura. | Usar uma chave errada ou desconhecida. |
| `signature_alg` | Informa o algoritmo de assinatura usado. | Ambiguidade criptografica. |
| `signature_len` | Define o tamanho real da assinatura DER. | Ler bytes invalidos ou lixo de memoria. |
| `signature` | Prova assimetrica de autoria sobre o CP. | Forjar comando sem a chave privada. |
| `reserved` | Mantem alinhamento e espaco de evolucao. | Quebrar compatibilidade a cada mudanca. |

### Nota sobre `network_id`

No site, o `network_id` deve ser explicado como campo de escopo. Ele nao precisa ser vendido como a unica barreira de seguranca. A seguranca principal vem de assinatura, hash do AS, anti-replay, device secret e membrane.

### Mensagem

Cada campo do CP existe para impedir uma classe especifica de confusao, adulteracao ou falsificacao.

## Etapa 7: AS / Active Substance

### Cena

O usuario abre o AS e ve apenas um bloco opaco: nonce, tag e ciphertext. O comando real fica escondido.

### Por que AS existe

O AS existe porque a assinatura prova autoria, mas nao deve necessariamente expor a intencao. A intencao real precisa ficar criptografada ate chegar em um Guardian que tenha o `device_secret` correto.

### O que fica dentro do AS quando aberto

- `device_id`: identificador do dispositivo logico.
- `topic`: topico MQTT local que o Guardian vai publicar.
- `amino_id`: verbo normalizado, como `TOGGLE`.
- `payload_type`: tipo de payload.
- `payload_i32`: valor numerico quando necessario.

### Protecoes adicionadas

- Confidencialidade da intencao.
- Separacao entre transporte e execucao.
- Guardian errado pode receber, mas nao consegue digerir.
- O dispositivo final nao precisa guardar o segredo.

### Mensagem

O AS e o principio ativo da capsula. Ele so faz efeito no Guardian que possui a enzima certa: o device secret.

## Etapa 8: Campo por Campo do AS

### Envelope criptografado

| Campo | Por que existe | O que evita |
| --- | --- | --- |
| `version` | Permite evoluir o formato do AS. | Descriptografar usando regra errada. |
| `cipher` | Indica o algoritmo, como AES-GCM. | Ambiguidade no modo criptografico. |
| `ciphertext_len` | Diz o tamanho real do conteudo criptografado. | Ler bytes extras ou truncados. |
| `nonce` | Valor unico usado na criptografia autenticada. | Reuso perigoso de cifra com mesmo segredo. |
| `tag` | Tag de autenticacao do AEAD. | Alterar ciphertext sem ser detectado. |
| `ciphertext` | Conteudo real criptografado. | Expor device, topico e comando. |

### Plaintext interno depois de abrir

| Campo | Por que existe | O que evita |
| --- | --- | --- |
| `device_id` | Aponta o dispositivo logico desejado. | Comando sem destino claro. |
| `topic` | Define onde publicar no broker local. | Publicacao arbitraria sem controle. |
| `amino_id` | Usa verbo normalizado em vez de string livre. | Comandos inventados ou ambiguos. |
| `payload_type` | Diz se o comando tem valor, booleano ou nada. | Interpretar payload errado. |
| `payload_i32` | Carrega valor para comandos como nivel, velocidade ou temperatura. | Usar payload fora do formato esperado. |
| `reserved` | Espaco para evolucao e alinhamento. | Quebrar compatibilidade. |

### Mensagem

O AS esconde a intencao e tambem padroniza o que uma intencao pode ser.

## Etapa 9: Por Que Separar CP e AS

### Cena

O site mostra uma Action Pill sendo interceptada. O atacante consegue ver o CP, mas nao consegue abrir o AS.

### Motivo da separacao

CP e AS resolvem problemas diferentes:

- CP responde: "esta capsula e autentica e integra?"
- AS responde: "qual e a intencao real e para quem ela serve?"

### Beneficio

Um Guardian pode:

- Rejeitar replay cedo.
- Repassar a Action Pill sem entender o conteudo.
- Validar assinatura antes de executar.
- Tentar digerir apenas quando for necessario.

### Ataque bloqueado

Sem separacao, o sistema tenderia a expor tudo cedo demais ou a exigir que todo Guardian abrisse tudo.

### Mensagem

O CP permite confiar na capsula. O AS impede que a intencao vaze.

## Etapa 10: Assinatura do Dono

### Cena

O Guardian usa a chave publica do dono para validar a assinatura da Action Pill.

### Protecao adicionada

- Assinatura assimetrica.
- Chave privada fica com o emissor/dono.
- Chave publica fica no Guardian.
- A assinatura cobre o conteudo relevante do CP, incluindo o hash do AS.

### Ataques bloqueados

- Criar uma Action Pill falsa.
- Alterar campos do CP.
- Trocar o AS por outro conteudo.
- Se passar pelo dono sem possuir a chave privada.

### O que ainda resta

- Reenviar um pacote autentico capturado.
- Tentar negar servico por volume.

### Mensagem

Nao basta falar com o Guardian. E preciso provar autoria criptografica.

## Etapa 11: Cache Anti-Replay

### Cena

O atacante captura uma Action Pill valida e tenta enviar de novo.

### Protecao adicionada

- O Guardian calcula um digest/id da capsula.
- O cache registra mensagens ja vistas.
- Se o pacote ja passou, ele nao e processado de novo.

### Por que vem cedo no fluxo

O cache e barato comparado com descriptografar e validar toda a intencao. Por isso ele deve acontecer antes do trabalho pesado.

### Ataques bloqueados

- Repetir comando antigo.
- Fazer loop infinito entre Guardians.
- Reprocessar a mesma Action Pill varias vezes.

### Mensagem

Mesmo uma mensagem verdadeira perde autoridade depois que ja foi usada.

## Etapa 12: Relay G2G Antes da Digestao Pesada

### Cena

O usuario envia a Action Pill para o Guardian errado. Esse Guardian nao sabe se a intencao e dele, entao repassa para os peers G2G antes de fazer o trabalho pesado local.

### Fluxo desejado

1. Recebe fragmentos.
2. Monta a Action Pill.
3. Verifica cache.
4. Se nao viu antes, coloca no cache.
5. Repassa via G2G.
6. Depois tenta validar/digerir localmente.

### Por que essa ordem existe

Se o Guardian gastar tempo descriptografando antes de repassar, o relay fica lento. Em uma rede com mais de um Guardian, isso gera instabilidade e atraso perceptivel.

### Ataques reduzidos

- Loop entre Guardians.
- Reenvio duplicado.
- Atraso excessivo quando o primeiro Guardian nao e o dono do dispositivo.

### Mensagem

Primeiro a rede espalha a intencao uma vez. Depois cada Guardian decide se consegue digerir.

## Etapa 13: Fragmentacao BLE e G2G

### Cena

A Action Pill aparece quebrada em fragmentos BLE.

### Por que fragmentar

BLE/GATT tem limite pratico de tamanho por escrita. A Action Pill completa precisa ser dividida.

### O que cada fragmento precisa carregar

- Identificador da mensagem.
- Tamanho total.
- Offset.
- Indice do fragmento.
- Total de fragmentos.
- Payload parcial.

### Protecoes/logicas

- O Guardian so monta a mensagem quando todos os fragmentos chegam.
- Fragmentos duplicados podem ser ignorados.
- O cache evita que uma Action Pill completa rode duas vezes.
- O relay deve evitar devolver a mensagem para o peer de origem imediatamente.

### Limite atual

BLE ainda e sensivel a concorrencia entre inbound e outbound. A correcao atual melhora o fluxo, mas a camada futura de anti-DoS pode filtrar ruido antes da conexao.

### Mensagem

G2G nao transporta comando aberto. Transporta uma capsula opaca em pedacos.

## Etapa 14: Ribosome Table

### Cena

O Guardian abre sua tabela local de dispositivos cadastrados.

### Por que Ribosome existe

O Ribosome e a memoria local da zona. Ele diz:

- Quais dispositivos existem naquele Guardian.
- Qual `device_secret` usar.
- Qual RNA/template define o comportamento permitido.
- Qual epoch/versao do segredo esta valendo.

### Campo por campo

| Campo | Por que existe | O que evita |
| --- | --- | --- |
| `mqtt_client_id` | Identifica o cliente MQTT local, como `lamp01`. | Publicar para dispositivo desconhecido. |
| `template_id` | Liga o dispositivo a um RNA/template. | Uma lampada aceitar comando de fechadura ou ar-condicionado. |
| `epoch` | Versao do segredo/configuracao. | Misturar configuracoes antigas e novas. |
| `device_secret` | Segredo simetrico usado para abrir o AS. | Guardian sem permissao descobrir/executar a intencao. |

### Decisao importante

O `device_secret` fica no Guardian, nao no dispositivo IoT. O app usa esse segredo para criptografar o AS, e o Guardian usa para descriptografar. O dispositivo final continua simples.

### Mensagem

O Ribosome e onde o Guardian sabe quais intencoes ele e capaz de digerir.

## Etapa 15: Active Enzyme / Descriptografia

### Cena

O Guardian tenta abrir o AS usando cada entrada do Ribosome ate encontrar o segredo correto.

### Por que isso existe

O Guardian nao precisa saber antes qual dispositivo esta dentro da Action Pill. Ele tenta digerir com os segredos locais. Se nenhum funciona, provavelmente aquela Action Pill pertence a outro Guardian.

### Protecoes adicionadas

- Guardian errado nao abre o AS.
- A intencao continua opaca durante o relay.
- A tag AEAD detecta adulteracao.
- O device secret separa dispositivos entre si.

### Ataques bloqueados

- Capturar Action Pill e ler comando.
- Alterar ciphertext sem invalidar a tag.
- Fazer um Guardian sem o segredo executar a intencao.

### Mensagem

O Guardian certo nao e escolhido por endereco. Ele se revela porque consegue abrir a intencao.

## Etapa 16: Amino Acids

### Cena

Depois de descriptografar, o site mostra que o comando nao e uma string livre. Ele e um amino acid.

### Por que Amino Acids existem

Eles normalizam comandos. Em vez de aceitar qualquer texto, a BlindNet trabalha com verbos controlados:

- `ON`
- `OFF`
- `TOGGLE`
- `OPEN`
- `CLOSE`
- `LOCK`
- `UNLOCK`
- `SET_SPEED`
- `SET_LEVEL`
- `SET_TEMPERATURE`
- `SET_MODE`
- `READ_STATE`

### Campo por campo

| Campo | Por que existe | O que evita |
| --- | --- | --- |
| `id` | Identidade numerica do verbo. | Ambiguidade de string. |
| `name` | Nome humano para interface/admin. | Configuracao incompreensivel. |
| `value_type` | Diz se precisa de valor, bool, int ou nada. | Payload invalido. |
| `flags` | Marca se muda estado ou e somente leitura. | Tratar leitura como acao perigosa. |

### Ataques bloqueados

- Enviar comando inventado.
- Enviar payload onde nao deve.
- Confundir `READ_STATE` com comando que altera estado.

### Mensagem

BlindNet nao deixa qualquer frase virar comando. Ela reduz comandos a verbos conhecidos.

## Etapa 17: RNA / RNS Templates

### Cena

O site mostra perfis de dispositivos:

- `LIGHT_SWITCH`
- `OUTLET`
- `DOOR`
- `AIR_CONDITIONER`
- `DIMMER`
- `FAN`
- `SENSOR_READONLY`

Cada perfil permite um conjunto de amino acids.

### Por que RNA/RNS existe

O RNA e o molde biologico da permissao. Ele define quais amino acids fazem sentido para cada tipo de dispositivo.

Exemplos:

- Lampada pode receber `ON`, `OFF`, `TOGGLE`, `READ_STATE`.
- Sensor somente leitura pode receber `READ_STATE`.
- Porta pode receber `OPEN`, `CLOSE`, `LOCK`, `UNLOCK`.
- Dimmer pode receber `SET_LEVEL`.

### Campo por campo

| Campo | Por que existe | O que evita |
| --- | --- | --- |
| `id` | Identifica o template. | Confundir classes de dispositivo. |
| `name` | Nome legivel no admin/site. | Configuracao obscura. |
| `amino_count` | Quantos comandos sao permitidos. | Ler lista alem do limite. |
| `aminos` | Lista de verbos permitidos. | Dispositivo aceitar comando fora da natureza dele. |
| `flags` | Espaco para regras futuras. | Quebrar evolucao da politica. |

### Mensagem

O RNA impede que uma intencao valida vire uma acao absurda para aquele dispositivo.

## Etapa 18: Membrane

### Cena

A Action Pill ja foi assinada, nao e replay, foi descriptografada, encontrou o dispositivo, mas ainda precisa atravessar a Membrane.

### Por que Membrane existe

Criptografia prova que a mensagem e legitima. Membrane prova que ela e permitida naquele contexto.

### Verificacoes

- O dispositivo existe no Ribosome.
- O `device_id`/cliente local faz sentido.
- O topico e permitido.
- O amino acid pertence ao RNA/template do dispositivo.
- O payload combina com o tipo esperado.

### Ataques bloqueados

- Comando assinado, mas fora da politica.
- Lampada recebendo comando de porta.
- Sensor recebendo comando que altera estado.
- Publicacao arbitraria em topico MQTT local.

### Mensagem

Descriptografar nao significa executar. A intencao ainda precisa passar pela membrana da zona.

## Etapa 19: Broker MQTT Local

### Cena

So depois de todas as validacoes o Guardian publica no broker local. O dispositivo IoT recebe o comando e acende o LED.

### Por que broker local existe

- Mantem compatibilidade com IoT simples.
- Permite usar firmware Arduino simples no dispositivo final.
- Separa o mundo seguro do Guardian do mundo simples do dispositivo.
- Evita colocar toda a criptografia no dispositivo pequeno.

### Ataques bloqueados

- Injetar comando direto pela rede principal.
- Fazer o dispositivo final carregar toda a responsabilidade de seguranca.

### Mensagem

O LED e simples de proposito. A cadeia dificil acontece antes dele.

## Etapa 20: Modo Admin e Cadastro de Dispositivo

### Cena

O usuario segura o botao, o Guardian abre o modo admin temporario, o dono resolve o challenge e cadastra o dispositivo.

### Por que modo admin existe

Configuracao e uma operacao sensivel. Ela nao deve ficar sempre aberta.

### Fluxo

1. Usuario segura o botao fisico.
2. Guardian muda para modo admin temporario.
3. Usuario conecta no AP admin.
4. Guardian entrega um challenge.
5. Usuario assina com a chave privada.
6. Guardian valida com a chave publica.
7. Interface admin e liberada.
8. Usuario cadastra dispositivo, secret e RNA/template.
9. Guardian salva e retorna ao modo normal.

### Protecoes

- Admin nao fica aberto permanentemente.
- Challenge evita senha simples como unica prova.
- Assinatura prova posse da chave privada.
- Configuracao entra no Ribosome/RNA.

### Mensagem

Administrar a zona tambem exige prova de identidade, nao so estar conectado na rede.

## Etapa 21: Ofuscacao de Dispositivos

### Cena

Um atacante faz scan. O site deve mostrar que ele nao encontra diretamente as lampadas reais como pontos de controle.

### Como a BlindNet dificulta sondagem

- Dispositivo IoT fica atras do AP do Guardian.
- Broker local nao e autoridade de seguranca.
- Comando real nao aparece em texto.
- Topico real fica dentro do AS criptografado.
- Guardian errado pode receber e repassar sem revelar destino.

### O que isso nao promete

Nao e invisibilidade perfeita. E reducao de superficie e separacao entre descoberta e controle.

### Mensagem

O atacante pode perceber que existe atividade, mas transformar essa visibilidade em controle fica muito mais dificil.

## Etapa 22: Ofuscacao de Topologia

### Cena

O usuario envia uma Action Pill para um Guardian e outro Guardian executa. O site mostra que o emissor nao precisou conhecer o caminho completo.

### Beneficio

- O app nao precisa saber qual Guardian controla cada dispositivo.
- O primeiro Guardian pode ser apenas porta de entrada.
- A Action Pill viaja opaca pela malha G2G.
- O Guardian correto se revela pela capacidade de abrir o AS.

### Ataques dificultados

- Mapear diretamente dispositivo para Guardian.
- Inferir topologia apenas observando o primeiro envio.
- Saber qual zona contem qual segredo.

### Mensagem

A rede nao precisa expor o mapa inteiro para entregar uma intencao.

## Etapa 23: O Que a BlindNet Bloqueia Hoje

### Painel de resultado

Mostrar uma lista com ataques e status:

| Ataque | Resultado |
| --- | --- |
| Publicar MQTT direto na rede principal | Bloqueado pela arquitetura com Guardian. |
| Descobrir dispositivo por scan simples | Dificultado pela ofuscacao atras do Guardian. |
| Ler comando capturado | Bloqueado pelo AS criptografado. |
| Alterar Action Pill | Bloqueado por hash + assinatura/tag. |
| Forjar comando sem chave privada | Bloqueado pela assinatura assimetrica. |
| Reenviar Action Pill antiga | Bloqueado pelo cache anti-replay. |
| Executar em Guardian errado | Bloqueado pela falta do device secret. |
| Enviar comando fora do tipo do dispositivo | Bloqueado por RNA/Membrane. |
| Mandar payload invalido | Bloqueado por amino/value type. |

### Mensagem

A BlindNet combina autenticidade, integridade, confidencialidade, anti-replay, autorizacao local e ofuscacao de topologia.

## Etapa 24: O Que Ainda Resta Vulneravel

### Cena

O atacante nao consegue forjar comando valido, entao tenta negar servico.

### Risco restante

- Bombardeamento BLE.
- Disputa de radio.
- Ocupacao de conexoes.
- Fila cheia.
- Interferencia fisica.

### Por que isso e diferente

Ataque de controle e ataque de disponibilidade sao coisas diferentes:

- Controle: atacante muda estado do dispositivo.
- Disponibilidade: atacante tenta impedir que comandos legitimos cheguem.

No prototipo atual, a cadeia de controle e forte. O ponto futuro e endurecer disponibilidade.

### Trabalho futuro

- Handshake leve antes de aceitar trafego caro.
- Identidade efemera.
- Filtro rapido por janela temporal.
- Prioridade entre inbound e outbound.
- Rotacao verificavel de aparencia BLE.
- Cotas e backoff por origem.

### Mensagem

Hoje o atacante tende a sobrar com DoS. Ele nao consegue simplesmente virar dono da rede.

## Demonstracao Real

### Cenario ideal

1. Dois Guardians ligados.
2. Dois dispositivos IoT simples com LED.
3. Cada dispositivo conectado no AP de seu Guardian.
4. Cada dispositivo conectado ao broker local.
5. Um comando enviado por BLE.
6. Um caso direto acende o LED do Guardian que recebeu.
7. Um caso indireto acende LED no outro Guardian via G2G.

### Frase para a demo

Parece apenas um LED acendendo. Mas esse LED so acende depois de passar por BLE, fragmentacao, cache, relay G2G, assinatura, Active Substance, Ribosome, Membrane e MQTT local.

### Momento visual forte

Mostrar o log ou animacao com:

```text
fragment accepted
message complete
relay queued
capsule authorized
digest start
ribosome match
membrane allowed
mqtt publish
LED ON
```

### Mensagem

O resultado visivel e simples. A cadeia por tras e o projeto.

## Portal de Transparencia Sobre IA

### Objetivo

Transformar o uso de IA em algo auditavel, visual e responsavel, nao em uma frase generica de rodape.

O portal deve mostrar:

- Onde IA foi usada.
- Onde ela errou.
- Onde o humano tomou a decisao.
- Quais prompts levaram a quais partes do projeto.
- O que foi validado em hardware real.
- O que nao pode ser creditado a IA porque dependeu de teste fisico, julgamento arquitetural e persistencia de engenharia.

### Ideia central

Em vez de dizer apenas "usei IA", o portal mostra o processo.

Frase de abertura:

> Este projeto foi desenvolvido com IA como ferramenta de engenharia assistida. Por isso, eu disponibilizo o historico, as categorias de uso e as decisoes humanas para que qualquer pessoa consiga entender como a ferramenta participou do processo.

### Secao 1: Mapa de Participacao

Visual sugerido:

- Grafico em barras ou radar com categorias.
- Cada categoria mostra intensidade de apoio da IA e intensidade de decisao humana.

Categorias:

| Categoria | Papel da IA | Papel humano |
| --- | --- | --- |
| Arquitetura | Debateu riscos, alternativas e trade-offs. | Definiu a ideia central, escolheu o modelo Guardian/Action Pill e decidiu o que entrava. |
| Firmware ESP-IDF | Ajudou a interpretar erros, sugerir imports, ajustar CMake e revisar logs. | Compilou, testou em hardware real e decidiu quais correcoes aceitar. |
| Criptografia | Ajudou a organizar assinatura, hash, AS, CP e scripts de teste. | Definiu o objetivo de seguranca e validou a cadeia funcionando no ESP. |
| BLE/G2G | Ajudou a depurar fragmentacao, relay e concorrencia inbound/outbound. | Testou com multiplos Guardians reais e observou falhas fisicas. |
| Admin/Membrane | Ajudou a estruturar telas, cadastro e modelos de permissao. | Definiu a experiencia, cadastrou dispositivos e validou persistencia. |
| Apresentacao | Ajudou a transformar a arquitetura em narrativa visual. | Selecionou o que mostrar, o tom e a estrategia de demonstracao. |

### Secao 2: Linha do Tempo dos Prompts

Visual sugerido:

- Timeline horizontal ou vertical.
- Cada bloco representa uma fase real do projeto.
- Ao clicar, abre um conjunto de prompts relacionados.

Fases:

1. `Build e imports`: erros de CMake, mbedTLS, NimBLE, componentes IDF.
2. `Action Pill`: criacao de chaves, assinatura, CP, AS, envio por BLE.
3. `Admin seguro`: setup button, challenge assinado, AP temporario.
4. `Membrane`: Ribosome, device secret, RNA, amino acids.
5. `Broker e dispositivo IoT`: ESP Arduino, MQTT local, LED.
6. `G2G`: descoberta BLE, relay entre Guardians, cache, estabilidade.
7. `Demo`: logs reais, interpretacao de falhas, roteiro e site.

Cada item da timeline deve ter:

- Problema inicial.
- Prompt ou trecho de prompt.
- Resposta/hipotese da IA.
- Decisao tomada.
- Resultado no hardware.

### Secao 3: Biblioteca de Prompts

Esta e a parte que pode gerar o "UAU".

Formato sugerido para cada prompt:

```text
Prompt real:
"...texto do prompt..."

Contexto:
O que estava quebrado ou sendo projetado naquele momento.

Resposta util:
Qual parte da resposta ajudou.

Resposta rejeitada ou corrigida:
O que nao foi aceito, nao funcionou ou precisou ser mudado.

Decisao humana:
Por que a solucao final foi escolhida.

Evidencia:
Log, commit, teste fisico, print ou comportamento observado no ESP.
```

Filtros:

- `Build`
- `Criptografia`
- `BLE`
- `G2G`
- `Admin`
- `Membrane`
- `MQTT`
- `Apresentacao`
- `Erros da IA`
- `Decisoes humanas`

### Secao 4: Grafo de Ideias

Visual sugerido:

- Grafo interativo com nos.
- Um no central: `BlindNet`.
- Ramos: `Guardian`, `Action Pill`, `CP`, `AS`, `Ribosome`, `RNA`, `Amino Acids`, `Membrane`, `G2G`, `Admin`.
- Cada no tem origem:
  - `Ideia humana`
  - `Refinada com IA`
  - `Depurada com IA`
  - `Validada em hardware`

Exemplo:

```text
Action Pill
├── CP: refinado com IA, validado em firmware
├── AS: refinado com IA, validado com device_secret
└── BLE sender: implementado/testado com apoio de IA
```

### Secao 5: Matriz de Responsabilidade

O objetivo e deixar claro que IA ajudou, mas nao "foi a autora sozinha".

| Parte | IA sugeriu | Humano decidiu | Hardware validou |
| --- | --- | --- | --- |
| CP/AS | Sim | Sim | Sim |
| Device secret no Guardian | Debateu consequencias | Sim | Sim |
| Retirar network_id como trava principal | Ajudou a analisar logs | Sim | Sim |
| Relay G2G | Ajudou a depurar | Sim | Sim |
| Arduino do LED | Ajudou a escrever base | Sim | Sim |
| Portal de transparencia | Ajudou a organizar | Sim | Nao se aplica |

### Secao 6: Erros, Frustracoes e Correcoes

Essa secao e importante porque aumenta a credibilidade.

Mostrar exemplos de momentos em que:

- A IA sugeriu algo que quebrou a build.
- A IA adicionou logs de forma errada e causou erro de linkage.
- Uma correcao parecia certa, mas gerou stack overflow.
- Uma hipotese sobre `network_id` nao bateu com o ESP real.
- O teste fisico mostrou que o fluxo G2G precisava mudar.

Mensagem:

> A IA acelerou o processo, mas nao substituiu validacao. Quando a resposta nao batia com o hardware, o hardware venceu.

### Secao 7: Redacoes e Cuidados

Como os prompts reais podem conter dados sensiveis, o portal deve ter um modo de publicacao responsavel.

Remover ou mascarar:

- Senhas Wi-Fi.
- Chaves privadas.
- Device secrets reais, se ainda forem usados.
- Enderecos MAC que voce nao queira expor.
- Caminhos pessoais se forem desnecessarios.
- Logs com informacoes privadas da rede.

Manter:

- Erros tecnicos.
- Decisoes arquiteturais.
- Perguntas feitas.
- Trechos de logs relevantes.
- Evidencia de teste em ESP real.

### Secao 8: Numeros do Processo

Visual sugerido:

- Cards com metricas.

Exemplos:

- `X` prompts trocados.
- `Y` categorias de problema.
- `Z` erros de build resolvidos.
- `N` subsistemas integrados.
- `2+` Guardians testados.
- `1` fluxo completo: app -> BLE -> Guardian -> G2G -> Membrane -> MQTT -> LED.

Esses numeros podem ser preenchidos depois, quando os prompts forem exportados.

### Secao 9: Declaracao Final de Transparencia

Texto sugerido:

> Este projeto nao tenta esconder o uso de IA. Pelo contrario: ele mostra como uma ferramenta de IA pode participar de um processo real de engenharia, com erros, revisoes, testes fisicos e decisoes humanas. O valor do projeto esta na arquitetura criada, na integracao dos subsistemas, na validacao em ESPs reais e na responsabilidade de documentar o processo.

## Frases-Chave

- Acender o LED e facil. Dificil e provar que o comando merece chegar ate ele.
- A BlindNet protege a intencao antes de proteger o dispositivo.
- O dispositivo IoT nao precisa ser inteligente sozinho; ele fica atras de um Guardian.
- O broker MQTT existe, mas nao e a autoridade de seguranca.
- O atacante pode ver trafego, mas nao consegue transformar visibilidade em controle.
- A rede nao transporta apenas comandos. Ela transporta comandos verificaveis.
- CP prova a capsula. AS esconde a intencao.
- O Guardian certo e aquele que consegue digerir a Action Pill.
- A membrane impede que autenticidade vire permissao absoluta.
- O prototipo nao promete invencibilidade. Ele reduz dramaticamente o caminho entre visibilidade e controle.

## Checklist de Conteudos Importantes

- [ ] Rede IoT comum e riscos.
- [ ] Guardian como fronteira de seguranca.
- [ ] Dispositivo atras do AP do Guardian.
- [ ] Por que BLE foi escolhido.
- [ ] Por que nao rede local/IP como controle principal.
- [ ] Por que nao ESP-NOW como entrada principal do prototipo.
- [ ] Action Pill como unidade de intencao.
- [ ] CP / Capsule Pill.
- [ ] Campo por campo do CP.
- [ ] AS / Active Substance.
- [ ] Campo por campo do AS.
- [ ] Separacao entre CP e AS.
- [ ] Assinatura assimetrica.
- [ ] Cache anti-replay.
- [ ] Fragmentacao BLE.
- [ ] Relay G2G.
- [ ] Ribosome Table.
- [ ] Device secret no Guardian.
- [ ] Active enzyme / descriptografia.
- [ ] Amino acids.
- [ ] RNA/RNS templates.
- [ ] Membrane.
- [ ] Broker MQTT local.
- [ ] Modo admin com challenge assinado.
- [ ] Ofuscacao de dispositivos.
- [ ] Ofuscacao de topologia.
- [ ] Ataque DoS como limite atual.
- [ ] Demonstracao fisica.
- [ ] Painel de transparencia sobre IA.

## Possivel Encerramento

BlindNet e um prototipo de arquitetura para seguranca IoT onde dispositivos simples ficam protegidos por Guardians que validam identidade, intencao, destino e permissao antes de qualquer comando ser executado.

O resultado visivel e um LED acendendo. O resultado tecnico e uma cadeia de seguranca funcionando em hardware real: assinatura, criptografia, anti-replay, relay, digestao local, membrane e publicacao controlada.
