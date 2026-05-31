# BlindNet Presentation

Apresentação interativa da arquitetura BlindNet, criada para explicar de forma visual uma proposta de segurança para redes IoT locais.

A apresentação está disponível em: https://blind-net.vercel.app/

## Visão geral

A BlindNet organiza dispositivos IoT atrás de Guardians locais. Em vez de expor lâmpadas, sensores, fechaduras ou outros dispositivos diretamente na rede principal, cada Guardian cria uma fronteira própria, valida comandos assinados, filtra a semântica permitida e publica apenas comandos autorizados em um broker MQTT local.

Este repositório contém apenas a camada de apresentação do projeto. Ele foi separado do firmware e dos scripts de demonstração para permitir deploy estático, revisão visual e compartilhamento controlado.

## O que a apresentação cobre

A narrativa visual percorre as principais camadas da BlindNet:

- Setup inicial do Guardian.
- Modo admin e cadastro de dispositivos.
- Guardian como fronteira de rede protegida.
- Estrutura da Action Pill, separando Capsule Pill e Active Substance.
- Assinatura assimétrica, nonce, expiração e cache anti-replay.
- Stomach como etapa de remontagem, digestão e decisão inicial.
- Ribosome Table, Active Enzyme e Membrane como pipeline de autorização.
- RNA e Amino Acids como linguagem semântica dos dispositivos.
- Device secret como chave local para descriptografar o Active Substance.
- Publicação final no núcleo MQTT local.
- Relay G2G entre Guardians usando BLE.
- Painel de transparência sobre o uso de IA no desenvolvimento.

## Estrutura do projeto

```text
Presentation/
├── Diagramas/                 # Diagramas principais usados nos slides
│   ├── configs/               # Diagramas de setup e modo admin
│   └── IA/                    # Diagramas de transparência sobre apoio de IA
├── src/
│   ├── main.ts                # Conteúdo dos slides e lógica de navegação
│   └── styles.css             # Layout responsivo e identidade visual
├── index.html                 # Entrada do Vite
├── package.json               # Scripts do projeto
└── README.md                  # Documentação principal
```

## Tecnologias

- Vite para build e desenvolvimento local.
- TypeScript para organizar a apresentação.
- CSS responsivo com foco em dispositivos móveis em modo paisagem.
- Diagramas bitmap gerados e organizados para leitura em tela cheia.
- Deploy estático pela Vercel.

## Como rodar localmente

Instale as dependências:

```bash
npm install
```

Inicie o servidor de desenvolvimento:

```bash
npm run dev
```

O Vite exibirá uma URL local. Para testar em celular, use a URL de rede gerada pelo Vite e mantenha o celular na mesma rede do computador.

## Build de produção

```bash
npm run build
```

O resultado será gerado na pasta `dist/`.

Para visualizar o build localmente:

```bash
npm run preview
```

## Deploy na Vercel

Configuração recomendada:

- Framework Preset: Vite.
- Build Command: `npm run build`.
- Output Directory: `dist`.
- Install Command: `npm install`.

O deploy publicado está em:

https://blind-net.vercel.app/

## Decisões de apresentação

A interface foi desenhada para funcionar como uma apresentação navegável:

- Cada diagrama ocupa uma página horizontal.
- O usuário avança lateralmente entre as etapas.
- Os detalhes aparecem abaixo do diagrama de cada slide.
- Em celulares, a experiência principal foi pensada para modo paisagem.
- A apresentação não inclui backend, ponte BLE, scripts de teste ou segredos de dispositivos.

## Transparência sobre IA

O projeto inclui uma seção dedicada ao uso de IA como ferramenta auditável. A proposta é deixar claro onde a IA apoiou o desenvolvimento, sem substituir a autoria das decisões arquiteturais, da integração em hardware, dos testes práticos e da validação do sistema.

A IA foi usada como apoio em atividades como:

- Organização de ideias e roteiro técnico.
- Apoio na escrita e revisão de código.
- Depuração de erros de build, firmware e integração.
- Criação e refinamento de diagramas explicativos.
- Estruturação da apresentação interativa.

As decisões de arquitetura, os testes nos ESPs, a integração entre Guardians, o cadastro dos dispositivos e a validação física da demonstração foram conduzidos e verificados no ambiente real do projeto.

## Escopo deste repositório

Este repositório contém apenas a apresentação visual da BlindNet. Ele não contém:

- Firmware dos Guardians.
- Scripts de envio de Action Pills.
- Chaves privadas.
- Device secrets reais.
- Ponte local de demonstração.
- Arquivos gerados durante testes com BLE ou MQTT.

Essa separação reduz risco de vazamento e deixa o deploy público ou privado focado apenas na comunicação visual da arquitetura.

## Status

Versão de apresentação acadêmica e demonstração visual. O objetivo é explicar a arquitetura, seus componentes e suas camadas de segurança de forma acessível para professores, avaliadores e visitantes.
