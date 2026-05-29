import "./styles.css";

type Layer = {
  title: string;
  short: string;
  threat: string;
  blocks: string;
  remaining: string;
  badge: string;
  mapState: "plain" | "guardian" | "pill" | "relay" | "safe";
};

type PillTab = "cp" | "as" | "why";

type PillField = {
  name: string;
  purpose: string;
  blocks: string;
};

type TimelineItem = {
  phase: string;
  problem: string;
  prompt: string;
  decision: string;
  evidence: string;
};

const layers: Layer[] = [
  {
    title: "Rede IoT comum",
    short: "App, broker e dispositivo ficam próximos demais. Descobrir a rede quase vira descobrir o controle.",
    threat: "Scan encontra broker, tópico e dispositivo. Um atacante tenta publicar TOGGLE.",
    blocks: "Nada ainda.",
    remaining: "Publicação falsa, leitura de tráfego, sondagem e replay.",
    badge: "risco alto",
    mapState: "plain",
  },
  {
    title: "Guardian na fronteira",
    short: "O dispositivo sai da rede principal e passa a viver atrás do AP do Guardian.",
    threat: "Atacante não encontra mais a lâmpada como alvo direto na rede principal.",
    blocks: "Scan direto do dispositivo e comando IP/MQTT externo simples.",
    remaining: "Ainda é preciso proteger a entrada do Guardian.",
    badge: "fronteira",
    mapState: "guardian",
  },
  {
    title: "BLE como plano de controle",
    short: "A intenção entra por BLE/G2G, separada do broker local e da rede IP dos dispositivos.",
    threat: "Rede local deixa de ser o caminho direto de comando.",
    blocks: "Dependência de portas locais e exposição do broker como entrada pública.",
    remaining: "BLE ainda pode sofrer disputa de rádio e DoS.",
    badge: "controle",
    mapState: "guardian",
  },
  {
    title: "Action Pill",
    short: "O comando vira uma cápsula: CP assinado por fora, AS criptografado por dentro.",
    threat: "Pacote interceptado não revela tópico, device_id ou verbo real.",
    blocks: "Leitura direta da intenção e alteração simples do comando.",
    remaining: "Ainda precisa validar autoria e replay.",
    badge: "opaco",
    mapState: "pill",
  },
  {
    title: "Assinatura e anti-replay",
    short: "O Guardian exige chave privada do dono e rejeita mensagens que já foram vistas.",
    threat: "Atacante tenta forjar ou reenviar uma Action Pill capturada.",
    blocks: "Falsificação sem chave privada, troca do AS e replay.",
    remaining: "Ainda falta saber se este Guardian consegue digerir o AS.",
    badge: "autêntico",
    mapState: "pill",
  },
  {
    title: "Ribosome + Membrane",
    short: "O Guardian tenta abrir o AS com device_secret local e valida se o amino é permitido pelo RNA.",
    threat: "Comando assinado, mas fora da política do dispositivo, é bloqueado.",
    blocks: "Guardian errado, comando fora do tipo e payload inválido.",
    remaining: "Se não for desta zona, a rede G2G deve carregar a intenção.",
    badge: "digerido",
    mapState: "safe",
  },
  {
    title: "G2G entre Guardians",
    short: "A Action Pill pode entrar por um Guardian e ser repassada até o nó que consegue digerir.",
    threat: "O app não precisa expor qual Guardian controla qual dispositivo.",
    blocks: "Mapeamento direto entre entrada, zona e dispositivo.",
    remaining: "O limite principal do protótipo atual é disponibilidade/DoS.",
    badge: "malha",
    mapState: "relay",
  },
];

const cpFields: PillField[] = [
  {
    name: "version",
    purpose: "Evolui o protocolo sem aceitar formato incompatível.",
    blocks: "Interpretação errada de pacote antigo.",
  },
  {
    name: "action_class",
    purpose: "Mostra apenas a classe geral, como MQTT ou POLICY.",
    blocks: "Exposição precoce do comando real.",
  },
  {
    name: "issued_ms / expires_ms",
    purpose: "Cria contexto temporal para a intenção.",
    blocks: "Uso tardio de mensagens antigas.",
  },
  {
    name: "nonce",
    purpose: "Dá unicidade ao pacote.",
    blocks: "Colisões e replay simples.",
  },
  {
    name: "active_hash",
    purpose: "Amarra o CP ao AS criptografado.",
    blocks: "Trocar o conteúdo interno depois da assinatura.",
  },
  {
    name: "issuer_key_id",
    purpose: "Escolhe qual chave pública deve validar a assinatura.",
    blocks: "Confusão de identidade do emissor.",
  },
  {
    name: "signature",
    purpose: "Prova assimétrica de autoria.",
    blocks: "Forjar comando sem a chave privada.",
  },
];

const asFields: PillField[] = [
  {
    name: "cipher",
    purpose: "Declara o algoritmo usado no envelope criptografado.",
    blocks: "Ambiguidade criptográfica.",
  },
  {
    name: "nonce + tag",
    purpose: "Permite criptografia autenticada.",
    blocks: "Alteração silenciosa do ciphertext.",
  },
  {
    name: "ciphertext",
    purpose: "Carrega device_id, tópico, amino e payload sem revelar.",
    blocks: "Leitura direta da intenção.",
  },
  {
    name: "device_id",
    purpose: "Aponta o dispositivo lógico depois da descriptografia.",
    blocks: "Comando sem destino verificável.",
  },
  {
    name: "amino_id",
    purpose: "Troca strings livres por verbos conhecidos.",
    blocks: "Comandos inventados ou ambíguos.",
  },
  {
    name: "payload_type / payload_i32",
    purpose: "Valida se o comando precisa de valor e qual tipo.",
    blocks: "Payload fora do formato esperado.",
  },
];

const timeline: TimelineItem[] = [
  {
    phase: "Build",
    problem: "Imports, CMake e componentes do ESP-IDF quebrando a compilação.",
    prompt: "Corrigir erros sem trocar a arquitetura.",
    decision: "Adicionar dependências e includes mínimos.",
    evidence: "Firmware voltou a compilar.",
  },
  {
    phase: "Action Pill",
    problem: "Como provar autoria e esconder a intenção ao mesmo tempo.",
    prompt: "Separar Capsule Pill e Active Substance.",
    decision: "CP assinado por fora, AS criptografado por dispositivo.",
    evidence: "Guardian valida assinatura e abre AS com device_secret.",
  },
  {
    phase: "G2G",
    problem: "Guardians recebiam e repassavam com instabilidade BLE.",
    prompt: "Analisar inbound/outbound e ordem do fluxo.",
    decision: "Cache primeiro, relay depois, digestão pesada em seguida.",
    evidence: "G1 repassa e G2 aciona o LED.",
  },
  {
    phase: "Admin",
    problem: "Configuração precisava ser temporária e autenticada.",
    prompt: "Criar challenge assinado para liberar painel.",
    decision: "Botão físico abre AP admin e assinatura libera UI.",
    evidence: "Cadastro persiste e volta no modo normal.",
  },
];

let currentLayer = 0;
let currentPillTab: PillTab = "cp";

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("App root não encontrado");
}

app.innerHTML = `
  <header class="topbar">
    <a class="brand" href="#top" aria-label="Voltar ao início">
      <span class="brand-mark">BN</span>
      <span><strong>BlindNet</strong><small>IoT Security</small></span>
    </a>
    <nav class="topnav" aria-label="Navegação">
      <a href="#layers">Camadas</a>
      <a href="#pill">Pill</a>
      <a href="#membrane">Membrane</a>
      <a href="#g2g">G2G</a>
      <a href="#transparency">IA</a>
    </nav>
  </header>

  <main id="top">
    <section class="hero">
      <canvas id="heroCanvas" aria-label="Visualização animada da rede BlindNet"></canvas>
      <div class="hero-copy">
        <p class="eyebrow">ESP32 · BLE · MQTT · criptografia · Guardians</p>
        <h1>O que precisa ser verdade para um LED acender?</h1>
        <p>Na BlindNet, acender um LED deixa de ser publicar um comando. A intenção precisa provar autoria, integridade, novidade, destino, segredo e permissão.</p>
        <div class="hero-actions">
          <a class="primary-action" href="#simulator">Explorar fluxo</a>
          <a class="secondary-action" href="#transparency">Ver transparência</a>
        </div>
      </div>
    </section>

    <section class="metrics" aria-label="Resumo da apresentação">
      <article><strong>CP + AS</strong><span>intenção assinada e opaca</span></article>
      <article><strong>BLE/G2G</strong><span>plano de controle separado</span></article>
      <article><strong>Membrane</strong><span>autenticidade não basta</span></article>
      <article><strong>DoS</strong><span>limite honesto do protótipo</span></article>
    </section>

    <section id="simulator" class="section simulator-section">
      <div class="section-head">
        <span class="eyebrow">Simulador mobile</span>
        <h2>A rede ganhando defesa, camada por camada</h2>
        <p>Toque para atacar, adicionar proteção e ver o que muda no caminho entre app, Guardian, broker e dispositivo.</p>
      </div>

      <div class="simulator-grid">
        <div class="device-frame">
          <div class="device-top">
            <span id="scenarioTitle"></span>
            <strong id="scenarioBadge"></strong>
          </div>
          <div id="networkMap" class="network-map">
            <div class="map-line line-a"></div>
            <div class="map-line line-b"></div>
            <div class="map-line line-c"></div>
            <div class="map-line line-d"></div>
            <div class="map-node node-app">App</div>
            <div class="map-node node-attacker">Scan</div>
            <div class="map-node node-guardian">Guardian</div>
            <div class="map-node node-broker">MQTT</div>
            <div class="map-node node-device">LED</div>
            <div class="moving-pill">PILL</div>
          </div>
          <div class="log-window" id="attackLog"></div>
        </div>

        <div class="control-panel">
          <div class="progress-label">
            <span>Camada atual</span>
            <strong id="layerCount"></strong>
          </div>
          <div class="progress-track"><span id="layerProgress"></span></div>
          <h3 id="layerTitle"></h3>
          <p id="layerShort"></p>
          <dl class="decision-list">
            <div><dt>Bloqueia</dt><dd id="layerBlocks"></dd></div>
            <div><dt>Ainda resta</dt><dd id="layerRemaining"></dd></div>
          </dl>
          <div class="button-row">
            <button class="tool-button" id="attackButton" type="button">Atacar</button>
            <button class="tool-button strong" id="nextLayerButton" type="button">Adicionar camada</button>
          </div>
        </div>
      </div>
    </section>

    <section id="layers" class="section">
      <div class="section-head">
        <span class="eyebrow">Mapa da arquitetura</span>
        <h2>Por que cada peça existe</h2>
        <p>Cada bloco reduz uma classe de ataque. O conjunto é o que transforma visibilidade em algo bem diferente de controle.</p>
      </div>
      <div class="layer-list" id="layerList"></div>
    </section>

    <section id="pill" class="section dark">
      <div class="section-head">
        <span class="eyebrow">Action Pill</span>
        <h2>CP prova a cápsula. AS esconde a intenção.</h2>
        <p>A Action Pill é roteável sem revelar o comando. O Guardian valida o lacre antes de tentar digerir o conteúdo.</p>
      </div>
      <div class="pill-grid">
        <div class="pill-orb" aria-hidden="true">
          <button class="pill-half pill-cp active" data-pill-tab="cp" type="button"><strong>CP</strong><span>público · assinado</span></button>
          <button class="pill-half pill-as" data-pill-tab="as" type="button"><strong>AS</strong><span>opaco · criptografado</span></button>
        </div>
        <div class="inspector">
          <div class="tabs" role="tablist">
            <button class="tab active" data-pill-tab="cp" type="button">CP</button>
            <button class="tab" data-pill-tab="as" type="button">AS</button>
            <button class="tab" data-pill-tab="why" type="button">Por quê</button>
          </div>
          <div id="pillInspector"></div>
        </div>
      </div>
    </section>

    <section id="membrane" class="section">
      <div class="section-head">
        <span class="eyebrow">Digestão local</span>
        <h2>Ribosome, RNA e Amino Acids</h2>
        <p>Mesmo depois da assinatura, a intenção só executa se o Guardian tiver o segredo e a Membrane permitir o verbo.</p>
      </div>
      <div class="cards">
        <article><span>Ribosome</span><h3>Quem existe na zona</h3><p>Guarda mqtt_client_id, template_id, epoch e device_secret. O segredo fica no Guardian.</p></article>
        <article><span>RNA/RNS</span><h3>Molde de comportamento</h3><p>Lâmpada aceita ON, OFF, TOGGLE e leitura. Sensor, porta e dimmer têm outros moldes.</p></article>
        <article><span>Amino Acids</span><h3>Verbos normalizados</h3><p>Comandos viram IDs conhecidos em vez de strings arbitrárias.</p></article>
        <article><span>Membrane</span><h3>Permissão final</h3><p>Assinatura prova autoria. Membrane prova se aquela ação é permitida naquele contexto.</p></article>
      </div>
    </section>

    <section id="g2g" class="section g2g">
      <div class="section-head">
        <span class="eyebrow">Guardian-to-Guardian</span>
        <h2>A intenção encontra quem consegue digerir</h2>
        <p>O app pode enviar para um Guardian qualquer. A malha repassa a Action Pill opaca até o nó certo.</p>
      </div>
      <div class="relay">
        <article><span>G1</span><strong>Recebe</strong><p>cache → relay → digestão local</p></article>
        <div class="relay-path"><b></b><em>Action Pill opaca</em></div>
        <article><span>G2</span><strong>Executa</strong><p>device_secret → membrane → MQTT → LED</p></article>
      </div>
    </section>

    <section id="transparency" class="section transparency">
      <div class="section-head">
        <span class="eyebrow">Portal de transparência</span>
        <h2>IA como ferramenta auditável</h2>
        <p>O painel mostra prompts, decisões humanas, erros da IA e evidências reais. A autoria fica no processo de engenharia.</p>
      </div>
      <div class="transparency-grid">
        <div class="bars" aria-label="Mapa de participação">
          <div><span>Arquitetura</span><b style="--value: 88%"></b><em>decisão humana</em></div>
          <div><span>Build</span><b style="--value: 72%"></b><em>depuração assistida</em></div>
          <div><span>BLE/G2G</span><b style="--value: 84%"></b><em>hardware decidiu</em></div>
          <div><span>Apresentação</span><b style="--value: 68%"></b><em>organização visual</em></div>
        </div>
        <div class="timeline" id="timeline"></div>
      </div>
    </section>

    <section class="section closing">
      <span class="eyebrow">Encerramento</span>
      <h2>Parece só um LED. Não é só um LED.</h2>
      <p>O LED acende porque uma cadeia de segurança funcionou em hardware real: BLE, cache, assinatura, AS, Ribosome, Membrane, G2G e MQTT local.</p>
      <a class="primary-action" href="#top">Voltar ao início</a>
    </section>
  </main>
`;

const byId = <T extends HTMLElement>(id: string): T => {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`Elemento #${id} não encontrado`);
  }
  return element as T;
};

const scenarioTitle = byId<HTMLSpanElement>("scenarioTitle");
const scenarioBadge = byId<HTMLElement>("scenarioBadge");
const networkMap = byId<HTMLDivElement>("networkMap");
const attackLog = byId<HTMLDivElement>("attackLog");
const layerCount = byId<HTMLElement>("layerCount");
const layerProgress = byId<HTMLSpanElement>("layerProgress");
const layerTitle = byId<HTMLHeadingElement>("layerTitle");
const layerShort = byId<HTMLParagraphElement>("layerShort");
const layerBlocks = byId<HTMLElement>("layerBlocks");
const layerRemaining = byId<HTMLElement>("layerRemaining");
const attackButton = byId<HTMLButtonElement>("attackButton");
const nextLayerButton = byId<HTMLButtonElement>("nextLayerButton");
const layerList = byId<HTMLDivElement>("layerList");
const pillInspector = byId<HTMLDivElement>("pillInspector");
const timelineElement = byId<HTMLDivElement>("timeline");

function renderLayer(): void {
  const layer = layers[currentLayer];
  scenarioTitle.textContent = layer.title;
  scenarioBadge.textContent = layer.badge;
  layerCount.textContent = `${currentLayer + 1}/${layers.length}`;
  layerProgress.style.width = `${((currentLayer + 1) / layers.length) * 100}%`;
  layerTitle.textContent = layer.title;
  layerShort.textContent = layer.short;
  layerBlocks.textContent = layer.blocks;
  layerRemaining.textContent = layer.remaining;
  attackLog.innerHTML = `<p>${layer.threat}</p>`;
  networkMap.dataset.state = layer.mapState;
}

function renderLayerList(): void {
  layerList.innerHTML = layers
    .map(
      (layer, index) => `
        <button class="layer-item" type="button" data-layer="${index}">
          <span>${String(index + 1).padStart(2, "0")}</span>
          <strong>${layer.title}</strong>
          <p>${layer.short}</p>
        </button>
      `,
    )
    .join("");

  layerList.querySelectorAll<HTMLButtonElement>("[data-layer]").forEach((button) => {
    button.addEventListener("click", () => {
      currentLayer = Number(button.dataset.layer);
      renderLayer();
      document.getElementById("simulator")?.scrollIntoView({ behavior: "smooth" });
    });
  });
}

function fieldList(fields: PillField[]): string {
  return fields
    .map(
      (field) => `
        <article class="field-row">
          <h4>${field.name}</h4>
          <p>${field.purpose}</p>
          <small>${field.blocks}</small>
        </article>
      `,
    )
    .join("");
}

function renderPill(tab: PillTab): void {
  currentPillTab = tab;
  document.querySelectorAll<HTMLElement>("[data-pill-tab]").forEach((button) => {
    button.classList.toggle("active", button.dataset.pillTab === tab);
  });

  if (tab === "cp") {
    pillInspector.innerHTML = `
      <h3>Capsule Pill</h3>
      <p>Envelope público, assinado e verificável. Ele prova que a cápsula não foi adulterada sem revelar o comando real.</p>
      <div class="field-list">${fieldList(cpFields)}</div>
    `;
    return;
  }

  if (tab === "as") {
    pillInspector.innerHTML = `
      <h3>Active Substance</h3>
      <p>Conteúdo criptografado que guarda device_id, tópico, amino acid e payload. Só o Guardian com device_secret consegue abrir.</p>
      <div class="field-list">${fieldList(asFields)}</div>
    `;
    return;
  }

  pillInspector.innerHTML = `
    <h3>Por que separar?</h3>
    <p>CP responde se a cápsula é autêntica. AS responde qual é a intenção. Separar os dois permite relay opaco, validação cedo e execução apenas no Guardian certo.</p>
    <div class="why-grid">
      <span>Cache barato antes da digestão pesada</span>
      <span>Relay sem revelar destino</span>
      <span>Assinatura amarra o AS ao CP</span>
      <span>Membrane decide depois da descriptografia</span>
    </div>
  `;
}

function renderTimeline(): void {
  timelineElement.innerHTML = timeline
    .map(
      (item) => `
        <article class="timeline-item">
          <span>${item.phase}</span>
          <h3>${item.problem}</h3>
          <p><strong>Prompt:</strong> ${item.prompt}</p>
          <p><strong>Decisão:</strong> ${item.decision}</p>
          <small>${item.evidence}</small>
        </article>
      `,
    )
    .join("");
}

function initCanvas(): void {
  const canvas = document.querySelector<HTMLCanvasElement>("#heroCanvas");
  if (!canvas) return;

  const context = canvas.getContext("2d");
  if (!context) return;

  const points = Array.from({ length: 18 }, (_, index) => ({
    angle: (Math.PI * 2 * index) / 18,
    radius: 80 + (index % 4) * 26,
    speed: 0.0015 + (index % 5) * 0.00035,
  }));

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    const scale = window.devicePixelRatio || 1;
    canvas.width = Math.floor(rect.width * scale);
    canvas.height = Math.floor(rect.height * scale);
    context.setTransform(scale, 0, 0, scale, 0, 0);
  };

  const draw = (time: number) => {
    const width = canvas.clientWidth;
    const height = canvas.clientHeight;
    const centerX = width * 0.56;
    const centerY = height * 0.5;

    context.clearRect(0, 0, width, height);
    context.fillStyle = "#0d1817";
    context.fillRect(0, 0, width, height);

    const nodes = points.map((point) => {
      const angle = point.angle + time * point.speed;
      return {
        x: centerX + Math.cos(angle) * point.radius,
        y: centerY + Math.sin(angle) * point.radius * 0.66,
      };
    });

    context.lineWidth = 1;
    nodes.forEach((node, index) => {
      const next = nodes[(index + 5) % nodes.length];
      context.strokeStyle = "rgba(141, 232, 209, 0.16)";
      context.beginPath();
      context.moveTo(node.x, node.y);
      context.lineTo(next.x, next.y);
      context.stroke();
    });

    nodes.forEach((node, index) => {
      context.fillStyle = index % 4 === 0 ? "#f4c95d" : "#66dcc8";
      context.globalAlpha = index % 4 === 0 ? 0.95 : 0.55;
      context.beginPath();
      context.arc(node.x, node.y, index % 4 === 0 ? 5 : 3, 0, Math.PI * 2);
      context.fill();
    });

    context.globalAlpha = 1;
    context.fillStyle = "rgba(255,255,255,0.94)";
    context.font = "700 24px system-ui";
    context.fillText("Guardian mesh", Math.max(20, width * 0.08), height - 54);
    context.fillStyle = "rgba(255,255,255,0.64)";
    context.font = "500 13px system-ui";
    context.fillText("Action Pills via BLE/G2G", Math.max(20, width * 0.08), height - 30);

    requestAnimationFrame(draw);
  };

  resize();
  window.addEventListener("resize", resize);
  requestAnimationFrame(draw);
}

attackButton.addEventListener("click", () => {
  networkMap.classList.remove("attack-pulse");
  window.setTimeout(() => networkMap.classList.add("attack-pulse"), 0);
});

nextLayerButton.addEventListener("click", () => {
  currentLayer = (currentLayer + 1) % layers.length;
  renderLayer();
});

document.querySelectorAll<HTMLButtonElement>("[data-pill-tab]").forEach((button) => {
  button.addEventListener("click", () => {
    renderPill(button.dataset.pillTab as PillTab);
  });
});

renderLayer();
renderLayerList();
renderPill(currentPillTab);
renderTimeline();
initCanvas();
