import "./styles.css";

type Slide = {
  id: string;
  index: string;
  eyebrow: string;
  title: string;
  image: string;
  problem: string;
  solution: string;
  why: string;
  limit?: string;
};

const images = {
  setup: new URL("../Diagramas/configs/setup_inicial.png", import.meta.url).href,
  admin: new URL("../Diagramas/configs/admin_cadastro.png", import.meta.url).href,
  guardian: new URL("../Diagramas/01_guardian_rede_protegida.png", import.meta.url).href,
  actionPill: new URL("../Diagramas/02_action_pill_cp_as.png", import.meta.url).href,
  signature: new URL("../Diagramas/03_assinatura_anti_replay.png", import.meta.url).href,
  stomach: new URL("../Diagramas/04_stomach_digestao_action_pill.png", import.meta.url).href,
  ribosome: new URL("../Diagramas/05_ribosome_membrane_pipeline.png", import.meta.url).href,
  rna: new URL("../Diagramas/06_rna_amino_acids.png", import.meta.url).href,
  enzyme: new URL("../Diagramas/07_active_enzyme_device_secret.png", import.meta.url).href,
  membrane: new URL("../Diagramas/08_membrane_filtro_semantico.png", import.meta.url).href,
  mqtt: new URL("../Diagramas/09_nucleo_mqtt_publicacao_local.png", import.meta.url).href,
  g2g: new URL("../Diagramas/10_g2g_relay_guardians.png", import.meta.url).href,
  iaSupport: new URL("../Diagramas/IA/IA_como_apoio.png", import.meta.url).href,
  iaTable: new URL("../Diagramas/IA/tabela_apoio.png", import.meta.url).href,
};

const slides: Slide[] = [
  {
    id: "setup",
    index: "01",
    eyebrow: "Configuração",
    title: "Setup inicial do Guardian",
    image: images.setup,
    problem: "Um Guardian novo ainda não sabe a rede principal, a zona, a chave pública do dono nem sua identidade local.",
    solution: "Ele sobe um AP temporário de setup, recebe as configurações mínimas, grava no config store e reinicia no modo normal.",
    why: "Isso separa o nascimento do nó da operação diária e evita deixar portas permanentes abertas para configuração.",
  },
  {
    id: "admin",
    index: "02",
    eyebrow: "Cadastro",
    title: "Admin e cadastro do dispositivo",
    image: images.admin,
    problem: "O Guardian precisa aprender que existe um dispositivo real, qual RNA ele deve usar e qual secret protege o Active Substance.",
    solution: "O dono abre uma janela admin, resolve um desafio assinado, aprova o dispositivo visto e o Guardian grava a entrada na Ribosome Table.",
    why: "O device_secret fica no Guardian, enquanto o app usa esse secret para montar Action Pills destinadas ao dispositivo correto.",
  },
  {
    id: "guardian",
    index: "03",
    eyebrow: "Fronteira",
    title: "Guardian como rede protegida",
    image: images.guardian,
    problem: "Numa rede IoT comum, scans revelam IPs, portas, serviços e possíveis alvos vulneráveis.",
    solution: "O dispositivo sai da rede principal e passa a viver atrás do Guardian, com broker local e fronteira própria.",
    why: "A superfície visível diminui: o atacante deixa de conversar diretamente com a lâmpada, fechadura ou sensor.",
    limit: "Isso reduz sondagem e exposição, mas ainda precisa de uma cadeia forte para autorizar comandos legítimos.",
  },
  {
    id: "action-pill",
    index: "04",
    eyebrow: "Cápsula",
    title: "Action Pill: CP + AS",
    image: images.actionPill,
    problem: "Um comando simples de IoT costuma misturar intenção, destino e autorização no mesmo pacote frágil.",
    solution: "A Action Pill separa Capsule Pill, assinada e verificável, de Active Substance, criptografado para o dispositivo.",
    why: "O Guardian pode validar e repassar a cápsula sem necessariamente conhecer o conteúdo interno.",
    limit: "A Action Pill prova autenticidade e integridade, mas o destino final ainda depende da digestão correta.",
  },
  {
    id: "signature",
    index: "05",
    eyebrow: "Autoria",
    title: "Assinatura e anti-replay",
    image: images.signature,
    problem: "Capturar um comando válido não deveria permitir repetir esse comando depois.",
    solution: "O Guardian valida assinatura, expiração, nonce e digest em cache antes de continuar o fluxo.",
    why: "Sem a chave privada do dono, o atacante não consegue forjar uma cápsula nova; com replay, cai no cache.",
    limit: "Essa camada protege o estado dos dispositivos, mas não elimina tentativa de ruído ou DoS no rádio.",
  },
  {
    id: "stomach",
    index: "06",
    eyebrow: "Digestão",
    title: "Stomach: remontar e decidir",
    image: images.stomach,
    problem: "O BLE/G2G entrega fragmentos, e fragmentos isolados não dizem se a intenção é nova, válida ou completa.",
    solution: "O Stomach remonta a Action Pill, calcula digest, consulta cache e só então libera o próximo passo.",
    why: "É o ponto onde ruído, duplicata e cápsula incompleta são filtrados antes de trabalho pesado.",
  },
  {
    id: "ribosome",
    index: "07",
    eyebrow: "Pipeline",
    title: "Ribosome, Enzyme e Membrane",
    image: images.ribosome,
    problem: "Mesmo uma cápsula autêntica pode não pertencer àquele Guardian ou não fazer sentido para aquele dispositivo.",
    solution: "A Ribosome Table encontra candidatos, a Active Enzyme tenta abrir o AS e a Membrane valida a semântica pelo RNA.",
    why: "A autorização deixa de ser apenas criptográfica e passa a ser contextual: dispositivo, comando e regra precisam encaixar.",
  },
  {
    id: "rna",
    index: "08",
    eyebrow: "Linguagem",
    title: "RNA formado por Amino Acids",
    image: images.rna,
    problem: "Dispositivos diferentes aceitam ações diferentes, e comando genérico demais vira risco.",
    solution: "Amino Acids representam ações permitidas; o RNA monta o vocabulário específico de cada dispositivo.",
    why: "A lâmpada pode aceitar TOGGLE, mas uma fechadura poderia exigir outra gramática e outra política.",
  },
  {
    id: "enzyme",
    index: "09",
    eyebrow: "Criptografia local",
    title: "Active Enzyme e device_secret",
    image: images.enzyme,
    problem: "O Guardian não deve aceitar um Active Substance apenas porque a cápsula externa é válida.",
    solution: "A Active Enzyme tenta descriptografar o AS com o device_secret armazenado para aquele dispositivo.",
    why: "Só o Guardian que possui o secret correto consegue transformar a substância criptografada em comando executável.",
    limit: "Se o AS não abre ali, ele pode ser apenas repassado por G2G sem revelar o conteúdo.",
  },
  {
    id: "membrane",
    index: "10",
    eyebrow: "Semântica",
    title: "Membrane como filtro final",
    image: images.membrane,
    problem: "Descriptografar não basta: o payload ainda pode pedir algo fora do RNA permitido.",
    solution: "A Membrane compara o AS com os receptores derivados do RNA e aceita apenas o que encaixa.",
    why: "É a camada que impede comandos semanticamente estranhos de virarem publicação no broker.",
  },
  {
    id: "mqtt",
    index: "11",
    eyebrow: "Execução",
    title: "Núcleo MQTT local",
    image: images.mqtt,
    problem: "O dispositivo IoT deve continuar simples, sem carregar toda a complexidade criptográfica.",
    solution: "Depois da validação, o Guardian publica um comando local no broker MQTT interno da zona.",
    why: "A inteligência fica no Guardian; o dispositivo só precisa estar no AP local e escutar seu tópico.",
  },
  {
    id: "g2g",
    index: "12",
    eyebrow: "Malha",
    title: "G2G Relay entre Guardians",
    image: images.g2g,
    problem: "O app não sabe necessariamente qual Guardian é o dono final daquele dispositivo.",
    solution: "O primeiro Guardian verifica cache, repassa a cápsula opaca por BLE/G2G e depois processa localmente.",
    why: "A intenção pode atravessar a malha sem expor o Active Substance até encontrar o nó capaz de digeri-la.",
    limit: "A demo já prova o fluxo; a evolução futura é endurecer ainda mais contra negação de serviço no BLE.",
  },
];

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) {
  throw new Error("Root #app nao encontrado");
}

const navItems = slides
  .map(
    (slide) => `
      <a class="step-link" href="#${slide.id}" data-target="${slide.id}">
        <span>${slide.index}</span>
        ${slide.eyebrow}
      </a>
    `,
  )
  .join("");

const slideMarkup = slides
  .map(
    (slide) => `
      <section class="slide" id="${slide.id}" data-slide="${slide.id}">
        <div class="slide-shell">
          <div class="slide-kicker">
            <span>${slide.index}</span>
            <strong>${slide.eyebrow}</strong>
          </div>
          <figure class="diagram-frame">
            <img src="${slide.image}" alt="${slide.title}" loading="lazy" />
          </figure>
          <div class="details">
            <p class="details-index">${slide.index} / ${String(slides.length).padStart(2, "0")}</p>
            <h2>${slide.title}</h2>
            <div class="detail-grid">
              <article>
                <h3>Problema</h3>
                <p>${slide.problem}</p>
              </article>
              <article>
                <h3>Solução</h3>
                <p>${slide.solution}</p>
              </article>
              <article>
                <h3>Por que importa</h3>
                <p>${slide.why}</p>
              </article>
              ${
                slide.limit
                  ? `<article><h3>Limite honesto</h3><p>${slide.limit}</p></article>`
                  : ""
              }
            </div>
          </div>
        </div>
      </section>
    `,
  )
  .join("");

app.innerHTML = `
  <header class="topbar">
    <a class="brand" href="#setup" aria-label="BlindNet inicio">
      <span>BN</span>
      <strong>BlindNet</strong>
    </a>
    <nav class="step-nav" aria-label="Etapas da apresentacao">
      ${navItems}
      <a class="step-link transparency-link" href="#transparencia" data-target="transparencia">
        <span>IA</span>
        Transparência
      </a>
    </nav>
  </header>

  <main class="deck" id="deck">
    <section class="intro" id="inicio">
      <p>Arquitetura de segurança para IoT local</p>
      <h1>BlindNet</h1>
      <span>Diagramas em tela cheia. Role para ver os detalhes de cada camada.</span>
      <a href="#setup">Iniciar</a>
    </section>

    ${slideMarkup}

    

    <section class="transparency" id="transparencia">
      <div class="transparency-copy">
        <p class="details-index">Transparência</p>
        <h2>Uso de IA como ferramenta auditável</h2>
        <p>
          A IA foi utilizada como ferramenta de apoio em implementação, depuração,
          organização visual e escrita técnica. As decisões de arquitetura,
          integração, validação e testes em hardware foram documentadas para
          permitir rastreabilidade do processo de desenvolvimento.
        </p>
      </div>
      <div class="transparency-diagrams">
        <figure class="transparency-diagram">
          <img src="${images.iaSupport}" alt="Mapa dos módulos em que a IA foi usada como apoio no desenvolvimento" />
        </figure>
        <figure class="transparency-diagram">
          <img src="${images.iaTable}" alt="Tabela de transparência com apoio da IA, decisões humanas e evidências práticas" />
        </figure>
      </div>
    </section>
  </main>

  <div class="rotate-hint">
    <strong>Vire o celular na horizontal</strong>
    <p>Os diagramas foram desenhados para serem apresentados em paisagem.</p>
  </div>
`;

const links = Array.from(document.querySelectorAll<HTMLAnchorElement>(".step-link"));
const sections = Array.from(
  document.querySelectorAll<HTMLElement>("[data-slide], .test-lab, .transparency"),
);
const deck = document.querySelector<HTMLElement>("#deck");
const horizontalPages = Array.from(
  document.querySelectorAll<HTMLElement>(".intro, [data-slide], .test-lab, .transparency"),
);

function nearestPageIndex(): number {
  if (!deck) return 0;
  const left = deck.scrollLeft;
  let nearest = 0;
  let nearestDistance = Number.POSITIVE_INFINITY;

  horizontalPages.forEach((page, index) => {
    const distance = Math.abs(page.offsetLeft - left);
    if (distance < nearestDistance) {
      nearest = index;
      nearestDistance = distance;
    }
  });

  return nearest;
}

function goToPage(index: number): void {
  if (!deck) return;
  const page = horizontalPages[Math.max(0, Math.min(index, horizontalPages.length - 1))];
  if (!page) return;
  deck.scrollTo({
    left: page.offsetLeft,
    behavior: "smooth",
  });
}

document.querySelectorAll<HTMLAnchorElement>('a[href^="#"]').forEach((link) => {
  link.addEventListener("click", (event) => {
    const target = link.dataset.target ?? link.getAttribute("href")?.replace("#", "");
    const section = target ? document.getElementById(target) : null;
    if (!section || !deck) return;
    event.preventDefault();
    deck.scrollTo({
      left: section.offsetLeft,
      behavior: "smooth",
    });
  });
});

let touchStartX = 0;
let touchStartY = 0;
let touchStartTime = 0;

deck?.addEventListener(
  "touchstart",
  (event) => {
    const touch = event.touches[0];
    if (!touch) return;
    touchStartX = touch.clientX;
    touchStartY = touch.clientY;
    touchStartTime = performance.now();
  },
  { passive: true },
);

deck?.addEventListener(
  "touchend",
  (event) => {
    const touch = event.changedTouches[0];
    if (!touch) return;

    const dx = touch.clientX - touchStartX;
    const dy = touch.clientY - touchStartY;
    const elapsed = performance.now() - touchStartTime;
    const absX = Math.abs(dx);
    const absY = Math.abs(dy);

    const isIntentionalHorizontalSwipe = absX >= 120 && absX > absY * 1.55 && elapsed < 900;
    if (!isIntentionalHorizontalSwipe) return;

    event.preventDefault();
    const current = nearestPageIndex();
    goToPage(dx < 0 ? current + 1 : current - 1);
  },
  { passive: false },
);

const observer = new IntersectionObserver(
  (entries) => {
    const visible = entries
      .filter((entry) => entry.isIntersecting)
      .sort((a, b) => b.intersectionRatio - a.intersectionRatio)[0];

    if (!visible) return;
    const id = visible.target.id;
    links.forEach((link) => {
      link.classList.toggle("active", link.dataset.target === id);
    });
  },
  {
    root: deck,
    rootMargin: "0px -45% 0px -45%",
    threshold: [0.2, 0.45, 0.7],
  },
);

sections.forEach((section) => observer.observe(section));

type DemoDevice = {
  id: string;
  deviceId: string;
  label: string;
  topic: string;
  amino: string;
  epoch: number;
  hasSecret: boolean;
  secretPreview?: string;
};

const bridgeStatus = document.querySelector<HTMLElement>("#bridgeStatus");
const deviceGrid = document.querySelector<HTMLElement>("#deviceGrid");

function setBridgeStatus(text: string, state: "ok" | "warn" | "busy" = "ok"): void {
  if (!bridgeStatus) return;
  bridgeStatus.textContent = text;
  bridgeStatus.dataset.state = state;
}

async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 85000);
  let response: Response;
  try {
    response = await fetch(path, {
      ...init,
      signal: controller.signal,
      headers: {
        "content-type": "application/json",
        ...(init?.headers ?? {}),
      },
    });
  } finally {
    window.clearTimeout(timeout);
  }

  const data = (await response.json()) as T & { ok?: boolean; error?: string };
  if (!response.ok || data.ok === false) {
    throw new Error(data.error ?? "falha na ponte local");
  }
  return data;
}

function renderDevices(devices: DemoDevice[]): void {
  if (!deviceGrid) return;

  if (devices.length === 0) {
    deviceGrid.innerHTML = `
      <article class="empty-devices">
        <h3>Nenhum dispositivo cadastrado</h3>
        <p>Edite a lista DEMO_DEVICES em Presentation/bridge/server.mjs e reinicie a ponte local.</p>
      </article>
    `;
    return;
  }

  deviceGrid.innerHTML = devices
    .map(
      (device) => `
        <article class="device-card" data-device-id="${device.id}">
          <div>
            <p>${device.id}</p>
            <h3>${device.label}</h3>
          </div>
          <div class="device-actions">
            <button type="button" data-action="send" data-device-id="${device.id}">
              ${device.amino}
            </button>
          </div>
        </article>
      `,
    )
    .join("");
}

async function loadDevices(): Promise<void> {
  try {
    const health = await api<{ ok: boolean }>("/api/health");
    if (health.ok) {
      setBridgeStatus("Ponte local conectada. Pronto para enviar Action Pills.", "ok");
    }
    const data = await api<{ devices: DemoDevice[] }>("/api/devices");
    renderDevices(data.devices);
  } catch (error) {
    setBridgeStatus(
      `Ponte local indisponível. Rode: npm run demo. Detalhe: ${(error as Error).message}`,
      "warn",
    );
    renderDevices([]);
  }
}

deviceGrid?.addEventListener("click", async (event) => {
  const button = (event.target as HTMLElement).closest<HTMLButtonElement>("button[data-action]");
  if (!button) return;

  const deviceId = button.dataset.deviceId;
  const action = button.dataset.action;
  const card = button.closest<HTMLElement>(".device-card");
  const output = card?.querySelector("pre");
  if (!deviceId || !action) return;

  button.disabled = true;
  setBridgeStatus(`Enviando comando para ${deviceId}...`, "busy");
  if (output) output.textContent = "gerando e enviando Action Pill...";

  try {
    const result = await api<{
      ok: boolean;
      queued?: boolean;
      jobId?: string;
      queueLength?: number;
    }>("/api/send", {
      method: "POST",
      body: JSON.stringify({ id: deviceId }),
    });
    const queueText = result.queueLength ? ` Fila: ${result.queueLength}.` : "";
    setBridgeStatus(`Comando de ${deviceId} enviado para a ponte.${queueText}`, "ok");
    console.log("BlindNet send result", result);
  } catch (error) {
    setBridgeStatus(`Falha ao enviar para ${deviceId}.`, "warn");
    console.error("BlindNet send error", error);
  } finally {
    button.disabled = false;
  }
});

loadDevices();
