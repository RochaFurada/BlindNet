import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, stat } from "node:fs/promises";
import { createReadStream } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const presentationRoot = path.resolve(__dirname, "..");
const projectRoot = path.resolve(presentationRoot, "..");
const distRoot = path.join(presentationRoot, "dist");
const outDir = path.join(__dirname, "out");

const port = Number(process.env.BLINDNET_BRIDGE_PORT ?? 8787);
const pythonBin = process.env.BLINDNET_PYTHON ?? "python";
const sendTimeoutMs = Number(process.env.BLINDNET_SEND_TIMEOUT_MS ?? 75000);
const privateKey = path.resolve(
  projectRoot,
  process.env.BLINDNET_PRIVATE_KEY ?? "tools/action_pill/test_keys/issuer_private_key.pem",
);
const actionPillScript = path.join(projectRoot, "tools/action_pill/send_action_pill_ble.py");
const sendQueue = [];
let processingQueue = false;

// Edite esta lista antes da demo. Os secrets ficam somente no notebook/ponte local.
const DEMO_DEVICES = [
  {
    id: "sala",
    deviceId: "lamp01",
    label: "Lâmpada Sala",
    topic: "blindnet/lamp01/cmd",
    deviceSecret: "848f7a845af059b91541e627a724335ed4d454b6f13fda306c751366e0fbb8d6",
    amino: "TOGGLE",
    epoch: 1,
  },
    {
    id: "cozinha",
    deviceId: "lamp01",
    label: "Lâmpada Cozinha",
    topic: "blindnet/lamp01/cmd",
    deviceSecret: "56d5501be9b30210ac45afe5c742b8746d0995023fe94a96f60b6c5156221dde",
    amino: "TOGGLE",
    epoch: 1,
  },
];

function validateDemoDevices() {
  const ids = new Set();
  for (const device of DEMO_DEVICES) {
    if (ids.has(device.id)) {
      throw new Error(`ID duplicado em DEMO_DEVICES: ${device.id}`);
    }
    ids.add(device.id);
    if (!/^[0-9a-fA-F]{64}$/.test(device.deviceSecret ?? "")) {
      throw new Error(`deviceSecret invalido para ${device.id}`);
    }
    if (!device.deviceId) {
      throw new Error(`deviceId ausente para ${device.id}`);
    }
  }
}

const contentTypes = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".json": "application/json; charset=utf-8",
};

function jsonResponse(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
  });
  res.end(body);
}

async function readJsonBody(req) {
  const chunks = [];
  for await (const chunk of req) {
    chunks.push(chunk);
    const size = chunks.reduce((total, part) => total + part.length, 0);
    if (size > 64 * 1024) {
      throw new Error("payload muito grande");
    }
  }

  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf-8"));
}

function publicDevice(device) {
  return {
    id: device.id,
    deviceId: device.deviceId ?? device.id,
    label: device.label,
    topic: device.topic,
    amino: device.amino ?? "TOGGLE",
    epoch: Number(device.epoch ?? 1),
    hasSecret: Boolean(device.deviceSecret),
  };
}

async function sendActionPill(device, action) {
  await mkdir(outDir, { recursive: true });

  const runId = randomUUID();
  const outPath = path.join(outDir, `${runId}.bin`);
  const metaPath = path.join(outDir, `${runId}.json`);
  const amino = String(action?.amino ?? device.amino ?? "TOGGLE").trim().toUpperCase();
  const timeout = Number(action?.timeout ?? process.env.BLINDNET_BLE_TIMEOUT ?? 45);

  const args = [
    actionPillScript,
    "--private-key",
    privateKey,
    "--device-secret",
    device.deviceSecret,
    "--device-id",
    device.deviceId ?? device.id,
    "--topic",
    device.topic,
    "--amino",
    amino,
    "--epoch",
    String(device.epoch ?? 1),
    "--timeout",
    String(timeout),
    "--no-response",
    "--out",
    outPath,
    "--meta-out",
    metaPath,
  ];

  return await new Promise((resolve) => {
    const startedAt = Date.now();
    let finished = false;
    const child = spawn(pythonBin, args, {
      cwd: projectRoot,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const timeoutHandle = setTimeout(() => {
      if (finished) return;
      finished = true;
      child.kill("SIGKILL");
      resolve({
        ok: false,
        code: "TIMEOUT",
        error: `envio excedeu ${Math.round(sendTimeoutMs / 1000)}s`,
        stdout,
        stderr,
        elapsedMs: Date.now() - startedAt,
      });
    }, sendTimeoutMs);

    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutHandle);
      resolve({
        ok: false,
        error: error.message,
        stdout,
        stderr,
        elapsedMs: Date.now() - startedAt,
      });
    });
    child.on("close", (code) => {
      if (finished) return;
      finished = true;
      clearTimeout(timeoutHandle);
      resolve({
        ok: code === 0,
        code,
        stdout,
        stderr,
        elapsedMs: Date.now() - startedAt,
      });
    });
  });
}

function enqueueSend(device, action) {
  const job = {
    id: randomUUID(),
    device,
    action,
    createdAt: Date.now(),
  };
  sendQueue.push(job);
  processSendQueue();
  return job;
}

async function processSendQueue() {
  if (processingQueue) return;
  processingQueue = true;

  try {
    while (sendQueue.length > 0) {
      const job = sendQueue.shift();
      if (!job) continue;

      console.log("[bridge] job iniciado", {
        jobId: job.id,
        appId: job.device.id,
        deviceId: job.device.deviceId ?? job.device.id,
        label: job.device.label,
      });

      const result = await sendActionPill(job.device, job.action);
      console.log("[bridge] job finalizado", {
        jobId: job.id,
        appId: job.device.id,
        ok: result.ok,
        code: result.code,
        elapsedMs: result.elapsedMs,
        error: result.error,
      });

      if (result.stdout) {
        console.log(result.stdout.trim());
      }
      if (result.stderr) {
        console.warn(result.stderr.trim());
      }
    }
  } finally {
    processingQueue = false;
  }
}

async function handleApi(req, res, pathname) {
  try {
    if (req.method === "GET" && pathname === "/api/health") {
      jsonResponse(res, 200, {
        ok: true,
        bridge: "blindnet",
        port,
        queueLength: sendQueue.length,
        processing: processingQueue,
      });
      return;
    }

    if (req.method === "GET" && pathname === "/api/devices") {
      jsonResponse(res, 200, {
        ok: true,
        devices: DEMO_DEVICES.map((device) => ({
          ...publicDevice(device),
          secretPreview: `${device.deviceSecret.slice(0, 8)}...${device.deviceSecret.slice(-8)}`,
        })),
      });
      return;
    }

    if (req.method === "POST" && pathname === "/api/send") {
      const input = await readJsonBody(req);
      const id = String(input.id ?? "").trim();
      const device = DEMO_DEVICES.find((candidate) => candidate.id === id);
      if (!device) {
        jsonResponse(res, 404, { ok: false, error: "dispositivo nao encontrado" });
        return;
      }

      const job = enqueueSend(device, input);
      jsonResponse(res, 202, {
        ok: true,
        queued: true,
        jobId: job.id,
        queueLength: sendQueue.length,
        device: publicDevice(device),
      });
      return;
    }

    jsonResponse(res, 404, { ok: false, error: "rota nao encontrada" });
  } catch (error) {
    jsonResponse(res, 400, { ok: false, error: error.message });
  }
}

async function serveStatic(req, res, pathname) {
  let filePath = path.normalize(path.join(distRoot, pathname === "/" ? "index.html" : pathname));
  if (!filePath.startsWith(distRoot)) {
    res.writeHead(403);
    res.end("Forbidden");
    return;
  }

  try {
    const fileStat = await stat(filePath);
    if (fileStat.isDirectory()) {
      filePath = path.join(filePath, "index.html");
    }
    const ext = path.extname(filePath);
    res.writeHead(200, {
      "content-type": contentTypes[ext] ?? "application/octet-stream",
    });
    createReadStream(filePath).pipe(res);
  } catch {
    const fallback = path.join(distRoot, "index.html");
    res.writeHead(200, {
      "content-type": "text/html; charset=utf-8",
    });
    createReadStream(fallback).pipe(res);
  }
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  if (url.pathname.startsWith("/api/")) {
    await handleApi(req, res, url.pathname);
    return;
  }

  await serveStatic(req, res, decodeURIComponent(url.pathname));
});

validateDemoDevices();

server.listen(port, "0.0.0.0", () => {
  console.log(`BlindNet demo bridge: http://localhost:${port}`);
  console.log(`Dispositivos configurados no DEMO_DEVICES: ${DEMO_DEVICES.length}`);
  DEMO_DEVICES.forEach((device) => {
    console.log(
      `- appId=${device.id} | deviceId=${device.deviceId ?? device.id} | ${device.label} | ${device.topic} | ${device.deviceSecret.slice(0, 8)}...${device.deviceSecret.slice(-8)}`,
    );
  });
  console.log(`Chave privada: ${privateKey}`);
});
