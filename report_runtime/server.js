const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { buildAdapterFailureMessage } = require("./adapter-error");
const {
  DEFAULT_BASE_URLS,
  normalizeSettings,
  sanitizePersistedSettings,
  mergeAnalyzePayloadWithSettings,
} = require("./settings");

const HOST = process.env.REPORT_RUNTIME_HOST || process.env.OATS_HOST || "127.0.0.1";
const PORT = Number(process.env.REPORT_RUNTIME_PORT || process.env.OATS_PORT || 8787);
const ROOT_DIR = path.resolve(__dirname, "..");
const RUNTIME_DIR = path.resolve(__dirname);
const PUBLIC_DIR = path.join(__dirname, "public");
const PY_ADAPTER = path.join(__dirname, "py_adapter.py");
const CONFIG_PATH = path.join(ROOT_DIR, "config.json");
const SETTINGS_PATH = path.join(RUNTIME_DIR, "settings.json");
const TEMPLATE_DIR = path.join(RUNTIME_DIR, "templates");
const DEFAULT_TEMPLATE_FILE = "uploaded-base-template.docx";
const ENTRY_TTL_MS = 10 * 60 * 1000;

const analyses = new Map();
const downloads = new Map();
const analyzeJobs = new Map();
const generateJobs = new Map();

// ── History persistence ───────────────────────────────────────────────────────
const HISTORY_PATH = path.join(ROOT_DIR, "outputs", "history", "history.json");
const HISTORY_MAX = 200;

function resolveExistingProjectFile(candidatePath) {
  const resolved = resolveProjectPath(candidatePath);
  if (!resolved || !fs.existsSync(resolved) || !fs.statSync(resolved).isFile()) {
    return "";
  }
  return resolved;
}

function findGeneratedReportPath(fileName) {
  const safeName = path.basename(String(fileName || "").trim());
  if (!safeName) {
    return "";
  }
  const outputsDir = path.join(ROOT_DIR, "outputs");
  if (!fs.existsSync(outputsDir)) {
    return "";
  }

  const queue = [outputsDir];
  while (queue.length > 0) {
    const currentDir = queue.shift();
    let entries = [];
    try {
      entries = fs.readdirSync(currentDir, { withFileTypes: true });
    } catch (_err) {
      continue;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) {
        queue.push(fullPath);
        continue;
      }
      if (entry.isFile() && entry.name === safeName) {
        return fullPath;
      }
    }
  }

  return "";
}

function normalizeHistoryEntry(entry) {
  const raw = entry && typeof entry === "object" ? entry : {};
  const analysisData =
    raw.analysis_data && typeof raw.analysis_data === "object"
      ? { ...raw.analysis_data }
      : {};
  const findings = Array.isArray(raw.findings)
    ? raw.findings
    : Array.isArray(analysisData.findings)
      ? analysisData.findings
      : [];
  const reportPath =
    resolveExistingProjectFile(raw.report_path || raw.output_path) ||
    findGeneratedReportPath(raw.file_name);
  const logPath = resolveExistingProjectFile(raw.log_path);

  return {
    id: String(raw.id || crypto.randomUUID()),
    date: raw.date ? String(raw.date) : "",
    input_name: String(raw.input_name || raw.source_file || "").trim(),
    source_file: String(raw.source_file || "").trim(),
    finding_count:
      raw.finding_count != null
        ? Number(raw.finding_count) || 0
        : findings.length,
    file_name: String(raw.file_name || "").trim(),
    report_path: reportPath ? toProjectRelativePath(reportPath) : "",
    log_path: logPath ? toProjectRelativePath(logPath) : "",
    findings,
    analysis_data: {
      ...analysisData,
      findings,
      _input_name: String(
        analysisData._input_name || raw.input_name || raw.source_file || "",
      ).trim(),
      _source_file: String(
        analysisData._source_file || raw.source_file || raw.input_name || "",
      ).trim(),
      _run_log_path: String(
        analysisData._run_log_path || raw.log_path || "",
      ).trim(),
    },
  };
}

function readHistory() {
  try {
    if (!fs.existsSync(HISTORY_PATH)) {
      return [];
    }
    const parsed = JSON.parse(fs.readFileSync(HISTORY_PATH, "utf8"));
    if (!Array.isArray(parsed)) {
      return [];
    }
    return parsed.map((entry) => normalizeHistoryEntry(entry));
  } catch (_) {
    return [];
  }
}

function appendHistory(entry) {
  try {
    const hist = readHistory();
    hist.unshift(normalizeHistoryEntry(entry));
    const trimmed = hist.slice(0, HISTORY_MAX);
    fs.mkdirSync(path.dirname(HISTORY_PATH), { recursive: true });
    fs.writeFileSync(HISTORY_PATH, JSON.stringify(trimmed, null, 2), "utf8");
  } catch (err) {
    // History write failure must never break report generation
    console.error("History write failed:", err.message || err);
  }
}

function setExpiringEntry(mapRef, key, value) {
  mapRef.set(key, value);
  const timer = setTimeout(() => {
    mapRef.delete(key);
  }, ENTRY_TTL_MS);
  if (typeof timer.unref === "function") {
    timer.unref();
  }
}

function jsonResponse(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function textResponse(
  res,
  status,
  body,
  contentType = "text/plain; charset=utf-8",
) {
  res.writeHead(status, {
    "Content-Type": contentType,
    "Content-Length": Buffer.byteLength(body),
    "Cache-Control": "no-store",
  });
  res.end(body);
}

function downloadFile(res, filePath, downloadName, contentType) {
  const fileBuffer = fs.readFileSync(filePath);
  const safeFileName = String(downloadName || path.basename(filePath)).replaceAll(
    /[^\w.\-]/g,
    "_",
  );
  res.writeHead(200, {
    "Content-Type": contentType || "application/octet-stream",
    "Content-Disposition": `attachment; filename="${safeFileName}"`,
    "Content-Length": fileBuffer.length,
    "Cache-Control": "no-store",
  });
  res.end(fileBuffer);
}

function readJsonBody(req, limitBytes = 20 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let received = 0;
    const chunks = [];

    req.on("data", (chunk) => {
      received += chunk.length;
      if (received > limitBytes) {
        reject(new Error("Request body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });

    req.on("end", () => {
      try {
        const raw = Buffer.concat(chunks).toString("utf8");
        resolve(raw ? JSON.parse(raw) : {});
      } catch (err) {
        reject(new Error("Invalid JSON body"));
      }
    });

    req.on("error", (err) => reject(err));
  });
}

function resolvePythonBinary() {
  const fromEnv = process.env.PYTHON_BIN;
  if (fromEnv) {
    return fromEnv;
  }

  const venvPython = path.join(ROOT_DIR, ".venv", "bin", "python");
  if (fs.existsSync(venvPython)) {
    return venvPython;
  }

  return process.platform === "win32" ? "python" : "python3";
}

function parseProgressLine(rawLine) {
  if (!rawLine.startsWith("__PROGRESS__")) {
    return null;
  }
  const payload = rawLine.slice("__PROGRESS__".length);
  try {
    return JSON.parse(payload);
  } catch (_err) {
    return null;
  }
}

function spawnAdapter(payload, onProgress) {
  const pythonBin = resolvePythonBinary();
  const pythonPath = process.env.PYTHONPATH
    ? `${ROOT_DIR}:${process.env.PYTHONPATH}`
    : ROOT_DIR;
  const child = spawn(pythonBin, [PY_ADAPTER], {
    cwd: ROOT_DIR,
    stdio: ["pipe", "pipe", "pipe"],
    env: {
      ...process.env,
      PYTHONPATH: pythonPath,
    },
  });

  const completion = new Promise((resolve, reject) => {
    const stdoutChunks = [];
    const stderrChunks = [];
    let stderrBuffer = "";

    child.stdout.on("data", (chunk) => stdoutChunks.push(chunk));
    child.stderr.on("data", (chunk) => {
      const text = chunk.toString("utf8");
      stderrChunks.push(chunk);
      stderrBuffer += text;

      while (true) {
        const idx = stderrBuffer.indexOf("\n");
        if (idx === -1) {
          break;
        }
        const line = stderrBuffer.slice(0, idx).trim();
        stderrBuffer = stderrBuffer.slice(idx + 1);
        if (!line) {
          continue;
        }
        const progress = parseProgressLine(line);
        if (progress && typeof onProgress === "function") {
          onProgress(progress);
        } else if (typeof onProgress === "function") {
          // Forward raw stderr warnings so they appear in the UI log panel
          // rather than being silently discarded (LLM errors, ⚠️ messages, etc.)
          onProgress({
            stage: "warn",
            current: 0,
            total: 1,
            message: `[stderr] ${line}`,
          });
        }
      }
    });

    child.on("error", (err) => reject(err));

    child.on("close", (code) => {
      const stdout = Buffer.concat(stdoutChunks).toString("utf8");
      const stderr = Buffer.concat(stderrChunks).toString("utf8");

      if (code !== 0) {
        reject(new Error(buildAdapterFailureMessage({ stdout, stderr, code })));
        return;
      }

      try {
        resolve(JSON.parse(stdout));
      } catch (_err) {
        reject(new Error(`Adapter returned invalid JSON: ${stdout}`));
      }
    });
  });

  child.stdin.write(JSON.stringify(payload));
  child.stdin.end();
  return { child, completion };
}

async function callAdapter(payload) {
  const { completion } = spawnAdapter(payload);
  return completion;
}

function serveStatic(req, res) {
  const urlPath = req.url === "/" ? "/index.html" : req.url;
  const safePath = path.normalize(urlPath).replace(/^\.+/, "");
  const fullPath = path.join(PUBLIC_DIR, safePath);

  if (!fullPath.startsWith(PUBLIC_DIR)) {
    textResponse(res, 403, "Forbidden");
    return;
  }

  fs.readFile(fullPath, (err, content) => {
    if (err) {
      textResponse(res, 404, "Not found");
      return;
    }

    const ext = path.extname(fullPath).toLowerCase();
    const contentType =
      ext === ".html"
        ? "text/html; charset=utf-8"
        : ext === ".js"
          ? "text/javascript; charset=utf-8"
          : ext === ".css"
            ? "text/css; charset=utf-8"
            : "application/octet-stream";

    res.writeHead(200, {
      "Content-Type": contentType,
      "Content-Length": content.length,
      "Cache-Control": "no-store",
    });
    res.end(content);
  });
}

function resolveProjectPath(candidatePath) {
  const rawPath = String(candidatePath || "").trim();
  if (!rawPath) {
    return "";
  }
  const resolved = path.resolve(
    path.isAbsolute(rawPath) ? rawPath : path.join(ROOT_DIR, rawPath),
  );
  if (resolved !== ROOT_DIR && !resolved.startsWith(ROOT_DIR + path.sep)) {
    return "";
  }
  return resolved;
}

function toProjectRelativePath(targetPath) {
  return path.relative(ROOT_DIR, targetPath).split(path.sep).join("/");
}

function getPersistedTemplateInfo(settings) {
  const resolved = resolveProjectPath(settings && settings.template_path);
  if (
    !resolved ||
    path.extname(resolved).toLowerCase() !== ".docx" ||
    !fs.existsSync(resolved)
  ) {
    return null;
  }
  return {
    source: "persisted-default",
    name: (settings && settings.template_name) || path.basename(resolved),
    path: toProjectRelativePath(resolved),
  };
}

function getTemplateState(settings) {
  const persisted = getPersistedTemplateInfo(settings);
  return {
    has_template: Boolean(persisted),
    active: persisted,
  };
}

function persistUploadedTemplate(filename, templateContentBase64) {
  const originalName = path.basename(String(filename || "").trim());
  if (!originalName || path.extname(originalName).toLowerCase() !== ".docx") {
    throw new Error("Uploaded template must be a .docx file.");
  }
  const rawContent = String(templateContentBase64 || "").trim();
  if (!rawContent) {
    throw new Error("template_content_base64 is required for uploaded templates.");
  }
  const templateBytes = Buffer.from(rawContent, "base64");
  fs.mkdirSync(TEMPLATE_DIR, { recursive: true });
  const storedTemplatePath = path.join(TEMPLATE_DIR, DEFAULT_TEMPLATE_FILE);
  fs.writeFileSync(storedTemplatePath, templateBytes);
  return {
    template_path: toProjectRelativePath(storedTemplatePath),
    template_name: originalName,
  };
}

function readRuntimeConfig() {
  try {
    const raw = fs.readFileSync(CONFIG_PATH, "utf8");
    const cfg = JSON.parse(raw);
    const llm = cfg.llm || {};
    return {
      provider: llm.provider || "local",
      model: "",
      base_url: llm.base_url || DEFAULT_BASE_URLS.local,
      context: "",
    };
  } catch (_err) {
    return {
      provider: "local",
      model: "",
      base_url: DEFAULT_BASE_URLS.local,
      context: "",
    };
  }
}

function readPersistedSettings() {
  try {
    const raw = fs.readFileSync(SETTINGS_PATH, "utf8");
    const parsed = JSON.parse(raw);
    const sanitized = sanitizePersistedSettings(parsed);
    const resolvedTemplatePath = resolveProjectPath(sanitized.template_path);
    if (!resolvedTemplatePath) {
      sanitized.template_path = "";
      sanitized.template_name = "";
    } else if (
      path.extname(resolvedTemplatePath).toLowerCase() !== ".docx" ||
      !fs.existsSync(resolvedTemplatePath)
    ) {
      sanitized.template_path = "";
      sanitized.template_name = "";
    }
    if (JSON.stringify(parsed) !== JSON.stringify(sanitized)) {
      fs.writeFileSync(
        SETTINGS_PATH,
        JSON.stringify(sanitized, null, 2),
        "utf8",
      );
    }
    return sanitized;
  } catch (_err) {
    return normalizeSettings(readRuntimeConfig());
  }
}

function writePersistedSettings(settings) {
  const normalized = sanitizePersistedSettings({
    ...readPersistedSettings(),
    ...(settings || {}),
  });
  fs.writeFileSync(SETTINGS_PATH, JSON.stringify(normalized, null, 2), "utf8");
  return normalized;
}

function getProgressPayload(progress, fallbackMessage) {
  const safeCurrent = Number(progress && progress.current) || 0;
  const safeTotal = Math.max(1, Number(progress && progress.total) || 1);
  return {
    stage: (progress && progress.stage) || "running",
    current: safeCurrent,
    total: safeTotal,
    message: (progress && progress.message) || fallbackMessage,
    detail:
      progress && progress.detail && typeof progress.detail === "object"
        ? progress.detail
        : null,
  };
}

function markJobCanceled(job, message) {
  if (!job) {
    return;
  }
  job.status = "canceled";
  job.error = message || "Cancelled by user";
  job.progress = getProgressPayload(
    { stage: "canceled", current: 0, total: 1, message: job.error },
    job.error,
  );
}

function startAnalyzeJob(requestBody) {
  const settings = readPersistedSettings();
  const merged = mergeAnalyzePayloadWithSettings(requestBody, settings);
  const resolved = merged.settings;
  const runtimeApiKey = merged.runtimeApiKey;
  if (!String(resolved.model || "").trim()) {
    return { error: "Model selection is required before analyzing" };
  }
  writePersistedSettings(resolved);

  const fileName = String(requestBody.filename || "").trim();
  const fileContentBase64 = String(
    requestBody.file_content_base64 || "",
  ).trim();
  if (!fileName || !fileContentBase64) {
    return { error: "filename and file_content_base64 are required" };
  }

  const jobId = crypto.randomUUID();
  const job = {
    id: jobId,
    status: "running",
    created_at: Date.now(),
    progress: getProgressPayload(
      { stage: "queued", current: 0, total: 1, message: "Queued analysis job" },
      "Queued analysis job",
    ),
    error: null,
    result: null,
    child: null,
  };
  setExpiringEntry(analyzeJobs, jobId, job);

  const adapter = spawnAdapter(
    {
      action: "analyze",
      filename: fileName,
      file_content_base64: fileContentBase64,
      client_context: resolved.context,
      api_key: runtimeApiKey,
      provider: resolved.provider,
      model: resolved.model,
      base_url: resolved.base_url,
    },
    (progress) => {
      job.progress = getProgressPayload(progress, "Analyzing scan input...");
    },
  );

  job.child = adapter.child;
  adapter.completion
    .then((result) => {
      if (job.status === "canceled") {
        return;
      }
      if (!result || !result.ok) {
        job.status = "failed";
        job.error = (result && result.error) || "Analyze failed";
        return;
      }
      const analysisId = result.analysis_id || crypto.randomUUID();
      if (result.data && typeof result.data === "object") {
        result.data._input_name =
          String(result.data._input_name || fileName || "").trim() || fileName;
        result.data._run_log_path = String(result.run_log_path || "").trim();
      }
      setExpiringEntry(analyses, analysisId, result.data);
      job.status = "completed";
      job.progress = getProgressPayload(
        { stage: "done", current: 1, total: 1, message: "Analysis complete" },
        "Analysis complete",
      );
      job.result = {
        analysis_id: analysisId,
        finding_count: Array.isArray(result.data && result.data.findings)
          ? result.data.findings.length
          : 0,
        false_positive_count: Array.isArray(result.false_positives)
          ? result.false_positives.length
          : 0,
        llm_interaction_count:
          Number(result.llm_interaction_count) ||
          Number(result.data && result.data._llm_interaction_count) ||
          0,
        data: result.data,
        raw_texts: Array.isArray(result.raw_texts) ? result.raw_texts : [],
        run_log_path: String(result.run_log_path || "").trim(),
      };
    })
    .catch((err) => {
      if (job.status === "canceled") {
        return;
      }
      job.status = "failed";
      job.error = err && err.message ? err.message : String(err);
    });

  return { job_id: jobId };
}

function startGenerateJob(requestBody) {
  const analysisId = requestBody.analysis_id;
  const analysisData = analysisId
    ? analyses.get(analysisId)
    : requestBody.analysis_data;
  const settings = readPersistedSettings();

  if (!analysisData || typeof analysisData !== "object") {
    return { error: "analysis_id or analysis_data is required" };
  }

  const uploadedTemplateName = String(
    requestBody.template_filename || "",
  ).trim();
  const uploadedTemplateContent = String(
    requestBody.template_content_base64 || "",
  ).trim();
  let templatePath =
    String(requestBody.template_path || "").trim() || settings.template_path || "";

  if (uploadedTemplateName || uploadedTemplateContent) {
    if (!uploadedTemplateName || !uploadedTemplateContent) {
      return {
        error: "template_filename and template_content_base64 are required together",
      };
    }
    try {
      const persistedTemplate = persistUploadedTemplate(
        uploadedTemplateName,
        uploadedTemplateContent,
      );
      writePersistedSettings(persistedTemplate);
      templatePath = persistedTemplate.template_path;
    } catch (err) {
      return { error: err.message || String(err) };
    }
  }

  if (!templatePath) {
    return { error: "No report template found. Upload a .docx base template first." };
  }

  const jobId = crypto.randomUUID();
  const job = {
    id: jobId,
    status: "running",
    created_at: Date.now(),
    progress: getProgressPayload(
      {
        stage: "queued",
        current: 0,
        total: 1,
        message: "Queued generation job",
      },
      "Queued generation job",
    ),
    error: null,
    result: null,
    child: null,
  };
  setExpiringEntry(generateJobs, jobId, job);

  const adapter = spawnAdapter({
    action: "generate",
    analysis_data: analysisData,
    template_path: templatePath,
    include_summary_table: requestBody.include_summary_table !== false,
  });

  job.child = adapter.child;
  adapter.completion
    .then((result) => {
      if (job.status === "canceled") {
        return;
      }
      if (!result || !result.ok) {
        job.status = "failed";
        job.error = (result && result.error) || "Generate failed";
        return;
      }

      const historyId = crypto.randomUUID();
      setExpiringEntry(downloads, historyId, {
        fileName: result.file_name || "report.docx",
        bytes: Buffer.from(result.docx_base64, "base64"),
      });

      job.status = "completed";
      job.progress = getProgressPayload(
        { stage: "done", current: 1, total: 1, message: "Report generated" },
        "Report generated",
      );
      job.result = {
        file_name: result.file_name,
        output_path: result.output_path,
        download_url: `/api/history/${historyId}/report`,
        history_id: historyId,
      };

      // Append to persistent history
      appendHistory({
        id: historyId,
        date: new Date().toISOString(),
        input_name:
          (analysisData && analysisData._input_name) ||
          (analysisData && analysisData._source_file) ||
          "unknown",
        source_file: (analysisData && analysisData._source_file) || "unknown",
        finding_count: Array.isArray(analysisData && analysisData.findings)
          ? analysisData.findings.length
          : 0,
        file_name: result.file_name,
        report_path: result.output_path,
        log_path: analysisData && analysisData._run_log_path,
        analysis_data: analysisData,
        findings: Array.isArray(analysisData && analysisData.findings)
          ? analysisData.findings
          : [],
      });
    })
    .catch((err) => {
      if (job.status === "canceled") {
        return;
      }
      job.status = "failed";
      job.error = err && err.message ? err.message : String(err);
    });

  return { job_id: jobId };
}

async function handleSettingsGet(_req, res) {
  const settings = readPersistedSettings();
  jsonResponse(res, 200, {
    ok: true,
    settings,
    defaults: { base_urls: DEFAULT_BASE_URLS },
    template: getTemplateState(settings),
  });
}

async function handleSettingsPut(req, res) {
  const body = await readJsonBody(req);
  const settings = writePersistedSettings(body || {});
  jsonResponse(res, 200, { ok: true, settings });
}

async function handleModels(req, res) {
  const body = await readJsonBody(req);
  const settings = readPersistedSettings();
  const merged = mergeAnalyzePayloadWithSettings(body || {}, settings);
  const resolved = merged.settings;
  const runtimeApiKey = merged.runtimeApiKey;

  let result;
  try {
    result = await callAdapter({
      action: "models",
      provider: resolved.provider,
      base_url: resolved.base_url,
      api_key: runtimeApiKey,
    });
  } catch (err) {
    jsonResponse(res, 502, {
      ok: false,
      error: (err && err.message) || "Model fetch failed",
      models: [],
    });
    return;
  }

  if (!result || !result.ok) {
    jsonResponse(res, 502, {
      ok: false,
      error: (result && result.error) || "Model fetch failed",
      models: [],
    });
    return;
  }
  jsonResponse(res, 200, { ok: true, models: result.models || [] });
}

async function handleAnalyze(req, res) {
  const body = await readJsonBody(req);
  const started = startAnalyzeJob(body || {});
  if (started.error) {
    jsonResponse(res, 400, { error: started.error });
    return;
  }
  jsonResponse(res, 202, { ok: true, job_id: started.job_id });
}

async function handleGenerate(req, res) {
  const body = await readJsonBody(req);
  const started = startGenerateJob(body || {});
  if (started.error) {
    jsonResponse(res, 400, { error: started.error });
    return;
  }
  jsonResponse(res, 202, { ok: true, job_id: started.job_id });
}

function handleAnalyzeStatus(req, res) {
  const parts = req.url.split("/");
  const jobId = parts[parts.length - 1];
  const job = analyzeJobs.get(jobId);
  if (!job) {
    jsonResponse(res, 404, { error: "Analysis job not found or expired" });
    return;
  }

  jsonResponse(res, 200, {
    ok: true,
    job_id: jobId,
    status: job.status,
    progress: getProgressPayload(job.progress, "Analyzing..."),
    error: job.error,
    result: job.result,
  });
}

function handleAnalyzeCancel(req, res) {
  const parts = req.url.split("/");
  const jobId = parts[parts.length - 2];
  const job = analyzeJobs.get(jobId);
  if (!job) {
    jsonResponse(res, 404, { error: "Analysis job not found or expired" });
    return;
  }
  if (job.status !== "running") {
    jsonResponse(res, 200, { ok: true, status: job.status });
    return;
  }

  markJobCanceled(job, "Analysis canceled by user");
  if (job.child && !job.child.killed) {
    job.child.kill("SIGTERM");
  }
  jsonResponse(res, 200, { ok: true, status: "canceled" });
}

function handleGenerateStatus(req, res) {
  const parts = req.url.split("/");
  const jobId = parts[parts.length - 1];
  const job = generateJobs.get(jobId);
  if (!job) {
    jsonResponse(res, 404, { error: "Generate job not found or expired" });
    return;
  }

  jsonResponse(res, 200, {
    ok: true,
    job_id: jobId,
    status: job.status,
    progress: getProgressPayload(job.progress, "Generating report..."),
    error: job.error,
    result: job.result,
  });
}

function handleGenerateCancel(req, res) {
  const parts = req.url.split("/");
  const jobId = parts[parts.length - 2];
  const job = generateJobs.get(jobId);
  if (!job) {
    jsonResponse(res, 404, { error: "Generate job not found or expired" });
    return;
  }
  if (job.status !== "running") {
    jsonResponse(res, 200, { ok: true, status: job.status });
    return;
  }

  markJobCanceled(job, "Generation canceled by user");
  if (job.child && !job.child.killed) {
    job.child.kill("SIGTERM");
  }
  jsonResponse(res, 200, { ok: true, status: "canceled" });
}

function handleDownload(req, res) {
  const parts = req.url.split("/");
  const id = parts[parts.length - 1];
  const item = downloads.get(id);

  if (item) {
    const safeFileName = String(item.fileName || "report.docx").replaceAll(
      /[^\w.\-]/g,
      "_",
    );

    res.writeHead(200, {
      "Content-Type":
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "Content-Disposition": `attachment; filename="${safeFileName}"`,
      "Content-Length": item.bytes.length,
      "Cache-Control": "no-store",
    });
    res.end(item.bytes);
    return;
  }

  const historyEntry = readHistory().find((entry) => entry.id === id);
  const reportPath = historyEntry && resolveExistingProjectFile(historyEntry.report_path);
  if (!historyEntry || !reportPath) {
    jsonResponse(res, 404, { error: "Download not found or expired" });
    return;
  }

  downloadFile(
    res,
    reportPath,
    historyEntry.file_name || path.basename(reportPath),
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  );
}

function handleHistory(_req, res) {
  const history = readHistory().map((entry) => ({
    ...entry,
    report_download_url: entry.report_path ? `/api/history/${entry.id}/report` : "",
    log_download_url: entry.log_path ? `/api/history/${entry.id}/log` : "",
  }));
  jsonResponse(res, 200, { ok: true, history });
}

function handleHistoryArtifact(req, res) {
  const match = req.url.match(/^\/api\/history\/([^/]+)\/(report|log)$/);
  if (!match) {
    jsonResponse(res, 404, { error: "History artifact not found" });
    return;
  }

  const [, id, artifactType] = match;
  const historyEntry = readHistory().find((entry) => entry.id === id);
  if (!historyEntry) {
    jsonResponse(res, 404, { error: "History entry not found" });
    return;
  }

  if (artifactType === "report") {
    const reportPath = resolveExistingProjectFile(historyEntry.report_path);
    if (!reportPath) {
      jsonResponse(res, 404, { error: "Generated report file no longer exists" });
      return;
    }
    downloadFile(
      res,
      reportPath,
      historyEntry.file_name || path.basename(reportPath),
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    );
    return;
  }

  const logPath = resolveExistingProjectFile(historyEntry.log_path);
  if (!logPath) {
    jsonResponse(res, 404, { error: "Run log file no longer exists" });
    return;
  }
  downloadFile(
    res,
    logPath,
    path.basename(logPath),
    "application/json; charset=utf-8",
  );
}

const server = http.createServer(async (req, res) => {
  try {
    if (req.method === "GET" && req.url === "/api/health") {
      jsonResponse(res, 200, { status: "ok", service: "report-tool-runtime" });
      return;
    }

    if (req.method === "GET" && req.url === "/api/config") {
      jsonResponse(res, 200, readRuntimeConfig());
      return;
    }

    if (req.method === "GET" && req.url === "/api/settings") {
      await handleSettingsGet(req, res);
      return;
    }

    if (req.method === "PUT" && req.url === "/api/settings") {
      await handleSettingsPut(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/models") {
      await handleModels(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/analyze") {
      await handleAnalyze(req, res);
      return;
    }

    if (req.method === "GET" && /^\/api\/analyze\/[^/]+$/.test(req.url)) {
      handleAnalyzeStatus(req, res);
      return;
    }

    if (
      req.method === "POST" &&
      /^\/api\/analyze\/[^/]+\/cancel$/.test(req.url)
    ) {
      handleAnalyzeCancel(req, res);
      return;
    }

    if (req.method === "POST" && req.url === "/api/generate") {
      await handleGenerate(req, res);
      return;
    }

    if (req.method === "GET" && /^\/api\/generate\/[^/]+$/.test(req.url)) {
      handleGenerateStatus(req, res);
      return;
    }

    if (
      req.method === "POST" &&
      /^\/api\/generate\/[^/]+\/cancel$/.test(req.url)
    ) {
      handleGenerateCancel(req, res);
      return;
    }

    if (req.method === "GET" && req.url === "/api/history") {
      handleHistory(req, res);
      return;
    }

    if (req.method === "GET" && /^\/api\/history\/[^/]+\/(report|log)$/.test(req.url)) {
      handleHistoryArtifact(req, res);
      return;
    }

    if (req.method === "GET" && req.url.startsWith("/api/download/")) {
      handleDownload(req, res);
      return;
    }

    if (req.method === "GET") {
      serveStatic(req, res);
      return;
    }

    jsonResponse(res, 404, { error: "Not found" });
  } catch (err) {
    jsonResponse(res, 500, { error: err.message || String(err) });
  }
});

server.listen(PORT, HOST, () => {
  // eslint-disable-next-line no-console
  console.log(`report runtime listening at http://${HOST}:${PORT}`);
});
