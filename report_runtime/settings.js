const DEFAULT_BASE_URLS = {
  local: "http://127.0.0.1:1234/v1",
  openrouter: "https://openrouter.ai/api/v1",
};

const PROVIDER_HOST_HINTS = {
  openrouter: ["openrouter.ai"],
  local: ["127.0.0.1", "localhost", "0.0.0.0"],
};

function normalizeProvider(value) {
  const provider = (value || "local").toString().trim().toLowerCase();
  return provider === "openrouter" ? "openrouter" : "local";
}

function isBaseUrlSafeForProvider(provider, baseUrl) {
  if (!baseUrl) {
    return false;
  }
  let host = "";
  try {
    host = new URL(baseUrl).hostname.toLowerCase();
  } catch (_err) {
    return false;
  }
  const hints = PROVIDER_HOST_HINTS[provider] || [];
  return hints.some((hint) => host === hint || host.endsWith("." + hint));
}

function normalizeSettings(input) {
  const source = input || {};
  const provider = normalizeProvider(source.provider);
  const rawBaseUrl = (source.base_url || "").toString().trim();
  const defaultBaseUrl = DEFAULT_BASE_URLS[provider];
  const baseUrl =
    rawBaseUrl && isBaseUrlSafeForProvider(provider, rawBaseUrl)
      ? rawBaseUrl
      : defaultBaseUrl;

  return {
    provider,
    model: (source.model || "").toString().trim(),
    base_url: baseUrl,
    context: (source.context || "").toString(),
    template_path: (source.template_path || "").toString().trim(),
    template_name: (source.template_name || "").toString().trim(),
  };
}

function sanitizePersistedSettings(input) {
  const normalized = normalizeSettings(input);
  return {
    ...normalized,
    model: "",
  };
}

function mergeAnalyzePayloadWithSettings(body, settings) {
  const request = body || {};
  const persisted = normalizeSettings(settings || {});

  const mergedSettings = normalizeSettings({
    provider: request.provider || persisted.provider,
    model: request.model || persisted.model,
    base_url: request.base_url || persisted.base_url,
    context: request.client_context || request.context || persisted.context,
  });

  return {
    settings: mergedSettings,
    runtimeApiKey: (request.api_key || "").toString(),
  };
}

module.exports = {
  DEFAULT_BASE_URLS,
  PROVIDER_HOST_HINTS,
  normalizeSettings,
  sanitizePersistedSettings,
  mergeAnalyzePayloadWithSettings,
  isBaseUrlSafeForProvider,
};
