const test = require("node:test");
const assert = require("node:assert/strict");

const {
  normalizeSettings,
  mergeAnalyzePayloadWithSettings,
  sanitizePersistedSettings,
  isBaseUrlSafeForProvider,
} = require("./settings");

test("normalizeSettings excludes api_key from persisted settings", () => {
  const settings = normalizeSettings({
    provider: "openrouter",
    model: "user-selected-model",
    base_url: "https://openrouter.ai/api/v1",
    api_key: "should-not-be-kept",
    context: "ctx",
    template_path: "report_runtime/templates/default-template.docx",
    template_name: "Base Template.docx",
  });

  assert.equal(settings.provider, "openrouter");
  assert.equal(settings.model, "user-selected-model");
  assert.equal(settings.base_url, "https://openrouter.ai/api/v1");
  assert.equal(settings.context, "ctx");
  assert.equal(
    settings.template_path,
    "report_runtime/templates/default-template.docx",
  );
  assert.equal(settings.template_name, "Base Template.docx");
  assert.equal(Object.hasOwn(settings, "api_key"), false);
});

test("sanitizePersistedSettings removes stale api_key fields", () => {
  const sanitized = sanitizePersistedSettings({
    provider: "local",
    api_key: "stale-key",
    model: "user-selected-model",
    template_path: "report_runtime/templates/default-template.docx",
    template_name: "Stored Template.docx",
  });

  assert.equal(Object.hasOwn(sanitized, "api_key"), false);
  assert.equal(sanitized.provider, "local");
  assert.equal(sanitized.model, "");
  assert.equal(
    sanitized.template_path,
    "report_runtime/templates/default-template.docx",
  );
  assert.equal(sanitized.template_name, "Stored Template.docx");
});

test("normalizeSettings rewrites unsafe openrouter base_url to default", () => {
  const settings = normalizeSettings({
    provider: "openrouter",
    base_url: "https://openrouter.com/api/v1/",
  });
  assert.equal(settings.base_url, "https://openrouter.ai/api/v1");
});

test("normalizeSettings rewrites unsafe local base_url to default", () => {
  const settings = normalizeSettings({
    provider: "local",
    base_url: "https://openrouter.ai/api/v1",
  });
  assert.equal(settings.base_url, "http://127.0.0.1:1234/v1");
});

test("isBaseUrlSafeForProvider validates host suffix", () => {
  assert.equal(
    isBaseUrlSafeForProvider("openrouter", "https://openrouter.ai/api/v1"),
    true,
  );
  assert.equal(
    isBaseUrlSafeForProvider("openrouter", "https://openrouter.com/api/v1"),
    false,
  );
  assert.equal(
    isBaseUrlSafeForProvider("local", "http://localhost:11434/v1"),
    true,
  );
  assert.equal(isBaseUrlSafeForProvider("local", "garbage"), false);
});

test("mergeAnalyzePayloadWithSettings keeps api key only in runtime payload", () => {
  const merged = mergeAnalyzePayloadWithSettings(
    {
      provider: "openrouter",
      api_key: "session-key",
    },
    {
      provider: "local",
      model: "qwen",
      base_url: "http://127.0.0.1:1234/v1",
      context: "stored",
    },
  );

  assert.equal(merged.settings.provider, "openrouter");
  assert.equal(Object.hasOwn(merged.settings, "api_key"), false);
  assert.equal(merged.runtimeApiKey, "session-key");
});
