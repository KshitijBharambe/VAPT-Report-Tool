const test = require("node:test");
const assert = require("node:assert/strict");

const { buildAdapterFailureMessage } = require("./adapter-error");

test("prefers adapter stdout JSON error over progress-only stderr", () => {
  const message = buildAdapterFailureMessage({
    stdout: JSON.stringify({
      ok: false,
      error:
        "Structured findings missing required source-of-truth fields: VAPT-001: description",
    }),
    stderr:
      '__PROGRESS__{"stage":"read","current":0,"total":1,"message":"Reading scan file…"}\n' +
      '__PROGRESS__{"stage":"per_vuln","current":1,"total":32,"message":"Cloud lookup progress 1/32"}\n',
    code: 1,
  });

  assert.equal(
    message,
    "Structured findings missing required source-of-truth fields: VAPT-001: description",
  );
});

test("falls back to non-progress stderr text when stdout has no JSON error", () => {
  const message = buildAdapterFailureMessage({
    stdout: "",
    stderr:
      '__PROGRESS__{"stage":"read","current":0,"total":1,"message":"Reading scan file…"}\n' +
      "Traceback: adapter exploded\n",
    code: 1,
  });

  assert.equal(message, "Traceback: adapter exploded");
});

test("prefers trailing stdout JSON error even when warning text precedes it", () => {
  const message = buildAdapterFailureMessage({
    stdout:
      "⚠️ Structured lookup JSON parse failed for SSL Certificate Cannot Be Trusted; retrying once.\n" +
      JSON.stringify({
        ok: false,
        error:
          "OpenRouter HTTP 429: Rate limit exceeded for model. Retry-After: 30 seconds.",
      }),
    stderr: "",
    code: 1,
  });

  assert.equal(
    message,
    "OpenRouter HTTP 429: Rate limit exceeded for model. Retry-After: 30 seconds.",
  );
});
