function parseAdapterStdoutError(stdout) {
  const trimmed = (stdout || "").trim();
  if (!trimmed) {
    return "";
  }

  try {
    const parsed = JSON.parse(trimmed);
    if (
      parsed &&
      typeof parsed === "object" &&
      typeof parsed.error === "string"
    ) {
      return parsed.error.trim();
    }
  } catch (_err) {
    // Fall through to raw stdout handling.
  }

  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter(Boolean);
  for (let index = lines.length - 1; index >= 0; index -= 1) {
    try {
      const parsed = JSON.parse(lines[index]);
      if (
        parsed &&
        typeof parsed === "object" &&
        typeof parsed.error === "string"
      ) {
        return parsed.error.trim();
      }
    } catch (_err) {
      // Keep scanning upward for a trailing JSON error line.
    }
  }

  return trimmed;
}

function stripProgressLines(stderr) {
  return (stderr || "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("__PROGRESS__"))
    .join("\n");
}

function buildAdapterFailureMessage({ stdout = "", stderr = "", code } = {}) {
  const stdoutError = parseAdapterStdoutError(stdout);
  if (stdoutError) {
    return stdoutError;
  }

  const stderrError = stripProgressLines(stderr);
  if (stderrError) {
    return stderrError;
  }

  return `Adapter exited with code ${code}`;
}

module.exports = {
  buildAdapterFailureMessage,
};
