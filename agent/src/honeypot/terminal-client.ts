/**
 * Sentinel Agent — BadUSB honeypot decoy terminal (client-side).
 *
 * Runs in a real browser window (bundled to public/honeypot.js by
 * esbuild). Looks like a terminal, but every keystroke's timestamp is
 * captured in-browser and each submitted line goes through the two-layer
 * gate in honeypot/session.ts on the server before it's allowed to
 * actually execute. This page never runs anything itself — it only
 * displays what the server decided.
 */
(function () {
  const output = document.getElementById("output") as HTMLDivElement;
  const input = document.getElementById("input") as HTMLInputElement;

  let keyTimestamps: number[] = [];

  function appendLine(text: string, className?: string): void {
    const line = document.createElement("div");
    line.className = className ? `line ${className}` : "line";
    line.textContent = text;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
  }

  input.addEventListener("keydown", (e) => {
    if (e.key !== "Enter") {
      keyTimestamps.push(performance.now());
    }
  });

  input.addEventListener("keydown", async (e) => {
    if (e.key !== "Enter") return;
    const commandText = input.value;
    if (!commandText.trim()) return;

    appendLine(`$ ${commandText}`, "prompt-line");
    input.value = "";
    const submittedTimestamps = keyTimestamps;
    keyTimestamps = [];

    try {
      const response = await fetch("/api/honeypot/command", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ commandText, keyTimestamps: submittedTimestamps }),
      });
      const result = await response.json();

      if (!result.allowed) {
        appendLine(result.reason || "Command blocked.", "blocked-line");
      } else {
        if (result.stdout) appendLine(result.stdout);
        if (result.stderr) appendLine(result.stderr, "stderr-line");
      }
    } catch {
      appendLine("(connection to sentinel agent lost)", "stderr-line");
    }
  });

  input.focus();
  document.addEventListener("click", () => input.focus());
})();
