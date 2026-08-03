/**
 * BadUSB honeypot decoy terminal (client-side).
 *
 * Runs in a local browser window. Timing is measured only for keys entered in
 * this focused decoy, and every submitted command is contained rather than
 * executed on the host.
 */
(function () {
  const output = document.getElementById("output") as HTMLDivElement;
  const input = document.getElementById("input") as HTMLInputElement;
  const params = new URLSearchParams(window.location.search);
  const deviceKey = params.get("deviceKey");
  const deviceContext = deviceKey
    ? {
        deviceKey,
        deviceName: params.get("deviceName") || "USB keyboard/HID device",
        vendorId: params.get("vendorId") || undefined,
        productId: params.get("productId") || undefined,
      }
    : undefined;

  let keyTimestamps: number[] = [];

  function appendLine(text: string, className?: string): void {
    const line = document.createElement("div");
    line.className = className ? `line ${className}` : "line";
    line.textContent = text;
    output.appendChild(line);
    output.scrollTop = output.scrollHeight;
  }

  input.addEventListener("keydown", (event) => {
    if (event.key !== "Enter") keyTimestamps.push(performance.now());
  });

  input.addEventListener("keydown", async (event) => {
    if (event.key !== "Enter") return;
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
        body: JSON.stringify({ commandText, keyTimestamps: submittedTimestamps, deviceContext }),
      });
      const result = await response.json();
      const verdict = result.assessment?.verdict;
      const lineClass = verdict === "harmful" ? "blocked-line" : verdict === "suspicious" ? "suspicious-line" : "contained-line";
      appendLine(result.reason || "Command contained.", lineClass);
    } catch {
      appendLine("(connection to Overseer agent lost)", "stderr-line");
    }
  });

  input.focus();
  document.addEventListener("click", () => input.focus());
})();
