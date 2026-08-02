/**
 * Deterministic catastrophic-command safety check.
 *
 * The honeypot is a pure decoy and never executes submitted commands. These
 * patterns force a harmful verdict without depending on an AI response.
 */
import { CATASTROPHIC_COMMAND_PATTERNS } from "../shared/constants.ts";

export function isCatastrophicCommand(commandText: string): boolean {
  return CATASTROPHIC_COMMAND_PATTERNS.some((pattern) => pattern.test(commandText));
}
