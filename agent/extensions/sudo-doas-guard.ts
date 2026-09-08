import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// Matches sudo/doas as a command word at segment start, with optional path prefix
// and optional shell wrappers (command, exec, nohup, etc.).
const SUDO_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:[A-Za-z_][A-Za-z0-9_]*=\S*\s+)*(?:(?:command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:sudo|doas)\b/;

const BLOCK_REASON =
  "Blocked: privilege escalation via 'sudo' or 'doas' is disabled.\n" +
  "- If a command needs elevated permissions, ask the user to run it manually.";

function isPrivilegeEscalation(cmd: string): boolean {
  return SUDO_PATTERN.test(cmd);
}

export default function sudoDoasGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event: ToolCallEvent, _ctx: ExtensionContext) => {
    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      if (isPrivilegeEscalation(event.input.command)) {
        return { block: true, reason: BLOCK_REASON };
      }
    }

    if (event.toolName === "eval" && typeof event.input?.code === "string") {
      if (isPrivilegeEscalation(event.input.code)) {
        return { block: true, reason: BLOCK_REASON };
      }
    }
  });
}
