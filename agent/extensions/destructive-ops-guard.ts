import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// Pipe-to-shell: curl/wget piped to a shell interpreter.
// Matches "curl ... | sh", "wget ... | bash", process substitution "sh <(curl ...)"
const PIPE_TO_SHELL_PATTERN =
  /(?:curl|wget)\b[^\n;&|]*?\|\s*(?:\/[^\s]*\/)?(?:sh|bash|zsh|fish|dash|ksh)\b/;
const PROC_SUB_PATTERN =
  /(?:sh|bash|zsh|fish|dash|ksh)\b[^\n;&|]*?<\((?:curl|wget)\b/;

// Package/container publishing
const PUBLISH_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:npm|pnpm|yarn|cargo)\s+publish\b/;
const TWINE_UPLOAD_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?twine\s+upload\b/;
const DOCKER_PUSH_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:docker|podman|buildah)\s+push\b/;
const DOTNET_PUSH_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?dotnet\s+nuget\s+push\b/;

// System power commands — bare binaries
const POWER_BARE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:shutdown|reboot|halt|poweroff|telinit)\b/;
// init 0 / init 6
const INIT_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?init\s+[06]\b/;
// systemctl power subcommands (systemd/NixOS)
const SYSTEMCTL_POWER_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?systemctl\b[^\n;&|]*?\s(?:poweroff|reboot|halt|suspend|hibernate|hybrid-sleep)\b/;

const PIPE_TO_SHELL_REASON =
  "Blocked: piping remote content to a shell interpreter (curl/wget | sh) is disabled.\n" +
  "- This is remote code execution with supply-chain risk.\n" +
  "- Download the file first, inspect it, then run it if safe.";

const PUBLISH_REASON =
  "Blocked: package or container publishing is disabled.\n" +
  "- Publishing to a registry is a public, irreversible action.\n" +
  "- Ask the user to publish manually if needed.";

const POWER_REASON =
  "Blocked: system power commands (shutdown, reboot, halt, poweroff) are disabled.\n" +
  "- Includes systemctl poweroff/reboot/halt and init 0/6.\n" +
  "- Ask the user to perform system power operations manually.";

function classifyBlockedCommand(cmd: string): string | null {
  if (PIPE_TO_SHELL_PATTERN.test(cmd) || PROC_SUB_PATTERN.test(cmd)) return PIPE_TO_SHELL_REASON;
  if (PUBLISH_PATTERN.test(cmd) || TWINE_UPLOAD_PATTERN.test(cmd) || DOCKER_PUSH_PATTERN.test(cmd) || DOTNET_PUSH_PATTERN.test(cmd)) return PUBLISH_REASON;
  if (POWER_BARE_PATTERN.test(cmd) || INIT_PATTERN.test(cmd) || SYSTEMCTL_POWER_PATTERN.test(cmd)) return POWER_REASON;
  return null;
}

export default function destructiveOpsGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event: ToolCallEvent, _ctx: ExtensionContext) => {
    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      const reason = classifyBlockedCommand(event.input.command);
      if (reason) return { block: true, reason };
    }

    if (event.toolName === "eval" && typeof event.input?.code === "string") {
      const reason = classifyBlockedCommand(event.input.code);
      if (reason) return { block: true, reason };
    }
  });
}
