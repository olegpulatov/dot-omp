import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// Pipe-to-interpreter: curl/wget piped to any interpreter or shell.
// Matches "curl ... | sh", "wget ... | python3", process substitution "sh <(curl ...)"
const INTERPRETER_NAMES = "sh|bash|zsh|fish|dash|ksh|python|python3|python2|perl|ruby|node|php";
const PIPE_TO_SHELL_PATTERN = new RegExp(
  `(?:curl|wget)\\b[^\\n;&|]*?\\|\\s*(?:\\/[^\\s]*\\/)?(?:${INTERPRETER_NAMES})\\b`,
);
const PROC_SUB_PATTERN = new RegExp(
  `(?:${INTERPRETER_NAMES})\\b[^\\n;&|]*?<\\((?:curl|wget)\\b`,
);

// eval/bash -c of remote content: eval "$(curl ...)", bash -c "$(wget ...)"
const EVAL_REMOTE_PATTERN =
  /(?:eval|bash|sh|zsh|fish|dash|ksh)\s+(?:-c\s+)?["'`]\$?\((?:curl|wget)\b/;
const EVAL_REMOTE_BACKTICK_PATTERN =
  /(?:eval|bash|sh|zsh|fish|dash|ksh)\s+(?:-c\s+)?["'`]?`(?:curl|wget)\b/;

// Reverse shells: bash -i >& /dev/tcp, nc -e, ncat -e, socat EXEC
const DEV_TCP_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:bash|sh|zsh|dash|ksh)\b[^\n;|]*?\/dev\/tcp\b/;
const NC_EXECUTE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:nc|netcat|ncat)\b[^\n;&|]*?\s-e\b/;
const SOCAT_EXEC_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?socat\b[^\n;&|]*?EXEC:/;

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

const RCE_REASON =
  "Blocked: remote code execution via curl/wget pipe to interpreter or eval of remote content is disabled.\n" +
  "- This executes untrusted remote code with supply-chain risk.\n" +
  "- Download the file first, inspect it, then run it if safe.";

const REVERSE_SHELL_REASON =
  "Blocked: reverse shell or bind shell command is disabled.\n" +
  "- This creates a network-connected shell, a classic attack pattern.\n" +
  "- Ask the user if you genuinely need remote shell access.";

const PUBLISH_REASON =
  "Blocked: package or container publishing is disabled.\n" +
  "- Publishing to a registry is a public, irreversible action.\n" +
  "- Ask the user to publish manually if needed.";

const POWER_REASON =
  "Blocked: system power commands (shutdown, reboot, halt, poweroff) are disabled.\n" +
  "- Includes systemctl poweroff/reboot/halt and init 0/6.\n" +
  "- Ask the user to perform system power operations manually.";

function classifyBlockedCommand(cmd: string): string | null {
  if (
    PIPE_TO_SHELL_PATTERN.test(cmd) ||
    PROC_SUB_PATTERN.test(cmd) ||
    EVAL_REMOTE_PATTERN.test(cmd) ||
    EVAL_REMOTE_BACKTICK_PATTERN.test(cmd)
  ) {
    return RCE_REASON;
  }
  if (DEV_TCP_PATTERN.test(cmd) || NC_EXECUTE_PATTERN.test(cmd) || SOCAT_EXEC_PATTERN.test(cmd)) {
    return REVERSE_SHELL_REASON;
  }
  if (PUBLISH_PATTERN.test(cmd) || TWINE_UPLOAD_PATTERN.test(cmd) || DOCKER_PUSH_PATTERN.test(cmd) || DOTNET_PUSH_PATTERN.test(cmd)) {
    return PUBLISH_REASON;
  }
  if (POWER_BARE_PATTERN.test(cmd) || INIT_PATTERN.test(cmd) || SYSTEMCTL_POWER_PATTERN.test(cmd)) {
    return POWER_REASON;
  }
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
