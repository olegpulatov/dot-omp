import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// Matches ssh/scp/sftp/mosh as a command word, with optional path prefix
// and optional shell wrappers (command, exec, env, nohup, etc.).
// (?!\-) rejects hyphenated command names (ssh-keygen, ssh-copy-id) but
// allows flags after the command (ssh -p 22 host).
const SSH_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup|env|nice|timeout)\s+[\w=-]*\s*)*(?:\/[^\s]*\/)?(?:ssh|scp|sftp|mosh)\b(?!\-)/;

// Dedicated port/network scanners
const SCAN_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:nmap|masscan|zmap|rustscan|naabu|arp-scan|arping|fping)\b/;

// netcat in port-scan mode (-z flag, including combined flags like -vz, -vzn)
const NETCAT_SCAN_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:nc|netcat|ncat)\b[^\n;&|]*?(?:\s-z\b|-[a-zA-Z]*z[a-zA-Z]*)/;

const BLOCK_REASON =
  "Blocked: remote shell, port scanning, and network scanning commands are disabled.\n" +
  "- OMP ssh:// protocol (read/write/grep tools) is NOT affected.\n" +
  "- Ask the user if you need remote access or network diagnostics.";

function isBlockedCommand(cmd: string): boolean {
  return SSH_PATTERN.test(cmd) || SCAN_PATTERN.test(cmd) || NETCAT_SCAN_PATTERN.test(cmd);
}

export default function sshNetworkScanGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event: ToolCallEvent, _ctx: ExtensionContext) => {
    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      if (isBlockedCommand(event.input.command)) {
        return { block: true, reason: BLOCK_REASON };
      }
    }

    if (event.toolName === "eval" && typeof event.input?.code === "string") {
      if (isBlockedCommand(event.input.code)) {
        return { block: true, reason: BLOCK_REASON };
      }
    }
  });
}
