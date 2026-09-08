import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// rm with recursive flag (-r, -R, --recursive) anywhere in the segment.
// Flags can appear after operands: rm foo -r, rm foo bar -rf
const RM_RECURSIVE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?rm\b[^\n;&|]*?(?:-[a-zA-Z]*[rR]|--recursive)/;

// find ... -delete
const FIND_DELETE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?find\b[^\n;&|]*?\s-delete\b/;

// Destructive standalone commands: dd, shred, mkswap, mke2fs, mkfs.*
const DESTRUCTIVE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?(?:dd|shred|mkswap|mke2fs|mkfs(?:\.\w+)?)\b/;

const BLOCK_REASON_RM =
  "Blocked: recursive 'rm' (rm -r, rm -rf, rm -R, etc.) is disabled.\n" +
  "- Use 'rip' or 'trash' for safe deletion with recovery.\n" +
  "- Ask the user if you truly need to remove a directory tree.";

const BLOCK_REASON_DESTRUCTIVE =
  "Blocked: destructive filesystem command (dd, mkfs, shred, etc.) is disabled.\n" +
  "- These commands cause irreversible data loss.\n" +
  "- Ask the user to run it manually if genuinely needed.";

const BLOCK_REASON_FIND_DELETE =
  "Blocked: 'find ... -delete' is disabled.\n" +
  "- Use 'rip' or 'trash' for safe deletion with recovery.";

function classifyBlockedCommand(cmd: string): string | null {
  if (RM_RECURSIVE_PATTERN.test(cmd)) return BLOCK_REASON_RM;
  if (FIND_DELETE_PATTERN.test(cmd)) return BLOCK_REASON_FIND_DELETE;
  if (DESTRUCTIVE_PATTERN.test(cmd)) return BLOCK_REASON_DESTRUCTIVE;
  return null;
}

export default function filesystemGuard(pi: ExtensionAPI): void {
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
