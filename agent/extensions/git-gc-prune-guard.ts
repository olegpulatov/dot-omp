import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// Matches "git gc" as a command — the word "git" followed by "gc" after
// optional global options (-C path, -c key=val, --git-dir=x, --no-pager, etc.).
// Does NOT match "git commit -m 'gc'" or branch names containing "gc".
const GIT_GC_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?git\b(?:\s+(?:-[Cc]\s+[^\s]+|--git-dir[=\s][^\s]+|--work-tree[=\s][^\s]+|--namespace[=\s][^\s]+|--exec[=\s][^\s]+|--no-pager|--bare|--no-replace-objects))*\s+gc\b/;

const GIT_PRUNE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?git\b(?:\s+(?:-[Cc]\s+[^\s]+|--git-dir[=\s][^\s]+|--work-tree[=\s][^\s]+|--namespace[=\s][^\s]+|--exec[=\s][^\s]+|--no-pager|--bare|--no-replace-objects))*\s+prune\b/;

// git reflog expire or git reflog delete — NOT bare "git reflog" or "git reflog show"
const GIT_REFLOG_DESTRUCTIVE_PATTERN =
  /(?:^|[;&|\n(\[])\s*(?:(?:sudo|doas|command|exec|builtin|nohup)\s+)*(?:\/[^\s]*\/)?git\b(?:\s+(?:-[Cc]\s+[^\s]+|--git-dir[=\s][^\s]+|--work-tree[=\s][^\s]+|--namespace[=\s][^\s]+|--exec[=\s][^\s]+|--no-pager|--bare|--no-replace-objects))*\s+reflog\s+(?:expire|delete)\b/;

const BLOCK_REASON_GC =
  "Blocked: 'git gc' is disabled.\n" +
  "- gc repacks objects and expires old reflog entries.\n" +
  "- Run it manually when you intentionally want to reclaim space:\n" +
  "  git gc --prune=now   # aggressive, removes all unreachable objects\n" +
  "  git gc               # default, respects gc.reflogExpire timeouts";

const BLOCK_REASON_PRUNE =
  "Blocked: 'git prune' is disabled.\n" +
  "- prune deletes unreachable objects from the object database.\n" +
  "- This is the actual data-removal step; recovery becomes impossible.\n" +
  "- Run it manually if you intentionally want this:\n" +
  "  git prune --expire=now";

const BLOCK_REASON_REFLOG =
  "Blocked: 'git reflog expire' or 'git reflog delete' is disabled.\n" +
  "- These remove reflog entries, making 'lost' commits unreachable.\n" +
  "- 'git reflog' (read-only) remains allowed for recovery.\n" +
  "- Run expire/delete manually if you intentionally want this:\n" +
  "  git reflog expire --expire=now --all";

function classifyBlockedGit(cmd: string): string | null {
  if (GIT_GC_PATTERN.test(cmd)) return BLOCK_REASON_GC;
  if (GIT_PRUNE_PATTERN.test(cmd)) return BLOCK_REASON_PRUNE;
  if (GIT_REFLOG_DESTRUCTIVE_PATTERN.test(cmd)) return BLOCK_REASON_REFLOG;
  return null;
}

export default function gitGcPruneGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event: ToolCallEvent, _ctx: ExtensionContext) => {
    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      const reason = classifyBlockedGit(event.input.command);
      if (reason) return { block: true, reason };
    }

    if (event.toolName === "eval" && typeof event.input?.code === "string") {
      const reason = classifyBlockedGit(event.input.code);
      if (reason) return { block: true, reason };
    }
  });
}
