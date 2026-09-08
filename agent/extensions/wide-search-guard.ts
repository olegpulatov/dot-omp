import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

const WIDE_SEARCH_BLOCK_REASON =
  "Blocked: system wide searches across '/', '/srv', user directories ('/Users', '/home'), or home directories require explicit user approval. Use paths known from context or ask the user for the target directory.";

const BLOCKED_TARGETS: Record<string, true> = {
  "/": true,
  "/srv": true,
  "/Users": true,
  "/home": true,
  [os.homedir().replace(/\\/g, "/")]: true,
};

function isBlockedTarget(targetPath: string, cwd: string): boolean {
  if (!targetPath || targetPath === ".") targetPath = cwd;
  let raw = targetPath.trim().replace(/^['"`]|['"`]$/g, "");
  if (raw.startsWith("~")) raw = path.join(os.homedir(), raw.slice(1));
  raw = raw.replace(/\$(?:HOME|\{HOME\})/g, os.homedir());
  raw = raw.replace(/\/\*{1,2}$/, "");
  raw = raw.replace(/:[\d+-]+$/, "");
  if (!raw) raw = "/";
  const abs = path.isAbsolute(raw) ? path.resolve(raw) : path.resolve(cwd, raw);
  const normalized = abs.replace(/\\/g, "/");

  if (BLOCKED_TARGETS[normalized]) return true;
  const parent = path.dirname(normalized).replace(/\\/g, "/");
  if (parent === "/Users" || parent === "/home") return true;

  // Block Documents directory under any user home
  if (/(?:^|\/)(?:Users|home)\/[^/]+\/Documents(?:\/|$)/i.test(normalized)) return true;

  // Block iCloud directories
  if (/(?:^|\/)(?:Library\/Mobile Documents|Library\/CloudStorage\/iCloudDrive|iCloud)(?:\/|$)/i.test(normalized)) return true;

  return false;
}

function isWideSearchInput(inputPath: unknown, fallbackCwd: string): boolean {
  if (typeof inputPath !== "string" || inputPath.trim().length === 0) {
    return isBlockedTarget(".", fallbackCwd);
  }
  const parts = inputPath.split(";");
  for (const part of parts) {
    if (isBlockedTarget(part, fallbackCwd)) {
      return true;
    }
  }
  return false;
}

function extractPathTokens(segment: string): string[] {
  const tokens = segment.split(/\s+/).map((t) => t.replace(/^['"`]|['"`]$/g, ""));
  const pathTokens: string[] = [];
  for (const t of tokens) {
    if (t.startsWith("-") || t.startsWith("!") || t.startsWith("(") || t.startsWith(")")) continue;
    if (
      t.startsWith("/") ||
      t.startsWith("~") ||
      t.startsWith("$HOME") ||
      t.startsWith("${HOME}") ||
      t === "." ||
      t === ".." ||
      t.startsWith("./") ||
      t.startsWith("../")
    ) {
      pathTokens.push(t);
    }
  }
  return pathTokens;
}

function isWideSearchBash(cmd: string, cwd: string): boolean {
  if (/(?:^|[;&|\n(\[])\s*?locate\b/.test(cmd)) return true;
  if (/(?:^|[;&|\n(\[])\s*?mdfind\b(?![^\n;&|]*?-onlyin)/.test(cmd)) return true;

  const segments = cmd.split(/[;&|\n]+/);
  for (let segment of segments) {
    segment = segment.trim();
    if (!segment) continue;

    const isFind = /\bfind\b/.test(segment);
    const isFd = /\bfd\b/.test(segment);
    const isRg = /\b(?:rg|ripgrep|ag|ack)\b/.test(segment);
    const isRecGrep = /\b(?:grep|egrep)\b[^\n;&|]*?-[a-zA-Z0-9]*[rR]/.test(segment);

    if (!isFind && !isFd && !isRg && !isRecGrep) continue;

    const pathTokens = extractPathTokens(segment);
    for (const token of pathTokens) {
      if (isBlockedTarget(token, cwd)) {
        return true;
      }
    }

    if (pathTokens.length === 0 && isBlockedTarget(".", cwd)) {
      return true;
    }
  }

  return false;
}

export default function wideSearchGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
    const fallbackCwd = ctx?.cwd || process.cwd();

    // 1. Guard grep & glob tools from wide searches
    if (event.toolName === "grep" || event.toolName === "glob") {
      if (isWideSearchInput(event.input?.path, fallbackCwd)) {
        return { block: true, reason: WIDE_SEARCH_BLOCK_REASON };
      }
    }

    // 2. Guard bash invocations
    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      const cmd = event.input.command;
      const cmdCwd = typeof event.input?.cwd === "string" ? event.input.cwd : fallbackCwd;

      if (isWideSearchBash(cmd, cmdCwd)) {
        return { block: true, reason: WIDE_SEARCH_BLOCK_REASON };
      }
    }

    // 3. Guard eval code cells
    if (event.toolName === "eval" && typeof event.input?.code === "string") {
      const code = event.input.code;
      if (isWideSearchBash(code, fallbackCwd)) {
        return { block: true, reason: WIDE_SEARCH_BLOCK_REASON };
      }
    }
  });
}
