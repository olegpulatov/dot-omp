import * as os from "node:os";
import * as path from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@oh-my-pi/pi-coding-agent";

// Matches sops with -d or --decrypt within the same command segment / call
const SOPS_DECRYPT_PATTERN =
  /(?:^|[;&|\n(\[])[^;&|\n)]*?\bsops\b[^;&|\n)]*?(?:^|\s|["'\`])(?:-d|--decrypt)(?:[\s"'\`=]|$)/m;

const AGE_KEY_FILE_PATTERN = /(?:^|[/\\])(?:keys\.txt|[^/\\]*?\.age\.key\.txt)$/i;
const AGE_KEY_TEXT_PATTERN =
  /(?:\.config\/(?:sops\/age|age)\/[^\s;&|'"`)]*?(?:keys\.txt|[^/\s;&|'"`)]*?\.age\.key\.txt))/i;
const AGE_KEY_CD_PATTERN =
  /(?:\.config\/(?:sops\/age|age))\b[\s\S]*?(?:keys\.txt|[^/\s;&|'"`]*?\.age\.key\.txt)\b/i;
const AGE_KEY_BARE_PATTERN =
  /(?:^|[\s"'\`])(?:keys\.txt|[^/\s;&|'"`]*?\.age\.key\.txt)(?:[\s"'\`=]|$)/i;

const SOPS_BLOCK_REASON =
  "Blocked: 'sops -d' exposes plaintext secrets. Inspect keys without decrypting values:\n" +
  "- Dotenv: grep -o '^[^=]*' file.sops.env | grep -v '^sops_'\n" +
  "- JSON:   jq 'del(.sops) | keys' file.sops.json\n" +
  "- YAML:   yq 'del(.sops) | keys' file.sops.yaml";

const AGE_KEY_BLOCK_REASON =
  "Blocked: reading age secret keys (keys.txt, *.age.key.txt in ~/.config/age or ~/.config/sops/age) is strictly prohibited.";

function isAgeSecretPath(rawPath: unknown, fallbackCwd?: string): boolean {
  if (typeof rawPath !== "string" || rawPath.trim().length === 0) return false;
  let p = rawPath.trim();
  if (p.startsWith("~")) p = path.join(os.homedir(), p.slice(1));
  const abs = path.isAbsolute(p) ? path.resolve(p) : path.resolve(fallbackCwd || process.cwd(), p);
  const normalized = abs.replace(/\\/g, "/");
  return /\/\.config\/(?:sops\/age|age)(?:\/|$)/i.test(normalized) && AGE_KEY_FILE_PATTERN.test(normalized);
}

function isAgeSecretCommand(command: string, cwd?: string): boolean {
  if (AGE_KEY_TEXT_PATTERN.test(command) || AGE_KEY_CD_PATTERN.test(command)) return true;
  const normalizedCwd = (cwd || "").replace(/\\/g, "/");
  if (/\/\.config\/(?:sops\/age|age)(?:\/|$)/i.test(normalizedCwd)) {
    return AGE_KEY_BARE_PATTERN.test(command);
  }
  return false;
}

export default function sopsGuard(pi: ExtensionAPI): void {
  pi.on("tool_call", async (event: ToolCallEvent, ctx: ExtensionContext) => {
    const fallbackCwd = ctx?.cwd || process.cwd();

    // 1. Guard read & grep tools
    if ((event.toolName === "read" || event.toolName === "grep") && event.input?.path) {
      if (isAgeSecretPath(event.input.path, fallbackCwd)) {
        return { block: true, reason: AGE_KEY_BLOCK_REASON };
      }
    }

    // 2. Guard bash invocations (cat, head, cp, etc. + cwd-relative)
    if (event.toolName === "bash" && typeof event.input?.command === "string") {
      const cmd = event.input.command;
      const cmdCwd = typeof event.input?.cwd === "string" ? event.input.cwd : fallbackCwd;

      if (SOPS_DECRYPT_PATTERN.test(cmd)) {
        return { block: true, reason: SOPS_BLOCK_REASON };
      }

      if (isAgeSecretCommand(cmd, cmdCwd)) {
        return { block: true, reason: AGE_KEY_BLOCK_REASON };
      }
    }

    // 3. Guard eval code cells
    if (event.toolName === "eval" && typeof event.input?.code === "string") {
      const code = event.input.code;
      if (SOPS_DECRYPT_PATTERN.test(code)) {
        return { block: true, reason: SOPS_BLOCK_REASON };
      }
      if (AGE_KEY_TEXT_PATTERN.test(code) || isAgeSecretPath(code, fallbackCwd)) {
        return { block: true, reason: AGE_KEY_BLOCK_REASON };
      }
    }
  });
}
