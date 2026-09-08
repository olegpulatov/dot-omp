# OMP Agent Extensions — Safety Guards

Run `/reload-plugins` inside an OMP session to re-scan the extensions directory after adding, removing, or moving guard files — no restart needed. To disable a guard, move its `.ts` file out of `~/.omp/agent/extensions/` (or rename it), then `/reload-plugins`. To disable by name without moving the file, add `extension-module:<name>` to `disabledExtensions` in `~/.omp/agent/config.yml`.

A collection of [Oh My Pi](https://github.com/oh-my-pi) coding-agent extensions that block dangerous, irreversible, or privacy-sensitive operations before they reach your system. Each guard is a standalone `.ts` file — drop the ones you want into your agent extensions directory and they load automatically.

## Installation

Copy one or more guard files into your OMP agent extensions directory:

```
~/.omp/agent/extensions/
```

Or symlink the whole directory. OMP auto-discovers `.ts` and `.js` files there on startup.

Project-level extensions go in `<repo>/.omp/extensions/`.

## Enabling, disabling, and reloading

OMP auto-discovers extension modules on startup. To control which guards are active during a running session without restarting:

- Run `/reload-plugins` inside an OMP session to re-scan the extensions directory and apply additions, removals, or edits.
- Move a guard file out of the extensions directory (or rename it without `.ts`/`.js`) to disable it, then `/reload-plugins`.
- Disable a specific guard by name without removing the file — add its id to `disabledExtensions` in `~/.omp/agent/config.yml`:

```yaml
disabledExtensions:
  - extension-module:ssh-network-scan-guard
```

The id is `extension-module:<filename>` based on the entry path (e.g. `sops-guard.ts` → `extension-module:sops-guard`).

To disable all ambient extensions at once, launch OMP with `--no-extensions`. Explicitly loaded extensions via `-e` still load.

## Available guards

### `sops-guard.ts` — SOPS and age secret key protection

Blocks:
- `sops -d` / `sops --decrypt` — prevents plaintext secret exposure in tool output
- Reading age secret key files (`keys.txt`, `*.age.key.txt`) in `~/.config/age/` or `~/.config/sops/age/` via `read`, `grep`, `bash`, or `eval` tools

The block reason includes safe alternatives for inspecting key names without decrypting values.

### `wide-search-guard.ts` — Filesystem-wide search prevention

Blocks:
- Searches targeting `/`, `/srv`, `/Users`, `/home`, home directories, `~/Documents`, and iCloud paths via `grep`, `glob`, `bash`, or `eval` tools
- `locate`, `mdfind` (without `-onlyin`), `find`, `fd`, `rg`/`ripgrep`, `ag`, `ack`, recursive `grep -r`/`grep -R` when pointed at blocked targets

Prevents the agent from scanning your entire filesystem and pulling unrelated files into context.

### `ssh-network-scan-guard.ts` — Remote shell and network scan blocking

Blocks:
- Remote shell commands: `ssh`, `scp`, `sftp`, `mosh`
- Port/network scanners: `nmap`, `masscan`, `zmap`, `rustscan`, `naabu`, `arp-scan`, `arping`, `fping`
- `nc`/`netcat`/`ncat` in port-scan mode (`-z` flag)

OMP has a built-in `ssh://` protocol for remote file access through `read`, `write`, and `grep` tools. This guard does NOT block that protocol — it only blocks raw shell binaries. This lets the agent read remote files through OMP's controlled path while preventing arbitrary SSH sessions and network scanning from the bash tool.

### `sudo-doas-guard.ts` — Privilege escalation blocking

Blocks:
- `sudo` and `doas` in any bash or eval command

Prevents the agent from elevating privileges. If a task requires root, the block reason tells the agent to ask you to run it manually.

### `filesystem-guard.ts` — Destructive filesystem operation blocking

Blocks:
- `rm` with recursive flags (`-r`, `-rf`, `-R`, `--recursive`, etc.)
- `find ... -delete`
- `dd`, `shred`, `mkswap`, `mke2fs`
- `mkfs` and all variants (`mkfs.ext4`, `mkfs.btrfs`, `mkfs.xfs`, `mkfs.ntfs`, etc.)

The block reason suggests `rip` or `trash` as safe alternatives with recovery.

### `destructive-ops-guard.ts` — Network RCE, public exposure, and power commands

Blocks:
- Pipe-to-shell: `curl ... | sh`, `wget ... | bash`, including process substitution `sh <(curl ...)`
- Package/container publishing: `npm publish`, `pnpm publish`, `yarn publish`, `cargo publish`, `twine upload`, `dotnet nuget push`, `docker push`, `podman push`, `buildah push`
- System power (bare): `shutdown`, `reboot`, `halt`, `poweroff`, `telinit`, `init 0`, `init 6`
- System power (systemd/NixOS): `systemctl poweroff`, `systemctl reboot`, `systemctl halt`, `systemctl suspend`, `systemctl hibernate`, `systemctl hybrid-sleep`

Each category has a distinct block reason explaining why and what to do instead.

### `git-gc-prune-guard.ts` — Git history destruction blocking

Blocks:
- `git gc` — repacks objects and expires old reflog entries per config
- `git prune` — deletes unreachable objects from the object database
- `git reflog expire` / `git reflog delete` — removes reflog entries, making lost commits unreachable

Allows:
- `git reflog` (bare, read-only) — your primary recovery tool after a bad reset or branch delete
- `git reflog show` — read-only viewing
- All other git commands (`commit`, `push`, `merge`, `rebase`, `reset`, etc.)

## How they work

Every guard subscribes to OMP's `tool_call` event, which fires before a tool executes. The handler inspects the tool name and input, and if the command matches a dangerous pattern, returns `{ block: true, reason: "..." }`. The block reason is shown to the agent so it can choose a safe alternative or ask you.

Patterns match command words at segment boundaries, handling path-qualified binaries (`/usr/bin/ssh`, `/run/current-system/sw/bin/git`, `/nix/store/.../bin/git`) and common `sudo`/`doas` prefixes. Most guards also recognize shell wrappers (`command`, `exec`, `nohup`, `builtin`). This prevents bypass via `/usr/bin/git gc` or `command ssh` without false-positiving on `ssh-keygen`, `git commit -m 'gc'`, or branch names containing "prune".

Guards intercept these tools:
- `bash` — checks `input.command`
- `eval` — checks `input.code`
- `read` / `grep` — checks `input.path` (sops-guard and wide-search-guard)
- `glob` — checks `input.path` (wide-search-guard)

Guards are fail-closed: if a handler throws, the tool call is blocked. This prevents a guard bug from allowing a dangerous operation through.

## Combining guards

All guards are independent and can run together. They operate on different command categories with no overlap. Load only the ones you need.

## License

MIT
