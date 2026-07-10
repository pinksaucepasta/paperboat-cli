# AGENTS.md — paperboat-cli

Repo-specific guide for **paperboat-cli**, part of the Paperboat platform. This folder is
opened inside the Paperboat workspace; the workspace-root `AGENTS.md` and `USERSTORY.md` are
the source of truth for the overall product and the non-negotiable rules (no hardcoding,
frozen contracts, UX first, ask before touching other sub-projects). This file covers only
what is specific to the CLI.

> **Status:** scaffolded — docs only, no implementation yet.

---

## What this is

paperboat-cli is an **invisible terminal wrapper**. It connects a user's local machine to
their project's Fly.io VM and gives them the VM's terminal as if it were local. "Invisible"
means it must feel like an ordinary shell/agent session — the wrapper's work happens
transparently inside the terminal byte stream, never in the user's way.

Primary responsibilities:

1. **Connect** to the user's project VM (Fly.io machine) and attach to its terminal (PTY),
   with the connection carried **through agentunnel** (never a raw exposed port).
2. **Auth** as a public client of the Paperboat identity authority. `pb auth login` uses a
   device-authorization flow approved in the dashboard through WorkOS. Each installation
   has its own revocable client session. CLI and papercode may share a documented,
   versioned Paperboat credential-store profile, but the CLI must never parse papercode's
   private state, copy browser cookies, or reinterpret an environment token as a Paperboat
   session.
3. **Bridge local image pastes into remote TUIs** (headline feature, below).
4. Manage server/agent config from the CLI where the platform calls for it.

Keep it a **thin wrapper**: connection + auth + paste bridge + config. Do not reimplement
papercode server logic or agentunnel behavior.

---

## Core mechanism: pasted-image rewriting

Remote coding agents (TUIs) run on the VM, but images the user pastes live on the **local**
machine, so a pasted local path is meaningless to the agent. The wrapper bridges this by
intercepting bracketed paste:

1. **Watch the bracketed-paste stream** — data the terminal wraps between `ESC[200~` and
   `ESC[201~` when the user pastes into the wrapped terminal.
2. **Detect a pasted local image** — either a local image **path**, or the **temp file the
   terminal just wrote** for a pasted image.
3. **Read that local file.** The wrapper runs on the **client**, so it has local filesystem
   access.
4. **Upload it to the papercode server on the VM** (`apps/server`) and receive the **VM-side
   path**.
5. **Rewrite the pasted text to the VM path** before the paste reaches the agent on the VM.

Net effect: the agent receives a valid VM path; the user just pastes an image as normal.

Rules for this path:

- **Non-image pastes pass through untouched** — never block, reorder, or corrupt them.
- **Preserve paste framing and ordering** — the agent must receive well-formed bracketed
  paste, in the right sequence.
- **Do not deadlock the PTY while uploading** — upload asynchronously; hold only the affected
  paste, and keep the rest of the stream flowing.
- **Fail open, visibly** — if upload fails, surface a clear inline message and fall back to
  the original text; never silently drop the user's paste.
- **Everything tunable is config-driven** — upload endpoint, temp-dir locations to watch,
  size limits, allowed image types. No hardcoding.

---

## Stack

**Go.** Single static binary (easy brew/winget/curl distribution, no runtime for users),
strong PTY/terminal and SSH libraries, and consistent with the rest of the platform
(agentunnel is Go; `flyctl` is Go). The CLI only needs to *read* papercode's auth-config
format and make HTTP/WebSocket calls, so nothing here benefits from sharing papercode's TS
code. If this decision is revisited, update this section first.

---

## Conventions

- **Client-side & untrusted-network aware.** Assume the network is hostile. Store access
  and refresh secrets in macOS Keychain, Windows Credential Manager, or Linux Secret
  Service. A file fallback is explicit, disabled by default, restricted to `0600`, and
  visibly warned. Shared client metadata contains secret references, never secret values.
- **Cross-project contracts are frozen.** The papercode server upload endpoint and the
  agentunnel connection are contracts owned by other repos. Treat them as frozen; changing
  them requires explicit permission (see workspace rules). Do not edit those repos from here.
- **Transparent terminal behavior is the UX bar.** Correct raw-mode handling, window-resize
  (`SIGWINCH`) propagation, signal forwarding, exit-code passthrough, and clean teardown on
  disconnect. A wrapper that mangles the terminal has failed its one job.
- **Deterministic, testable stream logic.** The bracketed-paste parser and path rewriter are
  the risk center — cover them with unit tests (partial frames, split reads, nested/adjacent
  pastes, non-image content, upload failure).

---

## Relationship to other sub-projects

- **papercode** is the GUI client; **paperboat-cli** is the terminal/CLI client. Both reach
  the **same per-project papercode server** running on the VM.
- **agentunnel** carries the connection to the VM.
- **paperboat-server** may handle pre-connect auth/authorization checks.

Before building against any of these, read their repos; do not guess their internals or
change their contracts without permission.
