# paperboat-cli

The Paperboat command-line client — an **invisible terminal wrapper** that connects your
local machine to your project's cloud VM and gives you its terminal as if it were local.

It reuses your existing Paperboat auth (from the global papercode config), connects through
agentunnel, and transparently bridges **local image pastes into remote TUIs**: when you paste
a local image into a coding agent running on the VM, the CLI uploads it to the VM and rewrites
the paste to the VM-side path before the agent sees it — so pasting "just works" remotely.

> **Status:** scaffolded, not yet implemented. See [AGENTS.md](AGENTS.md) for the design and
> conventions, and the workspace `USERSTORY.md` for how this fits the platform.

## Stack

Go — distributed as a single static binary.
