# Agent Instructions — turbo-guard

## Product Knowledge Base

- Before answering questions about this product (features, pricing, competitors,
  positioning, support, marketing), read `PRODUCT-KNOWLEDGE.md` in this same
  folder. It is the single source of truth for what Turbo Guard (free) and
  Turbo Guard Pro (premium add-on) do.
- It is also safe to share with other AI tools: upload it to Claude, ChatGPT,
  Cursor, or Copilot as the product's knowledge base.

## Git: never commit without explicit permission

- NEVER run `git commit`, `git commit --amend`, `git push`, `git tag`, or create a
  pull request / merge request unless the user has explicitly asked for that exact
  action in the current conversation.
- "Make it workable", "fix it", "yes", or "looks good" is NOT permission to commit.
  Only an explicit instruction such as "commit this", "commit and push", or
  "create a PR" counts.
- When work is done, leave the changes in the working tree (unstaged or staged) and
  report what changed. Let the user decide when and what to commit.
- If unsure whether the user wants a commit, ask first.
- Do not undo or reword existing commits without explicit permission.

## Repository

- Path: local WordPress plugin checkout (`wp-content/plugins/turbo-guard`).
- Branch: `main`
- Remotes: `gitlab` (gitlab.ibos.io/shariful/turbo-guard), `origin` (github.com/turbo-addons/turbo-guard)

## Local tooling

- PHP for linting (Local by Flywheel):
  `C:\Users\HP\AppData\Roaming\Local\lightning-services\php-8.2.23+0\bin\win64\php.exe`
  Usage: `& "<php.exe>" -l <file.php>`
- JS syntax check: `node --check <file.js>`
