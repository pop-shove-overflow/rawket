# bcow — Claude Code Instructions

## Git Workflow

### Branch per bead

Each bead gets its own feature branch:

```
git checkout -b bead/bcow-8al.2-wire-types
```

Branch naming: `bead/<bead-id>-<short-slug>` (slug derived from the bead title, lowercase, hyphens).

### Pre-commit quality gate

Never commit with compiler warnings or test failures. Before every commit:

1. Run `cargo clippy --workspace` and fix all warnings.
2. Run `cargo test --workspace` and verify no failures **and no warnings** (warnings appear in the compiler output above the `test result` lines — scan for them explicitly).
3. Never add `#[allow(clippy::...)]` attributes without explicit user confirmation. If a clippy lint cannot be fixed cleanly, explain the situation and wait for the user to approve the suppression.

### Commits within a bead

Make distinct commits for coherent pieces of work completed inside the bead. Do not squash everything into one commit. Examples of good commit boundaries:

- Struct definitions and size assertions in one commit
- Enum conversions (`TryFrom` impls) in a follow-up commit
- Unit tests in a final commit

Each commit message should include a concise bulleted summary of what is implemented.

### Merging into main

**Do NOT merge into main without explicit user approval.** When a bead is complete, leave it on its feature branch and tell the user it is ready. Wait for the user to say "merge" or similar before running `git merge`.

When the user approves a merge, use `--no-ff` to preserve branch topology:

```
git checkout main
git merge --no-ff bead/bcow-8al.2-wire-types
```

Never fast-forward. The merge commit should reference the bead ID:

```
Merge bead/bcow-8al.2-wire-types

Closes bcow-8al.2: Wire types module (src/wire/)
```

### Sub-agent isolation

Sub-agents execute in isolated git worktrees via the Agent tool's `isolation: "worktree"` parameter. Each agent gets its own worktree and feature branch automatically. The agent works entirely within its worktree and does not touch main or other agents' branches.

When launching a sub-agent for a bead, pass `isolation: "worktree"` to the Agent tool. The agent should:
1. Create its feature branch inside the worktree: `git checkout -b bead/<id>-<slug>`
2. Mark the bead in progress: `bd update <id> --status in_progress`
3. Implement and commit as usual
4. Do NOT merge into main — report completion and wait for user approval

## Bead Lifecycle

1. Pick the next ready bead (`bd ready`)
2. Create feature branch: `git checkout -b bead/<id>-<slug>`
3. Mark bead in progress: `bd update <id> --status in_progress`
4. Implement, making commits as coherent units of work are completed
5. Report completion — do NOT merge; wait for user to approve
6. On user approval: merge into main with `--no-ff`, then close bead: `bd close <id>`

## Unit Tests

Include unit tests wherever possible. Tests live in the same file as the code under test (`#[cfg(test)]` module at the bottom of each source file), except for integration tests which go in `tests/`.

Every bead that implements logic (not just type definitions) should include tests before the merge commit.

For any invariant that is documented in a design file and not obvious from the code alone, encode it as a test. A good signal: if a design doc says "X does NOT happen here", write a test that asserts X does not happen.
