# OpenClaw Agent Skills

Public shared skills for agents and claws.

This repo is the canonical source for common workflow skills that should not be
copied by hand into every OpenClaw repo.

## Skills

- `autoreview`: closeout/code-review workflow and helper script.
- `crabbox`: Crabbox/Testbox remote validation workflow.

## Use

Checkout-local discovery:

```sh
git clone https://github.com/openclaw/agent-skills.git
```

Then point your agent skill directory at `skills/`, or copy/sync selected skills
into the agent-specific skill directory your tool reads.

Downstream repos may vendor critical zero-setup snapshots, but those snapshots
should be generated from this repo and checked for drift. Edit canonical skill
content here first, then sync downstream copies.

## Validate

```sh
scripts/validate-skills
```

The validator checks every `skills/*/SKILL.md` for YAML frontmatter plus required
`name` and `description`.
