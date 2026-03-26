# Releasing mpp-rs

This project uses [changelogs-rs](https://github.com/wevm/changelogs-rs) for automated changelog management and releases.

## How It Works

```
PR opened/updated → changelog suggested → PR merged → RC PR created → RC merged → published to crates.io
```

### During Development

1. **Make changes** and open a PR
2. **Changelog suggested** - CI comments on the PR with changelog status and, if missing, an AI-generated changelog suggestion you can add with one click
3. **Review the changelog** - check the suggestion or existing file; edit if needed
4. **Merge the PR** - changelog files live in `.changelog/`

### Creating Changelogs Manually

If CI doesn't suggest one or you want to write it yourself, create it manually:

```bash
# Interactive prompt
changelogs add

# With AI assistance
changelogs add --ai "claude -p"
```

This creates a file like `.changelog/brave-lions-dance.md` (random name) with your changes.

### Releasing

1. **Push to main** triggers the release workflow
2. **RC PR created** - a "Version Packages" PR is automatically opened with:
   - Version bumps in `Cargo.toml`
   - Updated `CHANGELOG.md`
3. **Merge the RC PR** - packages are published to crates.io

## When Releases Happen

Releases are **not scheduled** - they happen when you merge the RC PR:

| Event | What Happens |
|-------|--------------|
| PR merged to main | RC PR created/updated (if changelogs exist) |
| RC PR merged | Packages published immediately |
| Multiple PRs merged | Single RC PR accumulates all changes |

**Batching**: If you merge several PRs before merging the RC PR, all changes are batched into one release. The RC PR updates automatically with each push to main.

**No changelogs**: If PRs are merged without changelog files (e.g., docs-only changes), no RC PR is created.

## Where Artifacts Are Published

| Artifact | Location | When |
|----------|----------|------|
| Crate | [crates.io/crates/mpp](https://crates.io/crates/mpp) | RC PR merged |
| GitHub Release | [Releases page](https://github.com/tempoxyz/mpp-rs/releases) | RC PR merged |
| Changelog | `CHANGELOG.md` in repo | RC PR merged |
| Git tag | `mpp@x.y.z` | RC PR merged |

### Version Tags

Tags follow the format `mpp@x.y.z` (e.g., `mpp@0.2.1`). For workspaces with multiple crates, each crate gets its own tag.

## Manual Commands

```bash
# Install changelogs CLI
curl -sSL https://changelogs.sh | sh

# Add changelog interactively
changelogs add

# Add changelog with AI
changelogs add --ai "claude -p"

# Check pending releases
changelogs status

# Preview version bumps (dry run)
changelogs version --dry-run

# Apply version bumps locally
changelogs version
```

## Changelog Format

Changelogs are markdown files in `.changelog/` with frontmatter specifying bump types:

```markdown
---
mpp: minor
---

Added new payment provider support.
```

Bump types: `major`, `minor`, `patch`

## Configuration

See [config.toml](./config.toml) for changelog settings:

- `dependent_bump` - How to bump dependents (default: `patch`)
- `changelog.format` - `root` for single CHANGELOG.md or `per-crate`
- `ignore` - Packages to exclude from releases

## CI Workflows

| Workflow | Trigger | Action |
|----------|---------|--------|
| `changelog.yml` | PR opened/updated | Comments on PR with changelog status and AI-generated add link |
| `release.yml` | Push to main | Creates RC PR or publishes packages |

## Required Secrets

- `ANTHROPIC_API_KEY` - For AI-generated changelogs
- `GITHUB_TOKEN` - For creating PRs (provided automatically)
- `CARGO_REGISTRY_TOKEN` - For publishing to crates.io (add when ready to publish)
