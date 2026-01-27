# Changelogs

This folder contains changelog files that describe changes to be released.

## Adding a changelog

Run `changelogs add` to create a new changelog file.

## File format

Changelog files are markdown with YAML frontmatter:

```markdown
---
package-name: minor
other-package: patch
---

Description of the changes made.
```

## Releasing

Run `changelogs version` to apply version bumps and generate changelogs.
