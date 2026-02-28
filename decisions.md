### Desktop app integration over manual CLI auth
Users were hitting Secret Key friction during `op account add` → Changed setup to guide users through desktop app sign-in + Developer CLI integration instead (avoids Secret Key entry entirely, better UX)
<!-- session:2026-02-21-ff9dfe3f | commit:530ce77ee5d1508113638cf3d1b8edfb824803e2 | files:`internal/application/commands_absorb_setup.go` | area:`internal | date:2026-02-21 | rule:WHEN onboarding 1Password CLI ALWAYS prefer desktop app integration path over manual `op account add` -->
### Interactive-first CLI with script fallback
All commands now prompt interactively when args are missing, but still accept explicit args for CI/automation → Chose interactive-first because target users are developers at terminal, not CI pipelines
<!-- session:2026-02-21-ff9dfe3f | commit:530ce77ee5d1508113638cf3d1b8edfb824803e2 | files:`cmd/secretvault/main.go`,`internal/application/commands_runtime.go`,`internal/application/commands_locking.go` | area:`internal | date:2026-02-21 -->
### Quiet dependency install with loader
Package manager output hidden behind ASCII spinner, only showing package name + source before user confirms → Reduces noise and makes setup feel polished
<!-- session:2026-02-21-ff9dfe3f | commit:530ce77ee5d1508113638cf3d1b8edfb824803e2 | files:`internal/integrations/system/system.go`,`internal/application/commands_absorb_setup.go` | area:`internal | date:2026-02-21 -->
