### op signin positional arg bug
Passed address as positional arg to `op signin my.1password.com` → CLI v2 rejects positional args, expects `--account` global flag → Fixed to `op --account <address> signin -f`
<!-- session:2026-02-21-ff9dfe3f | commit:530ce77ee5d1508113638cf3d1b8edfb824803e2 | files:`internal/application/commands_absorb_setup.go` | area:`internal | date:2026-02-21 | rule:WHEN invoking `op` CLI v2 NEVER pass account address as positional arg, ALWAYS use `--account` global flag -->
### Arch pacman install failure
Used `pacman -S 1password-cli` on Arch → Package is AUR-only, `target not found` → Switched to `yay`/`paru` detection and AUR install path
<!-- session:2026-02-21-ff9dfe3f | commit:530ce77ee5d1508113638cf3d1b8edfb824803e2 | files:`internal/integrations/system/system.go` | area:`internal | date:2026-02-21 | tried:`pacman -S 1password-cli` | rule:WHEN installing 1password packages on Arch ALWAYS use AUR helpers (yay/paru), NEVER use pacman directly -->
