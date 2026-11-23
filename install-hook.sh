#!/usr/bin/env bash
# install-hook.sh - make Git run ci.sh before every commit (shift-left gate).
cd "$(dirname "$0")"
printf '#!/usr/bin/env bash\necho "[pre-commit] running ShieldDesk security pipeline..."\n./ci.sh\nexit $?\n' > .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit ci.sh deploy.sh
echo "pre-commit hook installed: every 'git commit' now runs ci.sh"
