#!/usr/bin/env bash
set -euo pipefail

github_env="${1:?GitHub environment file path is required}"
runner_user="$(id -un)"
passwd_entry="$(getent passwd "$runner_user")"
runner_home="$(printf '%s\n' "$passwd_entry" | cut -d: -f6)"
login_shell="$(printf '%s\n' "$passwd_entry" | cut -d: -f7)"

test -n "$runner_home"
test -x "$login_shell"
printf 'HOME=%s\n' "$runner_home" >> "$github_env"

"$login_shell" -lic 'env' \
  | while IFS= read -r entry; do
      case "$entry" in
        HTTP_PROXY=*|HTTPS_PROXY=*|ALL_PROXY=*|NO_PROXY=*|http_proxy=*|https_proxy=*|all_proxy=*|no_proxy=*)
          printf '%s\n' "$entry" >> "$github_env"
          ;;
      esac
    done
