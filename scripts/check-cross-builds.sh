#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
	cat <<'EOF'
Usage: ./scripts/check-cross-builds.sh [core|extended]

Profiles:
  core      High-value compatibility matrix covering all unique build-tag families
  extended  Core matrix + additional BSD/Solaris coverage

Environment:
  CROSS_BUILD_CGO_ENABLED  Defaults to 0 for deterministic cross-build checks
  CROSS_BUILD_TARGETS   Optional newline-separated target list, format: GOOS/GOARCH[/GOARM]
EOF
}

read_targets_from_env() {
	local raw="${CROSS_BUILD_TARGETS:-}"
	if [[ -z "$raw" ]]; then
		return 1
	fi

	mapfile -t targets < <(printf '%s\n' "$raw" | sed '/^[[:space:]]*$/d')
	return 0
}

load_targets_for_profile() {
	local profile="${1:-core}"
	case "$profile" in
	core)
		targets=(
			"linux/amd64"
			"linux/arm64"
			"linux/arm/7"
			"windows/amd64"
			"windows/arm64"
			"windows/386"
			"darwin/amd64"
			"darwin/arm64"
			"freebsd/amd64"
			"aix/ppc64"
		)
		;;
	extended)
		targets=(
			"linux/amd64"
			"linux/arm64"
			"linux/arm/7"
			"windows/amd64"
			"windows/arm64"
			"windows/386"
			"darwin/amd64"
			"darwin/arm64"
			"freebsd/amd64"
			"freebsd/arm64"
			"netbsd/amd64"
			"openbsd/amd64"
			"dragonfly/amd64"
			"solaris/amd64"
			"aix/ppc64"
		)
		;;
	-h|--help|help)
		usage
		exit 0
		;;
	*)
		echo "Unknown profile: $profile" >&2
		usage >&2
		exit 1
		;;
	esac
}

declare -a targets=()
if ! read_targets_from_env; then
	load_targets_for_profile "${1:-core}"
fi

default_cgo="${CROSS_BUILD_CGO_ENABLED:-0}"
total="${#targets[@]}"

echo "Cross-build profile: ${1:-custom}"
echo "CGO_ENABLED=${default_cgo}"
echo "Checking ${total} target(s)"

index=0
for target in "${targets[@]}"; do
	index=$((index + 1))
	IFS='/' read -r goos goarch goarm <<<"$target"
	echo "==> [${index}/${total}] GOOS=${goos} GOARCH=${goarch}${goarm:+ GOARM=${goarm}}"
	if [[ -n "${goarm:-}" ]]; then
		env CGO_ENABLED="${default_cgo}" GOOS="${goos}" GOARCH="${goarch}" GOARM="${goarm}" go build ./...
	else
		env CGO_ENABLED="${default_cgo}" GOOS="${goos}" GOARCH="${goarch}" go build ./...
	fi
done

echo "Cross-build compatibility check passed."
