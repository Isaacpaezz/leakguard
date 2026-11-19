#!/usr/bin/env bash
# Builds leakguard.app and the DMG people download from GitHub Releases.
#
#   scripts/build-macos.sh VERSION      # for example 0.1.0, without the v
#
# Output, in dist/ (ignored by git):
#   dist/leakguard.app                         universal (arm64 + x86_64), ad-hoc signed
#   dist/leakguard-VERSION-macos.dmg           the app, an Applications shortcut, the guide
#   dist/leakguard-VERSION-macos.dmg.sha256    its SHA-256 checksum
#
# Needs macOS with Go and the Xcode command line tools (lipo, codesign,
# iconutil, hdiutil, plutil). It never signs with a Developer ID, never
# notarizes and never publishes anything: the release workflow uploads the
# files when the maintainer pushes a v* tag.
set -euo pipefail

usage() {
	echo "usage: scripts/build-macos.sh VERSION   (for example 0.1.0, without the leading v)" >&2
	exit 2
}

[[ $# -eq 1 ]] || usage
version=$1
# The same rule as tools/infoplist: a plain semantic version.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z-]+)*)?$'
[[ $version =~ $semver ]] || {
	echo "build-macos: \"$version\" is not a version like 1.2.3 or 1.2.3-rc.1" >&2
	usage
}
[[ $(uname -s) == Darwin ]] || {
	echo "build-macos: run this on macOS" >&2
	exit 1
}

cd "$(dirname "$0")/.."
dist=dist
app=$dist/leakguard.app
dmg=$dist/leakguard-$version-macos.dmg
guide="Cómo abrir leakguard.txt"

work=$(mktemp -d "${TMPDIR:-/tmp}/leakguard-build.XXXXXX")
trap 'rm -rf "$work"' EXIT

# The binaries match the bundle's LSMinimumSystemVersion.
export MACOSX_DEPLOYMENT_TARGET=13.0
ldflags="-s -w -X github.com/Isaacpaezz/leakguard/internal/version.Version=$version"

echo "==> Building leakguard $version (arm64, amd64)"
for arch in arm64 amd64; do
	CGO_ENABLED=0 GOOS=darwin GOARCH=$arch \
		go build -trimpath -ldflags "$ldflags" -o "$work/leakguard-$arch" ./cmd/leakguard
	CGO_ENABLED=1 GOOS=darwin GOARCH=$arch \
		go build -trimpath -ldflags "$ldflags" -o "$work/leakguard-menubar-$arch" ./cmd/leakguard-menubar
done

echo "==> Assembling $app"
bundle=$work/leakguard.app
mkdir -p "$bundle/Contents/MacOS" "$bundle/Contents/Resources"
for bin in leakguard leakguard-menubar; do
	lipo -create -output "$bundle/Contents/MacOS/$bin" "$work/$bin-arm64" "$work/$bin-amd64"
	chmod 755 "$bundle/Contents/MacOS/$bin"
done
go run ./tools/infoplist "$version" >"$bundle/Contents/Info.plist"
plutil -lint "$bundle/Contents/Info.plist"
go run ./tools/genappicon "$work/AppIcon.iconset"
iconutil -c icns -o "$bundle/Contents/Resources/AppIcon.icns" "$work/AppIcon.iconset"

# Ad-hoc signature: no Developer ID yet (see docs/install-macos.md). --deep
# signs the leakguard command inside too, then the bundle is sealed.
codesign --force --deep -s - "$bundle"
codesign --verify --deep --strict "$bundle"

echo "==> Creating $dmg"
stage=$work/dmg
mkdir -p "$stage"
ditto "$bundle" "$stage/leakguard.app"
ln -s /Applications "$stage/Applications"
cp docs/install-macos.md "$stage/$guide"

mkdir -p "$dist"
rm -rf "$app" "$dmg" "$dmg.sha256"
ditto "$bundle" "$app"
# hdiutil sometimes fails with "Resource busy" on CI runners: try again.
for attempt in 1 2 3; do
	if hdiutil create -volname "leakguard $version" -srcfolder "$stage" \
		-fs HFS+ -format UDZO -imagekey zlib-level=9 -ov "$dmg" >/dev/null; then
		break
	fi
	[[ $attempt -lt 3 ]] || {
		echo "build-macos: hdiutil create failed" >&2
		exit 1
	}
	sleep 5
done
hdiutil verify "$dmg" >/dev/null
(cd "$dist" && shasum -a 256 "$(basename "$dmg")" >"$(basename "$dmg").sha256")

echo "==> Done"
echo "$app"
echo "$dmg"
cat "$dmg.sha256"
