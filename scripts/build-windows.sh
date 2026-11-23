#!/usr/bin/env bash
# Builds the Windows installers people download from GitHub Releases.
#
#   scripts/build-windows.sh VERSION    # for example 0.2.0, without the v
#
# Output, in dist/ (ignored by git), for ARCH amd64 and arm64:
#   dist/leakguard-VERSION-windows-ARCH-setup.exe   the NSIS installer:
#       leakguard.exe (the CLI) and leakguard-tray.exe (the tray app) in
#       %ProgramFiles%\leakguard, a Start menu shortcut, the Settings entry
#   and a .sha256 checksum next to each file.
#
# The binaries are built without cgo. The tray gets its Windows resources
# (a manifest asking for Common Controls 6, which its dialogs need, DPI
# awareness and asInvoker, plus the app icon), made with go-winres into
# cmd/leakguard-menubar/rsrc_windows_ARCH.syso for the build and removed
# afterwards: they are never committed.
#
# Runs on Linux or macOS with Go, makensis (NSIS 3.04 or newer: apt-get
# install nsis, brew install makensis) and sha256sum or shasum. It never
# publishes anything: the release workflow uploads the files when the
# maintainer pushes a v* tag.
set -euo pipefail

# Pinned go-winres, run with go run: no module of leakguard depends on it.
winres=github.com/tc-hib/go-winres@v0.3.3

usage() {
	echo "usage: scripts/build-windows.sh VERSION   (for example 0.2.0, without the leading v)" >&2
	exit 2
}

[[ $# -eq 1 ]] || usage
version=$1
cd "$(dirname "$0")/.."
# tools/debversion checks VERSION (the rule of tools/infoplist); it
# explains a refusal and exits 2.
go run ./tools/debversion "$version" >/dev/null || usage
# Windows version resources are four numbers: 0.2.0-beta.1 is 0.2.0.0.
numeric=${version%%[-+]*}
[[ $numeric =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || usage
viversion=$numeric.0

for tool in go makensis; do
	command -v "$tool" >/dev/null || {
		echo "build-windows: $tool is missing" >&2
		exit 1
	}
done
if command -v sha256sum >/dev/null; then
	sha256() { sha256sum "$@"; }
elif command -v shasum >/dev/null; then
	sha256() { shasum -a 256 "$@"; }
else
	echo "build-windows: sha256sum or shasum is missing" >&2
	exit 1
fi

dist=dist
tray=cmd/leakguard-menubar
nsi=packaging/windows/leakguard.nsi
guide=docs/install-windows.md

work=$(mktemp -d "${TMPDIR:-/tmp}/leakguard-build.XXXXXX")
cleanup() {
	rm -rf "$work"
	rm -f "$tray"/rsrc_windows_*.syso
}
trap cleanup EXIT
umask 022

ldflags="-s -w -X github.com/Isaacpaezz/leakguard/internal/version.Version=$version"

echo "==> Drawing the icon"
go run ./tools/genappicon "$work/icon.iconset"

echo "==> Generating the tray's Windows resources (go-winres)"
res=$work/winres
mkdir -p "$res"
for size in 16 32 128 256; do
	cp "$work/icon.iconset/icon_${size}x${size}.png" "$res/icon_$size.png"
done
cp "$work/icon.iconset/icon_32x32@2x.png" "$res/icon_64.png"
cat >"$res/winres.json" <<EOF
{
  "RT_GROUP_ICON": {
    "APP": {"0000": ["icon_256.png", "icon_128.png", "icon_64.png", "icon_32.png", "icon_16.png"]}
  },
  "RT_MANIFEST": {
    "#1": {
      "0409": {
        "identity": {"name": "leakguard.tray", "version": "$viversion"},
        "description": "leakguard",
        "minimum-os": "win7",
        "execution-level": "as invoker",
        "ui-access": false,
        "auto-elevate": false,
        "dpi-awareness": "system",
        "disable-theming": false,
        "disable-window-filtering": false,
        "high-resolution-scrolling-aware": false,
        "ultra-high-resolution-scrolling-aware": false,
        "long-path-aware": false,
        "printer-driver-isolation": false,
        "gdi-scaling": false,
        "segment-heap": false,
        "use-common-controls-v6": true
      }
    }
  },
  "RT_VERSION": {
    "#1": {
      "0000": {
        "fixed": {"file_version": "$viversion", "product_version": "$viversion"},
        "info": {
          "0409": {
            "FileDescription": "leakguard",
            "FileVersion": "$version",
            "LegalCopyright": "MIT License",
            "OriginalFilename": "leakguard-tray.exe",
            "ProductName": "leakguard",
            "ProductVersion": "$version"
          }
        }
      }
    }
  }
}
EOF
rm -f "$tray"/rsrc_windows_*.syso
go run "$winres" make --in "$res/winres.json" --out "$tray/rsrc" --arch amd64,arm64

guidedef=()
if [[ -f $guide ]]; then
	guidedef=("-DGUIDE=$PWD/$guide")
else
	echo "build-windows: warning: $guide is missing; the installers go without the guide" >&2
fi

mkdir -p "$dist"
for arch in amd64 arm64; do
	echo "==> Building leakguard $version (windows/$arch)"
	bin=$work/bin-$arch
	mkdir -p "$bin"
	CGO_ENABLED=0 GOOS=windows GOARCH=$arch \
		go build -trimpath -ldflags "$ldflags" -o "$bin/leakguard.exe" ./cmd/leakguard
	CGO_ENABLED=0 GOOS=windows GOARCH=$arch \
		go build -trimpath -ldflags "$ldflags -H windowsgui" -o "$bin/leakguard-tray.exe" ./"$tray"

	setup=leakguard-$version-windows-$arch-setup.exe
	echo "==> Creating $dist/$setup"
	makensis -V2 -INPUTCHARSET UTF8 \
		"-DVERSION=$version" "-DVIVERSION=$viversion" "-DARCH=$arch" \
		"-DBINDIR=$bin" "-DLICENSEFILE=$PWD/LICENSE" "-DOUTFILE=$PWD/$dist/$setup" \
		${guidedef[@]+"${guidedef[@]}"} "$nsi"
	(cd "$dist" && sha256 "$setup" >"$setup.sha256")
done

echo "==> Done"
for arch in amd64 arm64; do
	cat "$dist/leakguard-$version-windows-$arch-setup.exe.sha256"
done
