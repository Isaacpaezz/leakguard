#!/usr/bin/env bash
# Builds the Linux packages people download from GitHub Releases.
#
#   scripts/build-linux.sh VERSION      # for example 0.2.0, without the v
#
# Output, in dist/ (ignored by git), for ARCH amd64 and arm64:
#   dist/leakguard-VERSION-linux-ARCH.tar.gz   both binaries, the .desktop file,
#                                              the icon, the guide, LICENSE
#   dist/leakguard_VERSION_ARCH.deb            for Debian, Ubuntu and Mint
#   and a .sha256 checksum next to each file.
#
# The .deb's Version field is the Debian form of VERSION (0.2.0-beta.1
# becomes 0.2.0~beta.1, see tools/debversion); its file name keeps VERSION
# so it matches the tag. The binaries are static (no cgo): the tray app
# talks to the desktop over D-Bus in pure Go.
#
# Needs Linux with Go, GNU tar, dpkg-deb 1.19 or newer and sha256sum (any
# Debian or Ubuntu has them). It never publishes anything: the release
# workflow uploads the files when the maintainer pushes a v* tag.
set -euo pipefail

usage() {
	echo "usage: scripts/build-linux.sh VERSION   (for example 0.2.0, without the leading v)" >&2
	exit 2
}

[[ $# -eq 1 ]] || usage
version=$1
# The same rule as tools/infoplist and tools/debversion.
semver='^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z-]+)*)?$'
[[ $version =~ $semver ]] || {
	echo "build-linux: \"$version\" is not a version like 1.2.3 or 1.2.3-rc.1" >&2
	usage
}
[[ $(uname -s) == Linux ]] || {
	echo "build-linux: run this on Linux" >&2
	exit 1
}
for tool in go tar dpkg-deb sha256sum; do
	command -v "$tool" >/dev/null || {
		echo "build-linux: $tool is missing" >&2
		exit 1
	}
done

cd "$(dirname "$0")/.."
dist=dist
pkg=packaging/linux
debversion=$(go run ./tools/debversion "$version")

work=$(mktemp -d "${TMPDIR:-/tmp}/leakguard-build.XXXXXX")
trap 'rm -rf "$work"' EXIT
umask 022

ldflags="-s -w -X github.com/Isaacpaezz/leakguard/internal/version.Version=$version"

echo "==> Drawing the icon"
go run ./tools/genappicon "$work/icon.iconset"

mkdir -p "$dist"
for arch in amd64 arm64; do
	echo "==> Building leakguard $version (linux/$arch)"
	bin=$work/bin-$arch
	mkdir -p "$bin"
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
		go build -trimpath -ldflags "$ldflags" -o "$bin/leakguard" ./cmd/leakguard
	CGO_ENABLED=0 GOOS=linux GOARCH=$arch \
		go build -trimpath -ldflags "$ldflags" -o "$bin/leakguard-tray" ./cmd/leakguard-menubar

	tarball=leakguard-$version-linux-$arch.tar.gz
	echo "==> Creating $dist/$tarball"
	top=leakguard-$version-linux-$arch
	stage=$work/tar/$top
	mkdir -p "$stage"
	install -m 0755 "$bin/leakguard" "$bin/leakguard-tray" "$stage/"
	install -m 0644 "$pkg/leakguard.desktop" "$stage/leakguard.desktop"
	install -m 0644 "$work/icon.iconset/icon_256x256.png" "$stage/leakguard.png"
	install -m 0644 docs/install-linux.md "$stage/install-linux.md"
	install -m 0644 LICENSE "$stage/LICENSE"
	tar --sort=name --owner=0 --group=0 --numeric-owner \
		-C "$work/tar" -czf "$dist/$tarball" "$top"

	deb=leakguard_${version}_$arch.deb
	echo "==> Creating $dist/$deb (Version $debversion)"
	root=$work/deb-$arch
	install -D -m 0755 "$bin/leakguard" "$root/usr/bin/leakguard"
	install -D -m 0755 "$bin/leakguard-tray" "$root/usr/bin/leakguard-tray"
	install -D -m 0644 "$pkg/leakguard.desktop" "$root/usr/share/applications/leakguard.desktop"
	install -D -m 0644 "$pkg/dev.leakguard.policy" "$root/usr/share/polkit-1/actions/dev.leakguard.policy"
	install -D -m 0644 LICENSE "$root/usr/share/doc/leakguard/copyright"
	install -D -m 0644 docs/install-linux.md "$root/usr/share/doc/leakguard/install-linux.md"
	# hicolor sizes from the macOS icon set: name@2x is twice the size.
	for size in 16 32 64 128 256 512; do
		case $size in
		64) src=icon_32x32@2x.png ;;
		*) src=icon_${size}x${size}.png ;;
		esac
		install -D -m 0644 "$work/icon.iconset/$src" \
			"$root/usr/share/icons/hicolor/${size}x${size}/apps/leakguard.png"
	done
	install -D -m 0755 "$pkg/prerm" "$root/DEBIAN/prerm"
	size=$(du -sk --exclude=DEBIAN "$root" | cut -f1)
	sed -e "s/@VERSION@/$debversion/" -e "s/@ARCH@/$arch/" -e "s/@INSTALLED_SIZE@/$size/" \
		"$pkg/control" >"$root/DEBIAN/control"
	chmod 0644 "$root/DEBIAN/control"
	if grep -q '@[A-Z_]*@' "$root/DEBIAN/control"; then
		echo "build-linux: $pkg/control has a placeholder left" >&2
		exit 1
	fi
	dpkg-deb --root-owner-group -Zxz --build "$root" "$dist/$deb" >/dev/null

	(cd "$dist" && sha256sum "$tarball" >"$tarball.sha256" && sha256sum "$deb" >"$deb.sha256")
done

echo "==> Done"
for arch in amd64 arm64; do
	cat "$dist/leakguard-$version-linux-$arch.tar.gz.sha256" "$dist/leakguard_${version}_$arch.deb.sha256"
done
