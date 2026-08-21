#!/bin/sh
set -eu

dist=${1:?dist directory is required}
repo=${2:?GitHub repository is required}
tag=${3:?release tag is required}
if ! printf '%s\n' "$tag" | grep -Eq '^[0-9]{4}\.[0-9]{2}\.[0-9]{2}\.(0|[1-9][0-9]*)$'; then
  echo "invalid release tag: $tag" >&2
  exit 1
fi
base="https://github.com/$repo/releases/download/$tag"

checksum() {
  shasum -a 256 "$1" | awk '{print $1}'
}

darwin_arm64="paperboat_${tag}_darwin_arm64.tar.gz"
linux_amd64="paperboat_${tag}_linux_amd64.tar.gz"
linux_arm64="paperboat_${tag}_linux_arm64.tar.gz"
for file in "$darwin_arm64" "$linux_amd64" "$linux_arm64"; do
  test -f "$dist/$file"
done

cat > "$dist/paperboat.rb" <<EOF
class Paperboat < Formula
  desc "Connect to Paperboat cloud project terminals"
  homepage "https://github.com/$repo"
  version "$tag"
  on_macos do
    url "$base/$darwin_arm64"
    sha256 "$(checksum "$dist/$darwin_arm64")"
  end

  on_linux do
    if Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "$base/$linux_arm64"
      sha256 "$(checksum "$dist/$linux_arm64")"
    else
      url "$base/$linux_amd64"
      sha256 "$(checksum "$dist/$linux_amd64")"
    end
  end

  def install
    bin.install "pb"
    bin.install_symlink "pb" => "paperboat"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pb --version")
  end
end
EOF
