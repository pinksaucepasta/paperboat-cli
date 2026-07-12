#!/bin/sh
set -eu

dist=${1:?dist directory is required}
repo=${2:?GitHub repository is required}
tag=${3:?release tag is required}
if ! printf '%s\n' "$tag" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$'; then
  echo "invalid release tag: $tag" >&2
  exit 1
fi
base="https://github.com/$repo/releases/download/$tag"

checksum() {
  shasum -a 256 "$1" | awk '{print $1}'
}

darwin_amd64="paperboat-cli_${tag}_darwin_amd64.tar.gz"
darwin_arm64="paperboat-cli_${tag}_darwin_arm64.tar.gz"
linux_amd64="paperboat-cli_${tag}_linux_amd64.tar.gz"
linux_arm64="paperboat-cli_${tag}_linux_arm64.tar.gz"
windows_amd64="paperboat-cli_${tag}_windows_amd64.zip"
windows_arm64="paperboat-cli_${tag}_windows_arm64.zip"

for file in "$darwin_amd64" "$darwin_arm64" "$linux_amd64" "$linux_arm64" "$windows_amd64" "$windows_arm64"; do
  test -f "$dist/$file"
done

cat > "$dist/paperboat.rb" <<EOF
class Paperboat < Formula
  desc "Connect to Paperboat cloud project terminals"
  homepage "https://github.com/$repo"
  version "${tag#v}"
  on_macos do
    if Hardware::CPU.arm?
      url "$base/$darwin_arm64"
      sha256 "$(checksum "$dist/$darwin_arm64")"
    else
      url "$base/$darwin_amd64"
      sha256 "$(checksum "$dist/$darwin_amd64")"
    end
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

cat > "$dist/paperboat.json" <<EOF
{
  "version": "${tag#v}",
  "description": "Connect to Paperboat cloud project terminals",
  "homepage": "https://github.com/$repo",
  "architecture": {
    "64bit": { "url": "$base/$windows_amd64", "hash": "$(checksum "$dist/$windows_amd64")" },
    "arm64": { "url": "$base/$windows_arm64", "hash": "$(checksum "$dist/$windows_arm64")" }
  },
  "bin": [["pb.exe", "pb"], ["pb.exe", "paperboat"]]
}
EOF
