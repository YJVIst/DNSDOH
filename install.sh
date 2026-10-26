#!/usr/bin/env bash
# DNSDOH controller bootstrap. All downloads and temporary data stay on the data disk.
set -euo pipefail
umask 077
version="${DNSDOH_VERSION:-v0.3.1}"
repository="YJVIst/DNSDOH"
installer_root=/mnt/youlin-data/installer
if [[ ${EUID} -ne 0 ]]; then echo '请使用 root 执行安装。' >&2; exit 1; fi
if [[ $(uname -m) != x86_64 ]]; then echo '主控一键安装目前支持 Linux x86_64。' >&2; exit 1; fi
if [[ ! $version =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo '版本号格式错误。' >&2; exit 1; fi
if ! command -v apt-get >/dev/null; then echo '主控一键安装支持 Debian 12/13、Ubuntu 22.04/24.04。' >&2; exit 1; fi
mkdir -p "$installer_root/cache" "$installer_root/tmp" "$installer_root/apt-cache" "$installer_root/apt-lists/partial"
export TMPDIR="$installer_root/tmp" DEBIAN_FRONTEND=noninteractive
if ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
  apt-get -o Dir::Cache="$installer_root/apt-cache" -o Dir::State::lists="$installer_root/apt-lists" update -qq
  apt-get -o Dir::Cache="$installer_root/apt-cache" -o Dir::State::lists="$installer_root/apt-lists" install -y --no-install-recommends python3 curl ca-certificates
fi
bundle="$installer_root/cache/DNSDOH-linux-amd64.tar.gz"
checksums="$installer_root/cache/SHA256SUMS"
release="https://github.com/$repository/releases/download/$version"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 "$release/DNSDOH-linux-amd64.tar.gz" -o "$bundle"
curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --retry 3 "$release/SHA256SUMS" -o "$checksums"
python3 - "$bundle" "$checksums" "$installer_root/stage-$version" <<'PY'
import hashlib, pathlib, shutil, sys, tarfile
bundle, checksums, dest = map(pathlib.Path, sys.argv[1:])
expected = [line.split()[0] for line in checksums.read_text().splitlines() if line.split()[-1] == bundle.name]
if len(expected) != 1 or hashlib.sha256(bundle.read_bytes()).hexdigest() != expected[0]:
    raise SystemExit('发布包 SHA-256 校验失败；未执行安装。')
with tarfile.open(bundle) as archive:
    members = archive.getmembers()
    if sum(m.size for m in members) > 512 * 1024 * 1024:
        raise SystemExit('发布包超出大小限制。')
    for m in members:
        p = pathlib.PurePosixPath(m.name)
        if p.is_absolute() or '..' in p.parts or not p.parts or p.parts[0] != 'DNSDOH' or not (m.isfile() or m.isdir()):
            raise SystemExit('发布包含有不安全路径或文件类型。')
    if dest.exists(): shutil.rmtree(dest)
    for m in members:
        path = dest / m.name
        if m.isdir(): path.mkdir(parents=True, exist_ok=True); continue
        path.parent.mkdir(parents=True, exist_ok=True)
        with archive.extractfile(m) as src, path.open('wb') as out: shutil.copyfileobj(src, out)
        path.chmod(0o755 if m.mode & 0o111 else 0o644)
print('发布包已通过校验。')
PY
exec python3 "$installer_root/stage-$version/DNSDOH/scripts/install-controller.py" "$@"
