# 源码构建与手动部署

一键主控安装、后台 SSH agent 安装都默认下载预编译的 x86_64 musl 静态程序，不会在目标服务器运行 Cargo 或 npm。性能不足的服务器可直接使用 Release；也可以在另一台 x86_64 构建机编译，再把发布包传到部署服务器。

主控和 agent 共用 Rust 程序：主控使用 `serve --mode controller`，节点使用 `serve --mode node`。Release 中两个独立二进制名称用于区分用途，内容和 SHA-256 相同。用户界面已内嵌，部署时不需要 Node.js。

## 1. 准备构建机

以下命令适用于 Debian / Ubuntu x86_64。构建机需要 Rust stable、Node.js 22 或 24、npm、Python 3、musl-tools。编译不需要连接生产数据库；运行集成测试时才需要独立 MariaDB 测试库。

```bash
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential musl-tools pkg-config curl ca-certificates git python3

# 只为尚不存在的专用构建目录设置属主，不改动已有部署数据盘。
if [ ! -d /mnt/youlin-data ]; then
  sudo install -d -m 755 -o "$(id -u)" -g "$(id -g)" /mnt/youlin-data
fi
mkdir -p /mnt/youlin-data/cache/cargo /mnt/youlin-data/cache/npm /mnt/youlin-data/tmp

export CARGO_HOME=/mnt/youlin-data/cache/cargo
export RUSTUP_HOME=/mnt/youlin-data/rustup
export npm_config_cache=/mnt/youlin-data/cache/npm
export TMPDIR=/mnt/youlin-data/tmp
export PATH="$CARGO_HOME/bin:$PATH"
```

已有部署数据盘请保留原权限，在获得写权限的构建目录操作，不要对数据库或整个目录递归改属主。

通过 [Rust 官方 rustup](https://rust-lang.github.io/rustup/installation/index.html) 安装最小工具链：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
  -o /mnt/youlin-data/tmp/rustup-init.sh
sh /mnt/youlin-data/tmp/rustup-init.sh -y --profile minimal
rustup component add rustfmt
rustup target add x86_64-unknown-linux-musl
```

从 [Node.js 官方下载页](https://nodejs.org/en/download) 安装 Node.js 22 / 24 的 Linux x64 版本。可解压官方二进制到 `/mnt/youlin-data/tools/node`，将其 `bin` 加到 PATH；不要求安装到系统根目录。确认：

```bash
rustc --version
cargo --version
node --version
npm --version
musl-gcc --version
```

## 2. 获取源码并编译

```bash
cd /mnt/youlin-data
git clone https://github.com/YJVIst/DNSDOH.git
cd DNSDOH
git checkout v0.3.2

# 减少并行编译的内存占用；不改变目标服务器的运行配置。
export CARGO_BUILD_JOBS=1

./scripts/build.sh
./scripts/build-agent.sh
```

`build.sh` 安装锁定的前端依赖、构建界面、检查 Rust 格式、执行单元测试并生成本机 Release 程序。`build-agent.sh` 编译包含同样功能的 musl 静态程序。

| 产物 | 用途 |
| --- | --- |
| `target/release/dnsdoh` | 构建机原生 Linux 程序，依赖构建机对应的系统 ABI |
| `target-musl/x86_64-unknown-linux-musl/release/dnsdoh` | 通用 x86_64 静态程序，主控和 agent 均可使用 |
| `web/dist` | 前端构建结果，已嵌入 Rust 程序 |

内存较小的构建机可进一步关闭 Release 的 LTO、增加 codegen units，代价是优化结果和二进制大小可能与官方发布不同：

```bash
export CARGO_BUILD_JOBS=1
export CARGO_PROFILE_RELEASE_LTO=false
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
./scripts/build.sh
./scripts/build-agent.sh
```

单任务构建仍需要编译器工作内存；机器资源不足时，直接使用 Release 或在另一台机器构建。Cargo 的并行参数见 [官方 build.jobs 说明](https://doc.rust-lang.org/cargo/reference/config.html#buildjobs)。

## 3. 打包并校验

```bash
python3 scripts/package.py
cd /mnt/youlin-data/artifacts
sha256sum -c SHA256SUMS
```

输出源码包、静态完整安装包、独立主控、独立 agent 和引导脚本。完整安装包内：

```text
DNSDOH/target/release/dnsdoh   # 静态主控
DNSDOH/agent/dnsdoh            # 静态 agent
DNSDOH/scripts/install-controller.py
DNSDOH/scripts/install-node.py
DNSDOH/deploy/...
DNSDOH/docs/...
```

如使用 Release 的独立文件，可在校验后执行 `chmod +x dnsdoh-controller-linux-amd64 dnsdoh-agent-linux-amd64`。独立文件不自动创建数据库、身份或 Nginx 配置；首次安装推荐使用完整包。

## 4. 把自建程序部署到服务器

将完整包和 `SHA256SUMS` 上传到目标服务器的数据盘，例如 `/mnt/youlin-data/incoming`。目标服务器只需 Debian 12/13 或 Ubuntu 22.04/24.04、x86_64、systemd 和 root，不需要编译工具。

```bash
cd /mnt/youlin-data/incoming
# 从完整校验文件只检查本次传入的完整安装包。
sha256sum --check <(grep '  DNSDOH-linux-amd64.tar.gz$' SHA256SUMS)
mkdir -p /mnt/youlin-data/local-release
tar -xzf DNSDOH-linux-amd64.tar.gz -C /mnt/youlin-data/local-release

python3 /mnt/youlin-data/local-release/DNSDOH/scripts/install-controller.py \
  --bundle /mnt/youlin-data/local-release/DNSDOH \
  --domain admin.example.com
```

将 `admin.example.com` 换成已解析到本机的管理域名，开放 80 / 443。此路径使用你刚编译的本地程序，不会重新从 GitHub 下载程序，也不会在目标机器编译；安装器会通过 apt 安装 Nginx、MariaDB core 和 Certbot 等运行依赖。

安装完成后：

```bash
cat /mnt/youlin-data/runtime/管理员登录信息.txt
systemctl status dnsdoh@controller dnsdoh-mariadb
nginx -t
```

首次登录，配置自己的 DNS 供应商 API、主域名和统一 DoH 标签。无需将私有节点记录公开到供应商。

## 5. 手工维护主控

安装器生成的文件和服务路径详见 [部署文档](DEPLOYMENT.md)。如果采用自有 MariaDB / Nginx 运维方案，可按以下要点人工配置：

1. 创建 `utf8mb4` 的专用 MariaDB 库及库账户，数据库仅允许主控访问。
2. 将 `deploy/controller.env.example` 复制到仓库外的 `runtime/controller.env`，填写数据库 URL、管理员初始账户、随机密码、管理 HTTPS URL 和 32 字节 base64url AES 主密钥；权限 0600。URL 中的数据库密码特殊字符需要编码。
3. 把静态程序放到 `/mnt/youlin-data/DNSDOH/target/release/dnsdoh`。主控使用非特权 `dnsdoh` 用户，环境文件由 systemd 的 `EnvironmentFile` 读取。调整 `deploy/dnsdoh@.service` 的路径后安装并启用 `dnsdoh@controller`。
4. 按 `deploy/nginx.conf` 配置管理域名代理到回环 18080；证书由你的现有 ACME 工具管理。不要将带令牌路径写入访问日志，不要公开管理数据库端口。
5. 安装 `dnsdoh-domain-maintain.service` / `.timer`，为 root 提供同一份加密配置。它负责将后台生成的统一 DoH 证书应用到专用 Nginx 文件。初次向导完成前不要预占新的 DoH 主机名。
6. 发布 agent 下载文件与清单，按下一节接入节点；配置每日 SQL + 主密钥备份和管理证书续期。

自定义已有部署不属于一键安装器的重复安装范围；它会拒绝覆盖未知配置。不要删除 env 或 AES 密钥来绕过检查。

源码运行时，可用 `scripts/run.py` 安全加载 root 专属环境文件，无需将凭据放到命令参数：

```bash
python3 scripts/run.py --env /mnt/youlin-data/runtime/controller.env migrate
python3 scripts/run.py --env /mnt/youlin-data/runtime/controller.env serve
```

数据库为空时初始化管理员；已有管理员不会被初始环境变量覆盖。服务托管时使用 systemd，以上前台命令用于人工运行与诊断。

## 6. 自建 agent 的发布与部署

完整包安装器已经自动发布其携带的 agent，无需重复操作。若后续仅更新自建 agent，可在主控上复制静态文件并生成匹配清单：

```bash
python3 - <<'PY'
import hashlib, json, re, shutil, subprocess
from pathlib import Path
binary = Path('/mnt/youlin-data/DNSDOH/target-musl/x86_64-unknown-linux-musl/release/dnsdoh')
version = subprocess.check_output([binary, '--version'], text=True).split()[-1]
assert re.fullmatch(r'\d+\.\d+\.\d+', version)
out = Path('/mnt/youlin-data/hosting/downloads')
out.mkdir(parents=True, exist_ok=True)
name = f'dnsdoh-{version}-linux-x86_64-musl'
shutil.copy2(binary, out/name)
(out/name).chmod(0o644)
manifest = {'version': version, 'platform': 'linux-x86_64', 'libc': 'musl',
            'file': name, 'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()}
tmp = out/'latest.json.new'
tmp.write_text(json.dumps(manifest, indent=2))
tmp.chmod(0o644)
tmp.replace(out/'latest.json')
PY
```

后台「DNS 服务器」选择 SSH 部署，或生成一次性安装命令。这两种方式都从主控 `/downloads/` 获取上述二进制，校验 SHA-256，在目标节点本地生成 Ed25519 私钥并完成接入，不进行源码编译。

直接运行 `dnsdoh-agent-linux-amd64 serve` 的默认模式是主控；节点必须显式配置 `DNSDOH_MODE=node` 或 `--mode node`，以及通过注册生成的节点 ID / 私钥 / 主控 URL。不要复用其他服务器的身份。已有配置模板见 `deploy/node.env.example`，完整签名、租约和证书维护说明见 [节点文档](NODES.md)。
