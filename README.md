# DNSDOH

Rust + MariaDB 私有 DNS-over-HTTPS 服务，附带中文管理后台、用户令牌、多服务器和 DNS 供应商自动化。

公共 DNS 仅发布解析器地址。实际节点域名放在私有分区，用户携带独立随机令牌才能查询获授权的 IP。统一 DoH 域名通过 DNS-only A / AAAA 直接指向各服务器，不经过主控网关转发。

## 一键安装主控

支持 **Debian 12/13、Ubuntu 22.04/24.04，x86_64，systemd，root**。先将一个管理域名的 A / AAAA 指向本机，并开放公网 TCP 80、443；推荐使用 DNS-only 记录。请仅发布本机实际可用的 IPv6 地址。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YJVIst/DNSDOH/main/install.sh)
```

按提示填写管理域名，例如 `admin.example.com`。也可直接传入：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YJVIst/DNSDOH/main/install.sh) --domain admin.example.com
```

脚本从 GitHub Release 下载静态程序并校验 SHA-256，自动安装 Nginx、独立 MariaDB、管理 HTTPS、证书续期、备份和 systemd 服务。无需安装 Rust 或 Node.js，无需填写数据库密码或管理员密码。

随机生成的管理员账号、初始密码保存在 root 专属文件：

```bash
cat /opt/dnsdoh/runtime/管理员登录信息.txt
```

默认将程序、数据库、缓存、证书、日志和下载放在 `/opt/dnsdoh`，无需挂载专用硬盘。可使用 `--data-dir /srv/dnsdoh` 或 `DNSDOH_DATA_ROOT` 指定其他目录；管理员凭据位于所选目录的 `runtime/管理员登录信息.txt`。系统目录只安装发行版软件包及服务 / Nginx 注册文件。已有不属于本安装器的主控、数据库端口或同名虚拟主机不会被覆盖。相同域名、相同安装目录重试保留已有密码和数据库。旧版安装请显式指定原目录，本次更新不自动迁移数据。

**填写域名无法代替 DNS 供应商授权。** 一键脚本完成管理主控安装；首次登录后，在强制向导中填写自己的 DNS API 凭据、选择主域名和 DoH 标签。随后系统自动申请统一 DoH 证书、配置解析并接入节点。项目不附带任何供应商令牌或预置管理员密码。

## 二进制与源码下载

[GitHub Releases](https://github.com/YJVIst/DNSDOH/releases/latest) 同时提供：

| 文件 | 用途 |
| --- | --- |
| `dnsdoh-controller-linux-amd64` | 已编译的静态主控程序 |
| `dnsdoh-agent-linux-amd64` | 已编译的静态节点程序 |
| `DNSDOH-linux-amd64.tar.gz` | 主控、agent、安装脚本和部署文档完整包 |
| `DNSDOH-source.tar.gz` | 公开源码与构建脚本 |
| `DNSDOH-install.sh` | 默认下载二进制的一键安装脚本 |
| `SHA256SUMS` | 所有下载文件的校验值 |

**一键安装和后台 SSH 节点部署都直接使用二进制，不会在目标服务器编译。** 低配置服务器无需 Rust / Node.js。主控和 agent 共享同一个 Rust 程序，通过运行模式区分，因此两个独立下载文件的校验值相同。

需要自行构建时，见 [源码构建及手动部署教程](docs/BUILD.md)，包含单任务构建参数、静态二进制构建、离线传包部署和人工维护步骤。

## 主要功能

- RFC 8484 GET / POST，A / AAAA / SOA，NXDOMAIN / NODATA / REFUSED；私有查询不递归回退公共 DNS。
- 私有分区、用户分区授权、有效期、停用；256 位随机令牌、独立撤销、一次性显示与下载。
- Cloudflare API Token / Global API Key、阿里云 DNS、腾讯云 DNSPod；账户域名分页选择。
- 统一 DoH 域名；服务器 HTTPS 与同步就绪后自动发布记录，停用 / 删除自动清理，失败保留账本重试。
- SSH 密码 / 私钥自动安装，服务器指纹校验及重装后的新指纹确认；可选单次安装命令。
- HTTPS + Ed25519 配置同步与证书控制，防重放；节点无需连接 MariaDB。
- DNS-01 自动证书申请、续期与分发；域名监测、修复、更换及旧域名迁移期。
- React / TypeScript 中文仪表盘、操作审计、查询统计与限速，适配手机和桌面。
- Argon2 管理密码、可撤销 Cookie 会话、CSRF；供应商凭据和证书在 MariaDB 中使用 AES-256-GCM 加密。

## 六种 XBoard 订阅模板

[templates/xboard](templates/xboard/README.md) 提供 Sing-box、Clash、Clash Meta、Stash、Surge、Surfboard 六份模板。将示例 DoH 域名、私有分区、节点域名和令牌替换后，粘贴到 XBoard 对应的订阅模板栏目。源码包、完整二进制包和独立 `DNSDOH-xboard-templates.tar.gz` 均附带这些文件。

模板没有真实访问密钥；不同模板建议使用独立令牌。NekoBox 普通订阅不会应用完整模板中的 DNS 配置，接入限制见模板说明。

## 用户接入

后台创建私有分区（如 `nodes.example.com`），添加实际节点 IP；创建用户、授权分区并签发完整地址：

```text
https://doh.example.com/dns-query/<43字符随机令牌>
```

用户只需在支持 DoH 的客户端中设置该完整地址。无需 UA 限制或额外请求头。UA 可以伪造，不能作为可靠身份。

需要同一解析器兼容公共域名时，可使用独立的[客户端兼容入口](docs/COMPATIBILITY.md)。私有分区不会回退公共 DNS；原入口行为不变。

新增 DNS 服务器只填公网 IP、SSH 端口、用户名、密码 / 私钥，核对服务器指纹后自动部署。服务器使用同一个 DoH 域名，不必逐个准备独立 HTTPS 名称。

## 运行边界

- 普通多地址 DNS 不保证选中最快服务器。当前不依赖或自动开通 Cloudflare 付费 Load Balancing / Anycast。
- 配置每 3 秒同步，租约 15 秒。主控 / 数据库失联后节点在租约到期时停止解析，恢复后自动同步；当前为单主控。
- 令牌限制后续 DNS 查询，不能撤销已获得的 IP、客户端缓存或已建立连接；代理服务自身仍应认证。
- 统一域名证书及解析配置会分发给节点，仅接入可信服务器。
- 更换 DoH 域名后用户需更新 URL，原令牌不变；旧域名默认保留 7 天。管理后台域名迁移需单独运维处理。
- 数据库恢复必须同时恢复原 `DNSDOH_MASTER_KEY`。每日备份会保存 SQL 和对应环境配置，文件权限 0600。

## 开发、部署与测试

源码编译需要 Rust stable、Node.js 20.19+、MariaDB。依赖锁定在 Cargo.lock / package-lock.json，构建缓存默认写入仓库下的 `.build/`，可通过 `DNSDOH_BUILD_ROOT` 指定其他目录。

```bash
./scripts/build.sh
# 准备 Rust toolchain 与系统 musl-tools 后构建通用静态 agent
./scripts/build-agent.sh
```

CI 使用真实 MariaDB 进行集成测试。部署验收还覆盖两台服务器的 HTTPS、SSH 安装、DNS 记录增删、域名切换和数据库故障恢复。

Cloudflare 已用真实账户验证；阿里云 DNS / DNSPod 经过独立签名与记录生命周期协议测试。主控安装器完整实机验收见 [测试范围](docs/ACCEPTANCE.md)。节点支持多个 Linux 包管理器；除实测平台外，不将静态运行检查等同于完整安装验证。

- [源码构建与手动部署](docs/BUILD.md)
- [一键安装与运维](docs/DEPLOYMENT.md)
- [节点、连接安全及域名迁移](docs/NODES.md)
- [HTTP API](docs/API.md)
- [验收与测试范围](docs/ACCEPTANCE.md)

MIT License。
