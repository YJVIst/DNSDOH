# 一键部署与运维

## 新装

主控安装器支持 Debian 12/13、Ubuntu 22.04/24.04，x86_64、systemd、root。内存建议至少 1 GiB。节点 agent 的发行版支持范围另见 [节点文档](NODES.md)。

先准备一个管理域名，例如 `admin.example.com`：公共 A / AAAA 应指向安装服务器；80 / 443 能从互联网访问。填写域名本身不能授权修改 DNS 供应商记录，因此这个初始管理域名需要预先解析。避免为没有 IPv6 连通性的服务器发布 AAAA。

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YJVIst/DNSDOH/main/install.sh)
```

仅提示管理域名。自动完成：

1. 下载 GitHub Release 静态二进制，验证 SHA-256，校验解压路径。
2. 安装 Nginx、Certbot、MariaDB core/client；不安装发行版默认 MariaDB 服务器实例。
3. 在所选安装目录初始化专用 MariaDB，回环端口 13306、独立系统用户和库账户。
4. 生成随机管理员用户名、32 字符随机密码、独立数据库密码、32 字节 AES 主密钥。
5. 启动回环 18080 的主控，数据库迁移自动完成。
6. 配置专用 Nginx 虚拟主机，通过 HTTP-01 申请管理 HTTPS，开启续期任务。
7. 启用 DoH 证书维护、每日备份和开机启动，验证实际 HTTPS 就绪接口。

Certbot 使用 webroot，不停止已有 Nginx，不反射明文 DoH 请求中的令牌；管理证书默认使用无需邮箱的 ACME 注册方式。Certbot 的 webroot 行为见 [官方说明](https://eff-certbot.readthedocs.io/en/stable/using.html#webroot)。

管理员初始凭据仅写入 root 可读文件，不写入公开日志：

```bash
cat /opt/dnsdoh/runtime/管理员登录信息.txt
```

首次登录仍需完成 DNS 供应商向导：填写自己的 API 凭据，选择有权限的主域名及 DoH 标签，然后系统自动创建统一 DoH 服务。建议管理域名 `admin.example.com`，DoH 域名 `doh.example.com`。两者不能重名。

## 安装目录

默认主控目录为 `/opt/dnsdoh`，节点目录为 `/opt/dnsdoh-node`。两者互相独立，不依赖开发机器的存储布局。

需要使用自己的数据盘时，在**首次安装**指定目录：

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/YJVIst/DNSDOH/main/install.sh) \
  --domain admin.example.com --data-dir /srv/dnsdoh
```

也可先 `export DNSDOH_DATA_ROOT=/srv/dnsdoh`。命令行 `--data-dir` 优先于环境变量，下载、数据库、凭据、证书、备份和生成的 systemd / Nginx 路径都会随之调整。目录须为独立绝对路径，不含空格、Shell 特殊字符或符号链接；不要放在 `/root`、`/home` 或 `/tmp`、`/var/tmp` 等临时目录，服务隔离会阻止访问。上级目录须允许服务用户穿越。

自定义路径后查看凭据：

```bash
cat /srv/dnsdoh/runtime/管理员登录信息.txt
```

已有版本继续使用原安装目录，重新运行时传入 `--data-dir 原绝对路径`。更换参数**不会搬迁**现有数据库、证书或身份；遇到其他目录的既有服务会拒绝覆盖。手动部署的既有服务仍按原有配置维护。

## 重试和已有服务器

相同域名、相同安装目录重跑保留数据库、管理员初始凭据和 AES 密钥。更改过后台密码后，登录文件中的初始密码不再适用；安装器不会重置它。域名验证失败可以修复 DNS / 防火墙后重试。

发现旧版手工部署、未知 `controller.env`、占用的 13306 / 18080、同名服务或外部 Nginx 虚拟主机时停止，避免覆盖其他应用。现有 v0.3 手动部署请按人工升级路径处理；不要删除配置文件绕过检查。独立节点可与主控共机，只要各自目录、配置和回环端口没有冲突。

安装器只写入自身 Nginx 文件，并在 `nginx -t` 失败时恢复原文件。不会关闭已有防火墙或开放数据库公网端口。若服务器启用了 UFW、安全组或上游防火墙，应允许 80 / 443。

失败日志：`/opt/dnsdoh/installer/controller-install.log`，0600。进度状态：`/opt/dnsdoh/runtime/install-controller.json`。同一时间仅允许一个安装进程。

可以下载并审阅脚本后执行；也可从 Release 解压到任意工作目录，用其 installer 和静态 agent 安装：

```bash
python3 ./DNSDOH/scripts/install-controller.py \
  --bundle ./DNSDOH --domain admin.example.com
```

直接运行 Python 安装器时，`--preflight` 只进行平台、域名格式和配置冲突检查，不执行安装。外层 `install.sh` 仍需先下载发布包。软件包仍需可用 apt 源，离线发布包不包含 Linux 系统包。

## 文件与服务

| 用途 | 路径 / 单元 |
| --- | --- |
| 主控 | `/opt/dnsdoh/DNSDOH/target/release/dnsdoh`、`dnsdoh@controller.service` |
| MariaDB | `/opt/dnsdoh/runtime/mariadb`、`dnsdoh-mariadb.service` |
| 数据库配置 | `/opt/dnsdoh/runtime/mariadb.cnf` |
| 主控秘密配置 | `/opt/dnsdoh/runtime/controller.env`，0600 |
| 管理凭据文件 | `/opt/dnsdoh/runtime/管理员登录信息.txt`，0600 |
| 管理域名 Nginx | `/etc/nginx/conf.d/dnsdoh-admin.conf` |
| 管理 HTTPS | runtime 下 `letsencrypt`，`dnsdoh-admin-cert.timer` |
| DoH 证书与 Nginx | `runtime/direct-tls`、`dnsdoh-domain-maintain.timer` |
| 节点发布文件 | `/opt/dnsdoh/hosting/downloads` |
| 每日备份 | `runtime/backups`、`dnsdoh-backup.timer` |
| 安装下载 / 日志 / 缓存 | `/opt/dnsdoh/installer` |

主控以 `dnsdoh` 用户运行，数据库以 `dnsdoh-db` 运行。根权限维护任务负责安装 / 应用证书；节点业务进程不持有供应商凭据。程序和运行数据均位于所选安装目录，不要求任何专用挂载点；发行版依赖及 systemd / Nginx 注册文件需要安装到系统目录。

```bash
systemctl status dnsdoh@controller dnsdoh-mariadb
systemctl list-timers 'dnsdoh-*'
nginx -t
python3 /opt/dnsdoh/DNSDOH/scripts/backup.py --env /opt/dnsdoh/runtime/controller.env --output /opt/dnsdoh/runtime/backups
```

## 证书与备份

管理证书使用 HTTP-01；保留管理域名的公网 80 端口验证路径。统一 DoH 证书由 Rust 主控通过供应商 DNS-01 管理，在到期前 30 天续期，失败退避重试；主控 root 维护任务每 10 秒应用，systemd 节点每 20 秒获取绑定。

每日 MariaDB 备份采用一致性事务、gzip、SHA-256 和原子替换，保留最近 14 份。每份 `.sql.gz` 同时有匹配的 `.env` 配置备份，权限 0600。**恢复 SQL 必须使用该数据库原来的 `DNSDOH_MASTER_KEY`**，否则供应商凭据、ACME 账户和证书无法解密。异地备份时加密保存这些文件，不要提交 Git。

数据库恢复先停止主控写入并备份当前状态，再导入 SQL 和对应配置。初始环境变量不会覆盖已存在的管理员；需要重置时设置受保护环境变量后使用程序 `reset-admin` 子命令。

## 更新

当前版本为 v0.3.3。一键脚本默认固定发布版本；以后发布新版本时会更新其默认值，也可显式指定 `DNSDOH_VERSION`。安装器支持同一管理域名、相同目录布局的重复安装，保留密钥与业务数据。升级前应保存数据库和 env 备份。

节点的独立升级使用后台「部署 / 重装」生成新任务，系统保留节点身份绑定，并核对 SSH 指纹。管理主控域名迁移不同于 DoH 域名更换，需另行调整管理 URL、证书及节点控制地址。
