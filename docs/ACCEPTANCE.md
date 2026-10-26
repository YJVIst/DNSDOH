# 测试与验收范围

项目采用真实 MariaDB、Rust 主控与双节点进程、独立协议验签服务器和 Playwright 浏览器测试。账号、服务器地址、证书、原始实机报告与含部署信息的截图不随公开仓库发布。

## v0.3 基础功能

- Rust 单元测试 9 项通过；额外供应商记录测试由协议测试启动。
- MariaDB + 双节点集成 74 项通过，包括权限、撤销、限速、Ed25519、防重放、配置租约和数据库故障恢复。
- 供应商 / SSH 协议 36 项通过：Cloudflare、AliDNS、DNSPod 的 A / AAAA / ACME TXT 增查删，独立 HMAC-SHA1 / TC3 验签，以及 SSH 私钥和主机指纹变化处理。
- 浏览器 21 项通过，覆盖业务创建、真实 DNS 查询、撤销、SSH 表单、一次性命令下载、删除、审计与 1440 / 1024 / 390 像素布局。
- 两台真实服务器完成统一域名直连 HTTPS、公共 DNS 私有记录隔离、DNS 增删和域名迁移。
- 真实远程 agent 崩溃重启、主控 MariaDB 停机 / 恢复通过；SQL 恢复到隔离库后成功解密 API 凭据、证书和 ACME 账户。

实际部署使用 Cloudflare。阿里云 DNS / DNSPod 尚无真实账户实测，协议测试不等同于供应商生产账户验收。没有执行 Clash Verge 客户端或真实代理节点联调。

节点在 Debian 13 实机完整安装通过；Alpine 3.23、Ubuntu 24.04、Debian 12、Rocky 9 官方根文件系统验证静态 agent 可运行和平台检测。后者不是完整 systemd / OpenRC / SELinux 安装验证。

## v0.3.1 一键主控

安装器 7 项检查通过，覆盖域名输入、随机凭据、0600 权限、拒绝符号链接、拒绝覆盖其他服务配置、Nginx 验证失败回滚和明文令牌保护。

完整实机新装检查 19 项通过、重复安装检查 19 项通过，使用独立的 Debian 13 主控安装，检验管理 HTTPS、随机账号登录、强制 DNS 向导、MariaDB 数据盘目录、服务和续期任务、备份，以及同域名重复安装保留凭据和业务数据。安装时原有 Nginx、DNS 节点和其他服务保持运行。

主控安装器目标平台为 Debian 12/13 和 Ubuntu 22.04/24.04；完整实机安装与重复安装证据以 Debian 13 为准。ARM64 尚未发布。

## 运行测试

```bash
python3 tests/installer.py
cargo test --locked
```

`tests/integration.py` 需要独立的 `*_test` MariaDB 库，会清空该测试库，不要传入生产库。配置路径使用 `DNSDOH_TEST_ENV`，运行目录用 `DNSDOH_TEST_RUNTIME`。CI 已配置该隔离数据库。

`tests/providers.py` 使用本地 HTTP 与 SSH fixture，需要 OpenSSH server、Python cryptography 及 root 测试环境；不会使用真实 DNS API 密钥。实机测试资料保留在操作者的数据盘，不属于公共交付文件。
