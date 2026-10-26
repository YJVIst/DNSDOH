# XBoard 私人 DNS 订阅模板

本目录提供六份完整模板，供 XBoard 后台「系统配置 → 订阅模板」使用。它们是带占位符的发布示例，不包含任何可用访问密钥；必须先替换下表中的值再保存到后台。

| 示例值 | 替换为 |
| --- | --- |
| `doh.example.com` | DNSDOH 统一 DoH 域名，需由公共 DNS 解析到已升级服务器 |
| `nodes.example.com` | 在 DNSDOH 中创建并授权给令牌用户的私有分区 |
| `node1.nodes.example.com` | 已有的私有节点域名；若仅依赖分区规则，可移除对应精确匹配项 |
| `YOUR_DNSDOH_TOKEN` | DNSDOH 创建令牌时返回的 43 字符原始令牌，不能用令牌 ID 代替 |

先替换完整节点域名，再替换分区。每份模板建议使用不同令牌；同一模板内的所有令牌占位符使用同一值。已有私有解析记录无需重复创建，但 XBoard 的节点地址必须是对应私有域名；不要把协议的 TLS SNI 随意改成私有节点域名。

保留 `$app_name`、`$proxies`、`$proxy_group`、`$subs_link`、`$subscribe_info`、`$subs_domain` 等已有 XBoard 变量，由 XBoard 生成订阅时填入。各版本 XBoard 的变量和客户端导出适配可能不同，保存后应检查实际导出结果。示例中的规则和代理组可按自己的业务调整。

| XBoard 模板栏目 | 文件 | 私有节点解析方式 |
| --- | --- | --- |
| Sing-box | [sing-box.json](sing-box.json) | HTTPS DNS 服务及 `route.default_domain_resolver`，面向 sing-box 1.12+ |
| Clash | [clash.yaml](clash.yaml) | `nameserver-policy`；传统 Clash 不支持 AnyTLS |
| Clash Meta | [clash-meta.yaml](clash-meta.yaml) | 节点专用 `proxy-server-nameserver-policy`，供支持该字段的 Mihomo 使用 |
| Stash | [stash.yaml](stash.yaml) | `nameserver-policy` 与专用节点解析器；后者要求 iOS/tvOS 3.6+、macOS 4.3+ |
| Surge | [surge.conf](surge.conf) | 唯一 `doh-server` 指向兼容入口，兼顾私有节点与公共域名 |
| Surfboard | [surfboard.conf](surfboard.conf) | `[Host]` 按私有域名指定 DoH；请使用支持节点 Host 规则与按域名 DoH 的新版本 |

## 服务器要求

主控与统一 DoH 域名指向的**所有 agent**均需升级到 v0.3.4 或更新版本。兼容入口格式为：

```text
https://doh.example.com/dns-query/compat/YOUR_DNSDOH_TOKEN
```

普通私有入口仍为 `/dns-query/<token>`。兼容入口先验证令牌，已配置私有分区（含停用分区）不转发公共 DNS；仅其他域名通过固定 HTTPS 公共上游解析。旧主控没有完整私有分区列表时会拒绝公共转发。详见 [兼容入口](../../docs/COMPATIBILITY.md)。

不同客户端支持的代理协议并不相同。DNS 模板不会让传统 Clash 支持 AnyTLS，也不能替代代理自身的密码、证书和用户授权。静态模板令牌由使用该模板的用户共享；本版本没有实现 XBoard 逐用户令牌映射。

## NekoBox Android 1.4.2

普通订阅导入会提取节点，再使用 NekoBox 本地设置生成配置；即使订阅响应是 Clash YAML 或 sing-box JSON，也不会自动采用其中的完整 DNS 设置。节点解析和 URL 测速使用「设置 → DNS 设置 → 直连 DNS」。使用当前普通订阅时，需要将此项设置为自己的完整兼容 DoH 地址。

本发布没有实现 NekoBox `sn://` 专用订阅转换，也不宣称六个模板能自动覆盖这种导入方式。完整配置导入与普通节点订阅是不同模式。

## 验证范围

发布前已检查六份模板的格式及占位符；Mihomo 1.19.33 和 sing-box 1.14.4 的配置检查通过。部署验收验证了两台 HTTPS 服务器的私有解析、公共解析、无效令牌和越权拒绝。NekoBox 1.4.2 用户已验证修改直连 DNS 后可连接。

Stash、Surge、Surfboard 的配置依据官方文档整理，未在各自原生客户端完成连接测试。示例模板仍需结合自己的 XBoard、客户端版本和订阅内容验收。

参考：[Mihomo DNS](https://wiki.metacubex.one/config/dns/)、[sing-box Dial Fields](https://sing-box.sagernet.org/configuration/shared/dial/)、[Stash DNS](https://stash.wiki/en/features/dns-server)、[Surge Encrypted DNS](https://manual.nssurge.com/dns/encrypted-dns.html)、[Surfboard Host](https://getsurfboard.com/docs/ai-profile-guide/reference/)、[NekoBox 1.4.2 配置生成](https://github.com/MatsuriDayo/NekoBoxForAndroid/blob/1.4.2/app/src/main/java/io/nekohasekai/sagernet/fmt/ConfigBuilder.kt)。
