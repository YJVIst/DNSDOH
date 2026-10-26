# 客户端兼容 DoH 入口

普通入口 `/dns-query/<token>` 保持仅解析已授权私有分区的行为。
需要一个解析器同时处理节点域名和公共域名的客户端，可使用：

```text
https://doh.example.com/dns-query/compat/<43字符随机令牌>
```

兼容入口支持 RFC 8484 GET / POST，使用相同的令牌、有效期、分区授权、限速和配置租约。它先认证，再处理 DNS 问题：

- 所有已配置私有分区（包括停用分区）都在本地处理。未授权返回 REFUSED；不存在的私有记录返回 NXDOMAIN。两者均不会回退公共 DNS。
- 其他 IN 类普通查询通过 HTTPS 转发给固定公共上游 Cloudflare 1.1.1.1，网络或响应错误时尝试阿里 DNS 223.5.5.5。公共上游会看到这些公共域名查询。
- 不转发令牌、客户端 IP 请求头、EDNS Client Subnet 或附加记录；校验响应的问题、事务 ID、大小和类型。
- 公共上游都失败时返回 SERVFAIL。原私有解析服务不受公共上游故障影响。
- 旧主控快照没有完整私有分区列表时，兼容入口拒绝公共转发。先升级主控，再升级统一 DoH 域名指向的所有 agent。

Mihomo 可用 `proxy-server-nameserver-policy` 分配私有分区；sing-box 1.12+ 可使用 HTTPS 类型 DNS 服务，并将 `route.default_domain_resolver` 指向兼容入口。DoH 服务器域名自身应使用独立公共解析器引导，以避免循环。

Surge 可将兼容入口设置为唯一 `doh-server`；不要同时配置公共 DoH 与私有 DoH 竞速。Stash 新版本可将兼容入口配置到 `proxy-server-nameserver`。Surfboard 新版本可在 `[Host]` 中对私有分区配置 `server:https://...`。

订阅模板中的固定令牌由使用该模板的用户共享，不等于为每位订阅用户单独签发令牌。要按订阅用户撤销权限，需要额外的 XBoard 用户与 DNSDOH 用户映射。

模板只能控制 DNS，不会为客户端增加代理协议支持。例如传统 Clash 不支持 AnyTLS，应使用支持该协议的 Mihomo / Clash Meta 等客户端。

六种可导入 XBoard 的完整示例见 [templates/xboard](../templates/xboard/README.md)。示例必须替换域名和令牌；NekoBox 普通订阅限制也在该目录说明。
