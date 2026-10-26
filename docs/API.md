# HTTP 接口

所有 JSON 写入接口拒绝未知字段。后台接口需要 `dnsdoh_session` Cookie；除登录外的写入还需要会话返回的 `X-CSRF-Token`。浏览器提供 Origin 时必须与 `DNSDOH_PUBLIC_URL` 完全匹配。

| 方法 | 路径 | 用途 |
| --- | --- | --- |
| POST | `/api/login` | `{username,password}`，返回 csrf 并设置 Cookie |
| GET | `/api/session` | 当前管理员、csrf、版本与入口 |
| POST | `/api/logout` | 撤销当前会话 |
| POST | `/api/password` | `{current_password,new_password}`，撤销其他会话 |
| GET | `/api/state` | 后台状态、用户、分区、记录、令牌标识、节点、聚合统计和审计 |
| POST / PUT | `/api/users` / `/api/users/{id}` | `{name,note?,enabled?,expires_at?,zone_ids?}` |
| POST / PUT | `/api/zones` / `/api/zones/{id}` | `{name,note?,enabled?}` |
| POST / PUT | `/api/records` / `/api/records/{id}` | `{zone_id,name,record_type,value,ttl?,enabled?}` |
| POST | `/api/tokens` | `{user_id,name,expires_at?}`，一次性返回 token 与 doh_url |
| POST | `/api/tokens/{id}/revoke` | 不可逆撤销 |
| POST / PUT | `/api/nodes` / `/api/nodes/{id}` | `{name,endpoint,region?,note?,enabled?}`；启用节点创建时返回 install_command、install_ticket、install_expires_at、installer_sha256；兼容旧版另返回 secret |
| POST | `/api/nodes/{id}/install` | 签发 15 分钟单次安装凭据；替换未使用凭据 |
| POST | `/internal/node/enroll` | `{ticket,node_id,endpoint,public_key}`，一次性兑换并绑定节点公钥 |
| GET | `/install/node.py` | 安装脚本；命令固定其 SHA-256 |
| POST | `/api/nodes/{id}/rotate` | 轮换接入密钥，旧密钥失效 |
| DELETE | `/api/users/{id}`、`/api/zones/{id}`、`/api/records/{id}`、`/api/nodes/{id}` | 删除；用户及分区有数据库级联关系 |
| PUT | `/api/settings` | `{token_qps,retention_days}` |
| POST | `/internal/node/sync` | Ed25519 签名认证（旧版未迁移节点兼容 Bearer），传节点元数据及可选统计报告，返回配置及租约 |
| GET | `/healthz` | 进程存活 |
| GET | `/readyz` | 配置可用 200，否则 503 |

时间字段是 Unix 秒或 null。写入成功返回 `{ok,revision,propagation_seconds}`，创建接口另带 `id`。MariaDB 事务同时写入数据、审计和配置版本；变更后重新加载主控快照。

## DoH

`GET /dns-query/{token}?dns=<无填充base64url DNS消息>`

`POST /dns-query/{token}`，请求类型 `application/dns-message`，请求体为 DNS wire message。

请求需有且仅有一个问题。成功处理的协议响应为 HTTP 200 + DNS 二进制；NXDOMAIN、NODATA、REFUSED 是 DNS 层结果。A / AAAA 返回已授权地址；SOA 用于分区与否定应答。查询不支持 AXFR、IXFR、ANY。未知分区、无权限分区返回 REFUSED，不向公共解析器转发。

HTTP 400：编码或消息错误；403：令牌无效、过期、撤销或用户失效；413：请求体过大；415：POST 媒体类型错误；429：限速；503：没有有效配置租约。

后台及 DoH 响应都使用 `no-store`。用户令牌不会通过列表接口再次返回；遗失时撤销并重新签发。

## 节点同步

节点每 3 秒 POST `{node_id,applied_revision,version,report}`。报告格式见 `src/model.rs`；每个批次有 UUID、最多 120 个分钟桶。主控事务去重，验证非负计数及总数一致性。

响应包含 `snapshot` 和 `lease_seconds`。节点用单调时钟计算租约截止点，网络传输耗时计入租约；主控无可用快照时不发放新租约。403 清空本地授权配置；网络错误保留配置至租约到期；无效统计报告不会永久阻塞后续配置恢复。

统一 DoH 域名直接反代本机 `/dns-query/`，不使用主控网关转发。旧版 gateway 接口保留兼容，但不在统一域名中使用。`nodes[].auth_mode` 为 `ed25519` 或 `legacy`。

## DNS 基础设施与自动部署（v0.3）

首次尚无 active 域名时，业务写入接口返回 HTTP 428，必须先完成供应商与域名配置。

| 方法 | 路径 | 内容 |
| --- | --- | --- |
| GET | `/api/infrastructure` | required、providers（无凭据）、domains、jobs |
| GET | `/api/infrastructure/ip` | 主控公网 IP 建议值 |
| POST / PUT | `/api/providers` / `/api/providers/{id}` | `{kind,name,credentials}`；kind: cloudflare / alidns / dnspod；创建先校验可访问域名列表 |
| GET | `/api/providers/{id}/zones` | 读取该凭据权限内的所有可用主域名 |
| POST | `/api/domains` | `{provider_id,zone_id,label,controller_ip}`；label 默认 doh，@ 为根域 |
| POST | `/api/domains/{id}/repair` | 重试失败配置 / 证书申请并立即重新检查 |
| POST | `/api/ssh/probe` | `{host,port:22}`，不发送登录凭据，返回 fingerprint、previous_fingerprint、trusted、changed |
| POST | `/api/managed-nodes` | `{name,ip_address,region?,note?,enabled?,ssh?}`；无 ssh 返回一次性安装命令 |
| PUT | `/api/managed-nodes/{id}` | 同上，必须保留 ip_address；更换 IP 使用删除 / 新增 |
| DELETE | `/api/managed-nodes/{id}` | 立即撤销身份，异步删除托管记录后清理节点 |
| POST | `/api/managed-nodes/{id}/deploy` | ssh 对象，返回后台 job_id |
| POST | `/api/managed-nodes/{id}/adopt` | `{ip_address}`，将旧版节点转换为统一域名节点 |
| POST | `/internal/node/control` | Ed25519 签名的根权限维护通道，返回统一域名证书绑定 |

credentials：Cloudflare `{token}` 或 `{email,key_secret}`（Global API Key）；AliDNS / DNSPod `{key_id,key_secret}`。
ssh：`{port,username,password?,private_key?,key_passphrase?,fingerprint,trust_host_key}`。密码 / 密钥只留在本次部署任务内存；主控重启后未完成任务标记失败，需要重新提交。

供应商和 SSH 错误不回传原始敏感响应；任务仅显示固定安装阶段。节点控制请求签名上下文与配置同步不同，不能跨接口重放。主控不接受任意供应商 URL，避免向不可信地址发送 API 密钥。
