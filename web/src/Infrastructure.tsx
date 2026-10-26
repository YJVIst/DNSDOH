import { useState, useEffect, type FormEvent, type ReactNode } from "react";
import {
  Globe2,
  ShieldCheck,
  Server,
  ArrowRight,
  RefreshCw,
  Plus,
  KeyRound,
  Terminal,
  Download,
  AlertCircle,
  X,
  CheckCircle2,
  LoaderCircle,
  Trash2,
  Pencil,
} from "lucide-react";
export type Infra = {
  required: boolean;
  providers: { id: string; kind: string; name: string }[];
  domains: {
    id: string;
    provider_id: string;
    zone_name: string;
    hostname: string;
    controller_ip: string;
    routing: string;
    state: string;
    last_error: string;
    cert_expires: number | null;
    revision: number;
  }[];
  jobs: {
    id: string;
    kind: string;
    target: string;
    state: string;
    stage: string;
    updated_at: number;
  }[];
  routing: string;
};
type Zone = { id: string; name: string; status: string };
type Node = {
  id: string;
  name: string;
  ip_address?: string | null;
  endpoint: string;
  region: string;
  note: string;
  enabled: boolean;
  online: boolean;
  auth_mode: string;
  deploy_state: string;
  domain_revision: number;
  deleted_at?: number | null;
};
type Call = (path: string, method?: string, body?: unknown) => Promise<any>;
function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
function ErrorBox({ text }: { text: string }) {
  return text ? (
    <div className="infra-error" role="alert">
      <AlertCircle size={18} />
      {text}
    </div>
  ) : null;
}
export function Infrastructure({
  value,
  call,
  refresh,
  mandatory = false,
}: {
  value: Infra;
  call: Call;
  refresh: () => Promise<void>;
  mandatory?: boolean;
}) {
  const [cloudflareAuth, setCloudflareAuth] = useState("token");
  const [provider, setProvider] = useState(value.providers[0]?.id || ""),
    [kind, setKind] = useState("cloudflare"),
    [zones, setZones] = useState<Zone[]>([]),
    [zone, setZone] = useState(""),
    [address, setAddress] = useState(
      value.domains.find((d) => d.state === "active")?.controller_ip || "",
    ),
    [adding, setAdding] = useState(value.providers.length === 0),
    [editing, setEditing] = useState(""),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [showDomain, setShowDomain] = useState(mandatory),
    [message, setMessage] = useState("");
  const active = value.domains.find((d) => d.state === "active");
  useEffect(() => {
    if (!address)
      call("/infrastructure/ip")
        .then((v) => setAddress(v.ip))
        .catch(() => {});
  }, []);
  useEffect(() => {
    if (!provider) return;
    let valid = true;
    call(`/providers/${provider}/zones`)
      .then((v) => {
        if (valid) {
          setZones(v.zones);
          setZone(v.zones.find((z: Zone) => z.status === "active")?.id || "");
        }
      })
      .catch((e) => {
        if (valid) setError(e.message);
      });
    return () => {
      valid = false;
    };
  }, [provider]);
  const submitProvider = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const form = e.currentTarget,
      f = new FormData(form);
    try {
      const result = await call(
        editing ? `/providers/${editing}` : "/providers",
        editing ? "PUT" : "POST",
        {
          kind,
          name: String(f.get("name")),
          credentials: {
            email: String(f.get("email") || ""),
            token: String(f.get("token") || ""),
            key_id: String(f.get("key_id") || ""),
            key_secret: String(f.get("key_secret") || ""),
          },
        },
      );
      form.reset();
      setProvider(result.id);
      setZones(result.zones);
      setZone(result.zones.find((z: Zone) => z.status === "active")?.id || "");
      setAdding(false);
      setEditing("");
      setShowDomain(true);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const submitDomain = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const f = new FormData(e.currentTarget);
    try {
      await call("/domains", "POST", {
        provider_id: provider,
        zone_id: zone,
        label: String(f.get("label")),
        controller_ip: address,
      });
      setMessage(
        "正在验证 DNS、申请证书和配置统一入口。完成后会自动进入控制台。",
      );
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const repair = async (id: string) => {
    setBusy(true);
    try {
      await call(`/domains/${id}/repair`, "POST");
      await refresh();
      setMessage("已提交修复任务，系统将重新检查权限、证书和记录。");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <section className={"infra-panel " + (mandatory ? "setup-panel" : "")}>
      <div className="infra-heading">
        <span className="infra-symbol">
          <Globe2 size={25} />
        </span>
        <div>
          <span className="eyebrow">DNSDOH / DIRECT DNS</span>
          <h2>
            {mandatory ? "先配置你的统一 DoH 域名" : "DNS 供应商与统一域名"}
          </h2>
          <p>公共 DNS 返回服务器地址，用户通过 HTTPS 直接连接解析节点。</p>
        </div>
      </div>
      {mandatory && (
        <div className="setup-steps">
          <span className={value.providers.length ? "complete" : "current"}>
            1 验证供应商
          </span>
          <ArrowRight size={16} />
          <span
            className={
              value.domains.length
                ? "complete"
                : value.providers.length
                  ? "current"
                  : ""
            }
          >
            2 选择主域名
          </span>
          <ArrowRight size={16} />
          <span
            className={
              value.domains.some((d) => d.state === "preparing")
                ? "current"
                : ""
            }
          >
            3 证书与解析
          </span>
        </div>
      )}
      <ErrorBox text={error} />
      {message && (
        <div className="info-strip">
          <LoaderCircle size={17} />
          <span>{message}</span>
        </div>
      )}
      {active && (
        <div className="domain-summary">
          <div>
            <small>当前统一 DoH 地址</small>
            <strong>https://{active.hostname}</strong>
            <span>公共 DNS 多地址直连 · HTTPS 加密 · 用户独立令牌</span>
          </div>
          <button
            className="button secondary"
            onClick={() => setShowDomain(!showDomain)}
          >
            <RefreshCw size={15} />
            更换域名
          </button>
        </div>
      )}
      {value.domains
        .filter(
          (d) =>
            d.last_error || d.state === "preparing" || d.state === "failed",
        )
        .map((d) => (
          <div className="infra-error domain-warning" key={d.id}>
            <AlertCircle size={18} />
            <div>
              <strong>{d.hostname}</strong>
              <p>{d.last_error || "正在申请证书和配置解析"}</p>
            </div>
            <button
              className="button secondary small"
              disabled={busy}
              onClick={() => repair(d.id)}
            >
              检查 / 修复
            </button>
          </div>
        ))}
      <div className="infra-grid">
        <div>
          <h3>DNS 供应商</h3>
          {value.providers.length > 0 && (
            <>
              <Field label="已保存的账户">
                <select
                  value={provider}
                  onChange={(e) => setProvider(e.target.value)}
                >
                  {value.providers.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} · {p.kind}
                    </option>
                  ))}
                </select>
              </Field>
              <div className="row-actions">
                <button
                  className="button secondary small"
                  onClick={() => {
                    setAdding(!adding);
                    setEditing("");
                  }}
                >
                  <Plus size={14} />
                  添加供应商
                </button>
                <button
                  className="button secondary small"
                  onClick={() => {
                    setEditing(provider);
                    setKind(
                      value.providers.find((p) => p.id === provider)?.kind ||
                        "cloudflare",
                    );
                    setAdding(true);
                  }}
                >
                  更新 API 凭据
                </button>
              </div>
            </>
          )}
          {adding && (
            <form onSubmit={submitProvider} className="provider-form">
              <Field label="供应商">
                <select
                  value={kind}
                  onChange={(e) => setKind(e.target.value)}
                  disabled={!!editing}
                >
                  <option value="cloudflare">Cloudflare</option>
                  <option value="alidns">阿里云 DNS</option>
                  <option value="dnspod">腾讯云 DNSPod</option>
                </select>
              </Field>
              <Field label="账户名称">
                <input
                  name="name"
                  required
                  maxLength={100}
                  placeholder="例如：我的域名账户"
                  defaultValue={
                    editing
                      ? value.providers.find((p) => p.id === editing)?.name
                      : ""
                  }
                />
              </Field>
              {kind === "cloudflare" ? (
                <>
                  <Field label="Cloudflare 凭据类型">
                    <select
                      value={cloudflareAuth}
                      onChange={(e) => setCloudflareAuth(e.target.value)}
                    >
                      <option value="token">API Token</option>
                      <option value="global">Global API Key</option>
                    </select>
                  </Field>
                  {cloudflareAuth === "token" ? (
                    <Field
                      label="API Token"
                      hint="需要 Zone Read 与 DNS Edit，可授权一个或多个域名。"
                    >
                      <input
                        name="token"
                        type="password"
                        required
                        autoComplete="new-password"
                      />
                    </Field>
                  ) : (
                    <>
                      <Field label="Cloudflare 账户邮箱">
                        <input
                          name="email"
                          type="email"
                          required
                          autoComplete="off"
                        />
                      </Field>
                      <Field label="Global API Key">
                        <input
                          name="key_secret"
                          type="password"
                          required
                          autoComplete="new-password"
                        />
                      </Field>
                    </>
                  )}
                </>
              ) : (
                <>
                  <Field
                    label={kind === "alidns" ? "AccessKey ID" : "Secret ID"}
                  >
                    <input name="key_id" required autoComplete="off" />
                  </Field>
                  <Field
                    label={
                      kind === "alidns" ? "AccessKey Secret" : "Secret Key"
                    }
                  >
                    <input
                      name="key_secret"
                      type="password"
                      required
                      autoComplete="new-password"
                    />
                  </Field>
                </>
              )}
              <p className="modal-help">
                支持账户下多个域名；验证后列出所有可访问域名供你选择。凭据加密保存，仅用于管理托管记录与证书验证。
              </p>
              <button className="button primary" disabled={busy}>
                {busy ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <ShieldCheck size={16} />
                )}
                验证并保存凭据
              </button>
            </form>
          )}
        </div>
        <div>
          {(mandatory || showDomain) && (
            <form onSubmit={submitDomain}>
              <h3>{active ? "准备新的统一入口" : "选择主域名"}</h3>
              <Field label="主域名" hint="这里只显示所选凭据可以访问的域名。">
                <select
                  value={zone}
                  onChange={(e) => setZone(e.target.value)}
                  required
                  disabled={!provider || !zones.length}
                >
                  <option value="">请选择</option>
                  {zones.map((z) => (
                    <option
                      key={z.id}
                      value={z.id}
                      disabled={z.status !== "active"}
                    >
                      {z.name}
                      {z.status !== "active" ? `（${z.status}）` : ""}
                    </option>
                  ))}
                </select>
              </Field>
              <Field
                label="DoH 主机名"
                hint="例如 doh；填写 @ 使用主域名本身。已有其他业务记录时不会覆盖。"
              >
                <input
                  name="label"
                  defaultValue="doh"
                  required
                  maxLength={63}
                />
              </Field>
              <Field
                label="主控服务器公网 IP"
                hint="自动检测结果可修改；必须能通过 443 端口到达本机。"
              >
                <input
                  value={address}
                  onChange={(e) => setAddress(e.target.value)}
                  required
                />
              </Field>
              <div className="info-strip">
                <Globe2 size={17} />
                <span>
                  普通 DNS
                  多记录用于分散连接，无法保证为每位用户选择最低延迟节点。当前无需开通付费负载均衡。
                </span>
              </div>
              {active && (
                <p className="modal-help">
                  新证书和入口就绪后切换，旧域名保留 7 天供迁移。已分发的客户端
                  DoH 地址需要改为新域名，用户令牌保持不变。
                </p>
              )}
              <button
                className="button primary"
                disabled={
                  busy ||
                  !zone ||
                  value.domains.some((d) => d.state === "preparing")
                }
              >
                {busy ? (
                  <LoaderCircle size={16} className="spin" />
                ) : (
                  <ArrowRight size={16} />
                )}
                配置证书并启用域名
              </button>
            </form>
          )}
          {!mandatory && !showDomain && (
            <div className="infra-explanation">
              <ShieldCheck size={28} />
              <h3>直连解析，统一身份</h3>
              <p>
                每个节点使用统一域名的有效证书。新增节点完成安全接入和 HTTPS
                检查后，系统通过供应商 API 添加 A / AAAA
                记录；删除节点时自动清理对应记录。
              </p>
              <p>
                主域名或 API 异常会在这里提醒，可修复凭据或更换域名。DNS
                缓存仍会影响切换生效时间。
              </p>
            </div>
          )}
        </div>
      </div>
      <JobList
        jobs={value.jobs.filter((j) => j.kind === "domain").slice(0, 3)}
      />
    </section>
  );
}
function JobList({ jobs }: { jobs: Infra["jobs"] }) {
  return (
    <div className="infra-jobs">
      {jobs.map((j) => (
        <div className={"infra-job " + j.state} key={j.id}>
          {j.state === "done" ? (
            <CheckCircle2 size={18} />
          ) : j.state === "failed" ? (
            <AlertCircle size={18} />
          ) : (
            <LoaderCircle size={18} className="spin" />
          )}
          <div>
            <strong>{j.kind === "ssh" ? "服务器自动部署" : "域名配置"}</strong>
            <p>{j.stage}</p>
          </div>
          <span>{new Date(j.updated_at * 1000).toLocaleTimeString()}</span>
        </div>
      ))}
    </div>
  );
}
function saveText(name: string, text: string) {
  const u = URL.createObjectURL(
    new Blob([text], { type: "text/plain;charset=utf-8" }),
  );
  const a = document.createElement("a");
  a.href = u;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(u), 1000);
}
export function ManagedNodes({
  nodes,
  infra,
  call,
  refresh,
  formOpen,
  onClose,
}: {
  nodes: Node[];
  infra: Infra;
  call: Call;
  refresh: () => Promise<void>;
  formOpen: boolean;
  onClose: () => void;
}) {
  const [selected, setSelected] = useState<Node | null>(null),
    [mode, setMode] = useState("ssh"),
    [auth, setAuth] = useState("password"),
    [host, setHost] = useState(""),
    [port, setPort] = useState(22),
    [fingerprint, setFingerprint] = useState<any>(null),
    [trusted, setTrusted] = useState(false),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [install, setInstall] = useState<any>(null),
    [remove, setRemove] = useState<Node | null>(null);
  const active = infra.domains.find((d) => d.state === "active");
  const close = () => {
    setSelected(null);
    setHost("");
    setFingerprint(null);
    setTrusted(false);
    setError("");
    onClose();
  };
  const openNode = (n: Node) => {
    setSelected(n);
    setHost(n.ip_address || "");
    setMode("ssh");
    setFingerprint(null);
    setTrusted(false);
    setError("");
  };
  const probe = async () => {
    setBusy(true);
    setError("");
    try {
      const result = await call("/ssh/probe", "POST", { host, port });
      setFingerprint(result);
      setTrusted(result.trusted);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setBusy(true);
    setError("");
    const form = e.currentTarget,
      f = new FormData(form);
    try {
      const ssh =
        mode === "ssh"
          ? {
              port,
              username: String(f.get("username")),
              password:
                auth === "password" ? String(f.get("password") || "") : "",
              private_key:
                auth === "key" ? String(f.get("private_key") || "") : "",
              key_passphrase:
                auth === "key" ? String(f.get("key_passphrase") || "") : "",
              fingerprint: fingerprint?.fingerprint || "",
              trust_host_key: trusted,
            }
          : undefined;
      let result;
      if (selected) {
        if (!selected.ip_address)
          await call(`/managed-nodes/${selected.id}/adopt`, "POST", {
            ip_address: host,
          });
        if (mode === "ssh")
          result = await call(
            `/managed-nodes/${selected.id}/deploy`,
            "POST",
            ssh,
          );
        else result = await call(`/nodes/${selected.id}/install`, "POST");
      } else
        result = await call("/managed-nodes", "POST", {
          name: String(f.get("name")),
          ip_address: host,
          region: String(f.get("region") || ""),
          note: String(f.get("note") || ""),
          enabled: true,
          ssh,
        });
      form.reset();
      close();
      if (result.install_command) setInstall(result);
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  const toggle = async (n: Node) => {
    try {
      await call(`/managed-nodes/${n.id}`, "PUT", {
        name: n.name,
        ip_address: n.ip_address,
        region: n.region,
        note: n.note,
        enabled: !n.enabled,
      });
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    }
  };
  const names: Record<string, string> = {
    legacy: "旧版节点",
    pending: "等待安装",
    installing: "正在安装",
    awaiting_dns: "等待 DNS",
    ready: "已接入",
    failed: "安装失败",
    deleting: "等待清理 DNS",
  };
  return (
    <>
      <div className="info-strip">
        <Globe2 size={18} />
        <span>
          统一地址 <b>https://{active?.hostname}</b> · 公共 DNS 直接返回节点 IP
          · 无主控转发
        </span>
      </div>
      <ErrorBox text={error} />
      <div className="node-grid">
        <article className="node-card online">
          <div className="node-card-top">
            <span className="node-symbol local">
              <Globe2 size={23} />
            </span>
            <span className="badge good">本机</span>
          </div>
          <h3>主控内置 DoH 节点</h3>
          <p className="node-region">{active?.controller_ip}</p>
          <div className="node-endpoint">https://{active?.hostname}</div>
          <p className="node-note">
            与其他节点并列加入公共 DNS，接收直接到达本机的查询。
          </p>
        </article>
        {nodes.map((n) => (
          <article
            className={"node-card " + (n.online && n.enabled ? "online" : "")}
            key={n.id}
          >
            <div className="node-card-top">
              <span className="node-symbol">
                <Server size={23} />
              </span>
              <span
                className={
                  "badge " +
                  (n.deploy_state === "ready" && n.online && n.enabled
                    ? "good"
                    : "warn")
                }
              >
                {n.enabled
                  ? names[n.deploy_state] || n.deploy_state
                  : n.deleted_at
                    ? "删除中"
                    : "已停用"}
              </span>
            </div>
            <h3>{n.name}</h3>
            <p className="node-region">
              {n.ip_address || "旧版独立入口"} · {n.region || "未设置地区"}
            </p>
            <div className="node-endpoint">https://{active?.hostname}</div>
            <p className="node-note">
              {n.auth_mode === "ed25519" ? "Ed25519 签名认证" : "等待身份绑定"}{" "}
              · {n.online ? "同步在线" : "等待同步"}
            </p>
            {n.ip_address && !n.deleted_at && (
              <div className="node-management-actions">
                <button
                  className="button secondary small"
                  onClick={() => openNode(n)}
                >
                  <Terminal size={15} />
                  部署 / 重装
                </button>
                <button
                  className="button secondary small"
                  onClick={() => toggle(n)}
                >
                  {n.enabled ? "停用" : "启用"}
                </button>
                <button
                  className="button small danger-ghost"
                  onClick={() => setRemove(n)}
                >
                  <Trash2 size={14} />
                  删除
                </button>
              </div>
            )}
            {!n.ip_address && (
              <>
                <p className="modal-help">旧版独立域名节点不参与公共 DNS。</p>
                <button
                  className="button secondary small"
                  onClick={() => openNode(n)}
                >
                  迁移为统一入口
                </button>
              </>
            )}
          </article>
        ))}
      </div>
      <JobList jobs={infra.jobs.filter((j) => j.kind === "ssh").slice(0, 5)} />
      {(formOpen || selected) && (
        <div className="modal-overlay">
          <section
            className="modal wide"
            role="dialog"
            aria-modal="true"
            aria-labelledby="managed-node-title"
          >
            <div className="modal-heading">
              <div>
                <span className="eyebrow">DNSDOH / NODE DEPLOYMENT</span>
                <h2 id="managed-node-title">
                  {selected ? "部署 / 重新安装服务器" : "添加 DNS 服务器"}
                </h2>
              </div>
              <button
                className="icon-button"
                aria-label="关闭窗口"
                onClick={close}
              >
                <X size={20} />
              </button>
            </div>
            <form className="modal-body" onSubmit={submit}>
              <ErrorBox text={error} />
              {!selected && (
                <Field label="服务器名称">
                  <input
                    name="name"
                    required
                    maxLength={100}
                    placeholder="例如：香港 DNS 01"
                  />
                </Field>
              )}
              <Field
                label="服务器公网 IP"
                hint="系统自动为统一域名添加对应记录，无需填写独立 HTTPS 地址。"
              >
                <input
                  name="ip_address"
                  value={host}
                  disabled={!!selected?.ip_address}
                  onChange={(e) => {
                    setHost(e.target.value);
                    setFingerprint(null);
                    setTrusted(false);
                  }}
                  required
                />
              </Field>
              {!selected && (
                <Field label="地区 / 备注">
                  <input name="region" maxLength={80} placeholder="可选" />
                </Field>
              )}
              <Field label="接入方式">
                <select value={mode} onChange={(e) => setMode(e.target.value)}>
                  <option value="ssh">SSH 自动安装（推荐）</option>
                  <option value="script">一次性安装命令</option>
                </select>
              </Field>
              {mode === "ssh" ? (
                <>
                  <div className="infra-grid">
                    <Field label="SSH 端口">
                      <input
                        name="port"
                        type="number"
                        min={1}
                        max={65535}
                        value={port}
                        onChange={(e) => {
                          setPort(Number(e.target.value));
                          setFingerprint(null);
                          setTrusted(false);
                        }}
                        required
                      />
                    </Field>
                    <Field
                      label="SSH 用户名"
                      hint="root 或具备免密 sudo 的用户"
                    >
                      <input
                        name="username"
                        defaultValue="root"
                        required
                        autoComplete="off"
                      />
                    </Field>
                  </div>
                  <button
                    type="button"
                    className="button secondary"
                    disabled={busy || !host}
                    onClick={probe}
                  >
                    <ShieldCheck size={16} />
                    检测 SSH 指纹
                  </button>
                  {fingerprint && (
                    <div
                      className={
                        "ssh-fingerprint " +
                        (fingerprint.changed ? "changed" : "")
                      }
                    >
                      <strong>
                        {fingerprint.changed
                          ? "服务器指纹已改变：请先核对重装情况"
                          : fingerprint.trusted
                            ? "已匹配保存的服务器指纹"
                            : "首次连接：请核对服务器指纹"}
                      </strong>
                      {fingerprint.previous_fingerprint && (
                        <p>
                          原指纹 <code>{fingerprint.previous_fingerprint}</code>
                        </p>
                      )}
                      <p>
                        当前指纹 <code>{fingerprint.fingerprint}</code>
                      </p>
                      {!fingerprint.trusted && (
                        <label className="checkbox-row">
                          <input
                            type="checkbox"
                            checked={trusted}
                            onChange={(e) => setTrusted(e.target.checked)}
                          />
                          <span>
                            已通过服务器控制台核实，信任此指纹
                            {fingerprint.changed ? "并替换旧记录" : ""}
                          </span>
                        </label>
                      )}
                    </div>
                  )}
                  <Field label="SSH 认证方式">
                    <select
                      value={auth}
                      onChange={(e) => setAuth(e.target.value)}
                    >
                      <option value="password">密码</option>
                      <option value="key">私钥</option>
                    </select>
                  </Field>
                  {auth === "password" ? (
                    <Field label="SSH 密码">
                      <input
                        name="password"
                        type="password"
                        required
                        autoComplete="new-password"
                      />
                    </Field>
                  ) : (
                    <>
                      <Field label="SSH 私钥">
                        <textarea
                          name="private_key"
                          rows={5}
                          required
                          placeholder="粘贴 OpenSSH / PEM 私钥"
                          autoComplete="off"
                        />
                      </Field>
                      <Field label="私钥口令">
                        <input
                          name="key_passphrase"
                          type="password"
                          autoComplete="new-password"
                          placeholder="未加密私钥可留空"
                        />
                      </Field>
                    </>
                  )}
                  <p className="modal-help">
                    SSH 凭据仅用于本次部署，不保存到数据库。支持 Debian /
                    Ubuntu、RHEL 系、SUSE、Alpine 和 Arch 的 x86_64
                    系统。系统重装后需要重新确认发生变化的 SSH 指纹。
                  </p>
                </>
              ) : (
                <div className="info-strip">
                  <Terminal size={18} />
                  <span>
                    保存后生成 15
                    分钟内单次有效的安装命令，可下载为文本，在服务器 root
                    终端自行执行。
                  </span>
                </div>
              )}
              <div className="modal-actions">
                <button
                  type="button"
                  className="button secondary"
                  onClick={close}
                >
                  取消
                </button>
                <button
                  className="button primary"
                  disabled={
                    busy || (mode === "ssh" && (!fingerprint || !trusted))
                  }
                >
                  {busy ? (
                    <LoaderCircle size={16} className="spin" />
                  ) : (
                    <ArrowRight size={16} />
                  )}{" "}
                  {mode === "ssh" ? "开始自动部署" : "生成安装命令"}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
      {install && (
        <div className="modal-overlay">
          <section
            className="modal wide"
            role="dialog"
            aria-modal="true"
            aria-label="一次性安装命令"
          >
            <div className="modal-heading">
              <h2>一次性安装命令</h2>
              <button
                className="icon-button"
                aria-label="关闭窗口"
                onClick={() => setInstall(null)}
              >
                <X size={20} />
              </button>
            </div>
            <div className="modal-body">
              <p>
                在对应服务器 root 终端执行。有效期至{" "}
                {new Date(install.install_expires_at * 1000).toLocaleString()}
                ，使用后失效。
              </p>
              <pre className="code-block">{install.install_command}</pre>
              <button
                className="button primary"
                onClick={() =>
                  saveText(
                    "DNSDOH-节点安装命令.txt",
                    install.install_command + "\n",
                  )
                }
              >
                <Download size={16} />
                下载安装命令
              </button>
              <button
                className="button secondary"
                onClick={() =>
                  navigator.clipboard.writeText(install.install_command)
                }
              >
                复制命令
              </button>
            </div>
          </section>
        </div>
      )}
      {remove && (
        <div className="modal-overlay">
          <section
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="删除服务器"
          >
            <div className="modal-heading">
              <h2>删除 {remove.name}</h2>
            </div>
            <div className="modal-body">
              <p>
                撤销节点身份并自动删除该节点的公共 DNS 记录。若供应商 API
                暂不可用，任务会保留并重试；DNS 缓存可能暂时仍返回旧地址。
              </p>
              <div className="modal-actions">
                <button
                  className="button secondary"
                  onClick={() => setRemove(null)}
                >
                  取消
                </button>
                <button
                  className="button danger-solid"
                  onClick={async () => {
                    try {
                      await call(`/managed-nodes/${remove.id}`, "DELETE");
                      setRemove(null);
                      await refresh();
                    } catch (e) {
                      setError((e as Error).message);
                    }
                  }}
                >
                  确认删除并清理 DNS
                </button>
              </div>
            </div>
          </section>
        </div>
      )}
    </>
  );
}
