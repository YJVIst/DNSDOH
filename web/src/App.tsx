import { Infrastructure, ManagedNodes, type Infra } from "./Infrastructure";
import {
  useState,
  useEffect,
  useCallback,
  useRef,
  type FormEvent,
  type ReactNode,
} from "react";
import {
  Activity,
  ArrowDownToLine,
  ArrowRight,
  ArrowUpRight,
  Check,
  CheckCircle2,
  ChevronRight,
  CircleHelp,
  Clock3,
  Copy,
  Database,
  FileClock,
  Globe2,
  KeyRound,
  LayoutDashboard,
  LoaderCircle,
  LockKeyhole,
  LogOut,
  Menu,
  Network,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Server,
  Settings2,
  ShieldCheck,
  ShieldX,
  Trash2,
  Users,
  X,
  Zap,
  AlertCircle,
  Eye,
  EyeOff,
} from "lucide-react";

type User = {
  id: string;
  name: string;
  note: string;
  enabled: boolean;
  expires_at: number | null;
  created_at: number;
  zone_ids: string[];
};
type Zone = { id: string; name: string; note: string; enabled: boolean };
type DnsRecord = {
  id: string;
  zone_id: string;
  zone_name: string;
  name: string;
  record_type: string;
  value: string;
  ttl: number;
  enabled: boolean;
};
type Token = {
  id: string;
  name: string;
  user_id: string;
  user_name: string;
  prefix: string;
  enabled: boolean;
  expires_at: number | null;
  created_at: number;
};
type Node = {
  id: string;
  name: string;
  endpoint: string;
  region: string;
  note: string;
  enabled: boolean;
  online: boolean;
  last_seen: number | null;
  applied_revision: number;
  version: string;
  auth_mode: string;
  ip_address?: string | null;
  deploy_state: string;
  domain_revision: number;
  deleted_at?: number | null;
};
type Metric = {
  bucket: number;
  total: number;
  success: number;
  denied: number;
  errors: number;
  latency_us: number;
};
type Audit = {
  actor: string;
  action: string;
  target: string;
  created_at: number;
};
type Data = {
  infrastructure: Infra;
  gateway: {
    url: string;
    strategy: string;
    selected_node: string | null;
    probes: {
      id: string;
      healthy: boolean;
      latency_ms: number;
      revision: number;
      checked_at: number;
    }[];
  };
  users: User[];
  zones: Zone[];
  records: DnsRecord[];
  tokens: Token[];
  nodes: Node[];
  audit: Audit[];
  metrics: Metric[];
  node_metrics: { node_id: string; total: number; success: number }[];
  settings: {
    revision: number;
    token_qps: number;
    retention_days: number;
    lease_seconds: number;
    sync_seconds: number;
  };
  system: {
    version: string;
    database: string;
    uptime_seconds: number;
    ready: boolean;
    public_url: string;
    doh_url: string;
    now: number;
  };
};
type Session = { username: string; csrf: string; version?: string };
type Page =
  "overview" | "zones" | "users" | "tokens" | "nodes" | "audit" | "settings";
type Entity = Partial<User & Zone & DnsRecord & Token & Node>;
type Modal = {
  kind:
    | "user"
    | "zone"
    | "record"
    | "token"
    | "node"
    | "secret"
    | "delete"
    | "revoke"
    | "rotate"
    | "password"
    | "guide";
  item?: Entity;
  resource?: string;
  secret?: string;
  secretType?: "token" | "node";
  controller?: string;
  installCommand?: string;
  installExpires?: number;
  title?: string;
};
const pages: {
  id: Page;
  label: string;
  icon: typeof Activity;
  desc: string;
}[] = [
  {
    id: "overview",
    label: "概览",
    icon: LayoutDashboard,
    desc: "你的私有解析网络，一目了然。",
  },
  {
    id: "zones",
    label: "域名与记录",
    icon: Globe2,
    desc: "在私有分区中维护节点的真实地址。",
  },
  {
    id: "users",
    label: "用户管理",
    icon: Users,
    desc: "按用户分配域名权限，随时调整访问范围。",
  },
  {
    id: "tokens",
    label: "访问令牌",
    icon: KeyRound,
    desc: "为每位用户签发独立的 DoH 访问凭据。",
  },
  {
    id: "nodes",
    label: "DNS 服务器",
    icon: Server,
    desc: "从一个控制台管理所有解析节点。",
  },
  {
    id: "audit",
    label: "操作记录",
    icon: FileClock,
    desc: "记录管理变更，让每一次操作都有据可查。",
  },
  {
    id: "settings",
    label: "系统设置",
    icon: Settings2,
    desc: "管理查询限速、数据保留与账户安全。",
  },
];
const number = (n: number) => new Intl.NumberFormat("zh-CN").format(n);
const date = (n: number | null) =>
  n
    ? new Date(n * 1000).toLocaleString("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
        hour12: false,
      })
    : "—";
const until = (n: number | null | undefined) =>
  !n ? "长期有效" : new Date(n * 1000).toLocaleDateString("zh-CN");
const dateInput = (n: number | null | undefined) =>
  n
    ? new Date(n * 1000 - new Date().getTimezoneOffset() * 60000)
        .toISOString()
        .slice(0, 16)
    : "";
const expired = (n: number | null | undefined) =>
  Boolean(n && n <= Date.now() / 1000);
async function api(path: string, csrf = "", method = "GET", body?: unknown) {
  const response = await fetch(`/api${path}`, {
    method,
    credentials: "same-origin",
    headers: {
      ...(body !== undefined ? { "Content-Type": "application/json" } : {}),
      ...(csrf ? { "X-CSRF-Token": csrf } : {}),
    },
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  const payload = await response
    .json()
    .catch(() => ({ error: "服务器暂时不可用" }));
  if (!response.ok) {
    const error = new Error(payload.error || "请求失败") as Error & {
      status: number;
    };
    error.status = response.status;
    throw error;
  }
  return payload;
}
function Logo({ large = false }: { large?: boolean }) {
  return (
    <div className={`brand ${large ? "large" : ""}`}>
      <span className="brand-mark">
        <Network size={24} />
      </span>
      <span>
        DNS<span className="brand-accent">DOH</span>
        <small>PRIVATE DNS NETWORK</small>
      </span>
    </div>
  );
}
function Badge({
  children,
  tone = "neutral",
}: {
  children: ReactNode;
  tone?: "good" | "bad" | "warn" | "neutral" | "blue";
}) {
  return (
    <span className={`badge ${tone}`}>
      <i />
      {children}
    </span>
  );
}
function Empty({
  icon: Icon = Globe2,
  title,
  description,
  action,
}: {
  icon?: typeof Activity;
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="empty-icon">
        <Icon size={26} />
      </div>
      <h3>{title}</h3>
      <p>{description}</p>
      {action}
    </div>
  );
}
function IconButton({
  title,
  onClick,
  children,
  danger = false,
}: {
  title: string;
  onClick: () => void;
  children: ReactNode;
  danger?: boolean;
}) {
  return (
    <button
      className={`icon-button ${danger ? "danger" : ""}`}
      title={title}
      aria-label={title}
      onClick={onClick}
    >
      {children}
    </button>
  );
}
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
function download(name: string, value: string) {
  const url = URL.createObjectURL(
    new Blob([value], { type: "application/json" }),
  );
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [session, setSession] = useState<Session | null>(null),
    [loading, setLoading] = useState(true),
    [data, setData] = useState<Data | null>(null);
  const [page, setPage] = useState<Page>("overview"),
    [search, setSearch] = useState(""),
    [zoneFilter, setZoneFilter] = useState("all"),
    [menu, setMenu] = useState(false);
  const [modal, setModal] = useState<Modal | null>(null),
    [error, setError] = useState(""),
    [toast, setToast] = useState(""),
    [refreshing, setRefreshing] = useState(false),
    [updated, setUpdated] = useState<Date | null>(null);
  const [nodeFormOpen, setNodeFormOpen] = useState(false);
  const [busy, setBusy] = useState(false),
    [formError, setFormError] = useState("");
  const fetchState = useCallback(async () => {
    try {
      const result = await api("/state");
      setData(result);
      setUpdated(new Date());
      setError("");
    } catch (e) {
      const err = e as Error & { status: number };
      if (err.status === 401) setSession(null);
      else setError(err.message);
    }
  }, []);
  useEffect(() => {
    api("/session")
      .then((s) => {
        setSession(s);
        return fetchState();
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [fetchState]);
  useEffect(() => {
    if (!session) return;
    const timer = setInterval(fetchState, 10000);
    return () => clearInterval(timer);
  }, [session, fetchState]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 3500);
    return () => clearTimeout(timer);
  }, [toast]);
  const navigate = (next: Page) => {
    setPage(next);
    setSearch("");
    setMenu(false);
  };
  const open = (m: Modal) => {
    setFormError("");
    setModal(m);
  };
  const refresh = async () => {
    setRefreshing(true);
    await fetchState();
    setRefreshing(false);
  };
  const notify = (message: string) => setToast(message);
  const copy = async (value: string) => {
    try {
      if (navigator.clipboard && window.isSecureContext)
        await navigator.clipboard.writeText(value);
      else {
        const t = document.createElement("textarea");
        t.value = value;
        document.body.appendChild(t);
        t.select();
        const ok = document.execCommand("copy");
        t.remove();
        if (!ok) throw new Error();
      }
      notify("已复制到剪贴板");
    } catch {
      notify("无法自动复制，请手动选择复制");
    }
  };
  const run = async (path: string, method: string, body?: unknown) => {
    const result = await api(path, session?.csrf, method, body);
    await fetchState();
    return result;
  };
  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!modal) return;
    setBusy(true);
    setFormError("");
    const form = new FormData(event.currentTarget);
    const text = (key: string) => String(form.get(key) || "");
    const expires = text("expires_at")
      ? Math.floor(new Date(text("expires_at")).getTime() / 1000)
      : null;
    const id = modal.item?.id;
    try {
      if (modal.kind === "user")
        await run(id ? `/users/${id}` : "/users", id ? "PUT" : "POST", {
          name: text("name"),
          note: text("note"),
          enabled: form.get("enabled") === "on",
          expires_at: expires,
          zone_ids: form.getAll("zone_ids"),
        });
      if (modal.kind === "zone")
        await run(id ? `/zones/${id}` : "/zones", id ? "PUT" : "POST", {
          name: text("name"),
          note: text("note"),
          enabled: form.get("enabled") === "on",
        });
      if (modal.kind === "record")
        await run(id ? `/records/${id}` : "/records", id ? "PUT" : "POST", {
          zone_id: text("zone_id"),
          name: text("name"),
          record_type: text("record_type"),
          value: text("value"),
          ttl: Number(text("ttl")),
          enabled: form.get("enabled") === "on",
        });
      if (modal.kind === "token") {
        const result = await run("/tokens", "POST", {
          user_id: text("user_id"),
          name: text("name"),
          expires_at: expires,
        });
        setModal({
          kind: "secret",
          secretType: "token",
          secret: result.token,
          item: { id: result.id, name: text("name") },
        });
        return;
      }
      if (modal.kind === "node") {
        const result = await run(
          id ? `/nodes/${id}` : "/nodes",
          id ? "PUT" : "POST",
          {
            name: text("name"),
            endpoint: text("endpoint"),
            region: text("region"),
            note: text("note"),
            enabled: form.get("enabled") === "on",
          },
        );
        if (!id) {
          setModal({
            kind: "secret",
            secretType: "node",
            secret: result.secret,
            installCommand: result.install_command,
            installExpires: result.install_expires_at,
            controller: result.controller_url,
            item: { id: result.id, name: text("name") },
          });
          return;
        }
      }
      if (modal.kind === "delete")
        await run(`/${modal.resource}/${id}`, "DELETE");
      if (modal.kind === "revoke") await run(`/tokens/${id}/revoke`, "POST");
      if (modal.kind === "rotate") {
        const result = await run(`/nodes/${id}/rotate`, "POST");
        setModal({
          kind: "secret",
          secretType: "node",
          secret: result.secret,
          installCommand: result.install_command,
          installExpires: result.install_expires_at,
          controller: result.controller_url,
          item: modal.item,
        });
        return;
      }
      if (modal.kind === "password")
        await run("/password", "POST", {
          current_password: text("current_password"),
          new_password: text("new_password"),
        });
      setModal(null);
      notify("已保存，配置正在同步到各解析节点");
    } catch (e) {
      setFormError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  if (loading)
    return (
      <div className="splash">
        <Logo large />
        <LoaderCircle className="spin" />
        <p>正在连接控制台</p>
      </div>
    );
  if (!session)
    return (
      <Login
        onLogin={async (s) => {
          setSession(s);
          await fetchState();
        }}
      />
    );
  const infraCall = (path: string, method = "GET", body?: unknown) =>
    api(path, session.csrf, method, body);
  if (data?.infrastructure.required)
    return (
      <div className="setup-shell">
        <div className="setup-brand">
          <h1>DNSDOH</h1>
          <button
            className="button secondary"
            onClick={async () => {
              await api("/logout", session.csrf, "POST");
              setSession(null);
            }}
          >
            退出登录
          </button>
        </div>
        <Infrastructure
          value={data.infrastructure}
          call={infraCall}
          refresh={fetchState}
          mandatory
        />
      </div>
    );
  const current = pages.find((p) => p.id === page)!;
  const matches = (...values: (string | undefined)[]) =>
    values.join(" ").toLowerCase().includes(search.toLowerCase());
  const tokenState = (t: Token) => {
    const user = data?.users.find((u) => u.id === t.user_id);
    if (!t.enabled) return { label: "已撤销", tone: "neutral" as const };
    if (!user?.enabled) return { label: "用户停用", tone: "warn" as const };
    if (expired(t.expires_at) || expired(user.expires_at))
      return { label: "已到期", tone: "warn" as const };
    return { label: "有效", tone: "good" as const };
  };
  const primaryAction = () => {
    if (page === "zones") open({ kind: "record" });
    else if (page === "users") open({ kind: "user" });
    else if (page === "tokens") open({ kind: "token" });
    else if (page === "nodes") setNodeFormOpen(true);
    else open({ kind: "record" });
  };
  const actionLabel =
    page === "users"
      ? "添加用户"
      : page === "tokens"
        ? "签发令牌"
        : page === "nodes"
          ? "添加服务器"
          : "添加解析记录";
  return (
    <div className="app-shell">
      {menu && (
        <button
          className="sidebar-scrim"
          aria-label="关闭导航"
          onClick={() => setMenu(false)}
        />
      )}
      <aside className={`sidebar ${menu ? "open" : ""}`}>
        <Logo />
        <div className="workspace">
          <span className="workspace-avatar">
            <ShieldCheck size={18} />
          </span>
          <span>
            私有解析网络<small>管理工作空间</small>
          </span>
          <ChevronRight size={15} />
        </div>
        <div className="nav-caption">工作空间</div>
        <nav>
          {pages.slice(0, 5).map((p) => (
            <button
              key={p.id}
              className={`nav-item ${page === p.id ? "active" : ""}`}
              onClick={() => navigate(p.id)}
            >
              <p.icon size={19} />
              <span>{p.label}</span>
              {p.id === "nodes" && data && <b>{data.nodes.length}</b>}
            </button>
          ))}
        </nav>
        <div className="nav-caption system-caption">管理</div>
        <nav>
          {pages.slice(5).map((p) => (
            <button
              key={p.id}
              className={`nav-item ${page === p.id ? "active" : ""}`}
              onClick={() => navigate(p.id)}
            >
              <p.icon size={19} />
              <span>{p.label}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <div className="privacy-card">
            <span className="privacy-icon">
              <LockKeyhole size={17} />
            </span>
            <strong>解析，只对授权用户开放</strong>
            <p>独立令牌 · 私有记录 · 加密传输</p>
            <button onClick={() => open({ kind: "guide" })}>
              查看接入说明 <ArrowUpRight size={14} />
            </button>
          </div>
          <div className="sidebar-version">
            <span className="live-dot" /> DNSDOH{" "}
            <span>v{data?.system.version || "0.1.0"}</span>
          </div>
        </div>
      </aside>
      <div className="main-shell">
        <header className="topbar">
          <div className="breadcrumb">
            <IconButton title="打开导航" onClick={() => setMenu(true)}>
              <Menu size={20} />
            </IconButton>
            <span>工作空间</span>
            <ChevronRight size={14} />
            <strong>{current.label}</strong>
          </div>
          <div className="topbar-right">
            <span className="connection-state">
              <i className={error ? "warn-dot" : "live-dot"} />
              {error ? "连接异常" : "管理主控已连接"}
            </span>
            <span className="topbar-divider" />
            <button
              className="help-button"
              onClick={() => open({ kind: "guide" })}
              aria-label="使用说明"
            >
              <CircleHelp size={19} />
            </button>
            <div className="admin-avatar">
              {session.username.slice(0, 1).toUpperCase()}
            </div>
            <span className="admin-name">
              {session.username}
              <small>管理员</small>
            </span>
            <IconButton
              title="退出登录"
              onClick={async () => {
                try {
                  await api("/logout", session.csrf, "POST");
                  setSession(null);
                  setData(null);
                } catch (e) {
                  setError((e as Error).message);
                }
              }}
            >
              <LogOut size={17} />
            </IconButton>
          </div>
        </header>
        <main className="main-content">
          {data?.infrastructure.domains.some((d) => d.last_error) &&
            page !== "settings" && (
              <div className="infra-error global-domain-alert">
                <AlertCircle size={18} />
                <span>
                  域名或 DNS
                  供应商需要检查。请到系统设置查看提示、修复或更换域名。
                </span>
                <button
                  className="button secondary small"
                  onClick={() => navigate("settings")}
                >
                  查看 / 修复
                </button>
              </div>
            )}
          <div className="page-heading">
            <div>
              <div className="eyebrow">
                DNSDOH CONSOLE <span>/ {page.toUpperCase()}</span>
              </div>
              <h1>{current.label === "概览" ? "网络概览" : current.label}</h1>
              <p>{current.desc}</p>
            </div>
            <div className="heading-actions">
              <button
                className="button secondary"
                onClick={refresh}
                disabled={refreshing}
              >
                <RefreshCw size={16} className={refreshing ? "spin" : ""} />
                刷新
              </button>
              {!["audit", "settings"].includes(page) && (
                <button className="button primary" onClick={primaryAction}>
                  <Plus size={17} />
                  {actionLabel}
                </button>
              )}
            </div>
          </div>
          {error && (
            <div className="alert error">
              <AlertCircle size={18} />
              <span>{error}</span>
              <button onClick={refresh}>重试</button>
            </div>
          )}
          {!data ? (
            <div className="loading-panel">
              <LoaderCircle className="spin" />
              正在加载实际运行数据…
            </div>
          ) : (
            <>
              {page === "overview" && (
                <Overview
                  data={data}
                  navigate={navigate}
                  open={open}
                  tokenState={tokenState}
                />
              )}
              {page === "zones" && (
                <>
                  <div className="zone-strip">
                    <button
                      className={`zone-chip ${zoneFilter === "all" ? "selected" : ""}`}
                      onClick={() => setZoneFilter("all")}
                    >
                      <Globe2 size={16} />
                      全部分区 <b>{data.zones.length}</b>
                    </button>
                    {data.zones.map((z) => (
                      <button
                        key={z.id}
                        className={`zone-chip ${zoneFilter === z.id ? "selected" : ""}`}
                        onClick={() => setZoneFilter(z.id)}
                      >
                        <i className={z.enabled ? "live-dot" : "muted-dot"} />
                        {z.name}
                        <span
                          onClick={(e) => {
                            e.stopPropagation();
                            open({ kind: "zone", item: z });
                          }}
                          role="button"
                          aria-label={`编辑分区 ${z.name}`}
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === "Enter") {
                              e.stopPropagation();
                              open({ kind: "zone", item: z });
                            }
                          }}
                        >
                          <Pencil size={13} />
                        </span>
                      </button>
                    ))}
                    <button
                      className="zone-add"
                      onClick={() => open({ kind: "zone" })}
                    >
                      <Plus size={16} />
                      新建分区
                    </button>
                  </div>
                  <section className="panel">
                    <div className="panel-toolbar">
                      <div>
                        <h2>
                          解析记录{" "}
                          <span className="count">{data.records.length}</span>
                        </h2>
                        <p>真实地址仅通过授权的 DoH 请求返回</p>
                      </div>
                      <div className="toolbar-actions">
                        <SearchBox
                          value={search}
                          onChange={setSearch}
                          placeholder="搜索域名或 IP 地址"
                        />
                        <button
                          className="button small secondary"
                          onClick={() =>
                            download(
                              "DNSDOH-records.json",
                              JSON.stringify(
                                { zones: data.zones, records: data.records },
                                null,
                                2,
                              ),
                            )
                          }
                        >
                          <ArrowDownToLine size={15} />
                          导出记录
                        </button>
                      </div>
                    </div>
                    {!data.zones.length ? (
                      <Empty
                        title="创建你的第一个私有分区"
                        description="例如 nodes.example.com，节点地址将只保存在这里。"
                        action={
                          <button
                            className="button primary"
                            onClick={() => open({ kind: "zone" })}
                          >
                            <Plus size={16} />
                            新建分区
                          </button>
                        }
                      />
                    ) : (
                      <Table
                        headers={[
                          "域名",
                          "类型",
                          "解析地址",
                          "TTL",
                          "状态",
                          "操作",
                        ]}
                        empty="暂无匹配的解析记录"
                      >
                        {data.records
                          .filter(
                            (r) =>
                              (zoneFilter === "all" ||
                                r.zone_id === zoneFilter) &&
                              matches(r.name, r.value),
                          )
                          .map((r) => (
                            <tr key={r.id}>
                              <td>
                                <div className="table-name">
                                  <span className="table-icon blue">
                                    <Globe2 size={17} />
                                  </span>
                                  <span>
                                    <strong className="mono">{r.name}</strong>
                                    <small>{r.zone_name}</small>
                                  </span>
                                </div>
                              </td>
                              <td>
                                <span className="type-tag">
                                  {r.record_type}
                                </span>
                              </td>
                              <td className="mono">{r.value}</td>
                              <td>{r.ttl}s</td>
                              <td>
                                <Badge tone={r.enabled ? "good" : "neutral"}>
                                  {r.enabled ? "已启用" : "已停用"}
                                </Badge>
                              </td>
                              <td>
                                <div className="row-actions">
                                  <IconButton
                                    title={`编辑记录 ${r.name}`}
                                    onClick={() =>
                                      open({ kind: "record", item: r })
                                    }
                                  >
                                    <Pencil size={15} />
                                  </IconButton>
                                  <IconButton
                                    title={`删除记录 ${r.name}`}
                                    danger
                                    onClick={() =>
                                      open({
                                        kind: "delete",
                                        resource: "records",
                                        item: r,
                                      })
                                    }
                                  >
                                    <Trash2 size={15} />
                                  </IconButton>
                                </div>
                              </td>
                            </tr>
                          ))}
                      </Table>
                    )}
                  </section>
                  {zoneFilter !== "all" &&
                    data.zones.find((z) => z.id === zoneFilter) && (
                      <div className="subtle-action">
                        <span>删除分区会同时删除其中的记录及用户授权。</span>
                        <button
                          className="text-danger"
                          onClick={() =>
                            open({
                              kind: "delete",
                              resource: "zones",
                              item: data.zones.find((z) => z.id === zoneFilter),
                            })
                          }
                        >
                          删除当前分区
                        </button>
                      </div>
                    )}
                </>
              )}
              {page === "users" && (
                <section className="panel">
                  <div className="panel-toolbar">
                    <div>
                      <h2>
                        用户列表{" "}
                        <span className="count">{data.users.length}</span>
                      </h2>
                      <p>域名权限按分区授予，默认没有任何访问权限</p>
                    </div>
                    <SearchBox
                      value={search}
                      onChange={setSearch}
                      placeholder="搜索用户或备注"
                    />
                  </div>
                  <Table
                    headers={[
                      "用户",
                      "授权分区",
                      "有效令牌",
                      "到期时间",
                      "状态",
                      "操作",
                    ]}
                    empty="还没有用户，点击右上角添加用户"
                  >
                    {data.users
                      .filter((u) => matches(u.name, u.note))
                      .map((u) => (
                        <tr key={u.id}>
                          <td>
                            <div className="table-name">
                              <span className="user-initial">
                                {u.name.slice(0, 1).toUpperCase()}
                              </span>
                              <span>
                                <strong>{u.name}</strong>
                                <small>{u.note || "暂无备注"}</small>
                              </span>
                            </div>
                          </td>
                          <td>
                            <div className="tag-list">
                              {u.zone_ids.length ? (
                                u.zone_ids.map((id) => (
                                  <span className="tag" key={id}>
                                    {data.zones.find((z) => z.id === id)
                                      ?.name || "分区已删除"}
                                  </span>
                                ))
                              ) : (
                                <span className="muted">未授权</span>
                              )}
                            </div>
                          </td>
                          <td>
                            {
                              data.tokens.filter(
                                (t) =>
                                  t.user_id === u.id &&
                                  tokenState(t).tone === "good",
                              ).length
                            }
                          </td>
                          <td>{until(u.expires_at)}</td>
                          <td>
                            <Badge
                              tone={
                                !u.enabled
                                  ? "neutral"
                                  : expired(u.expires_at)
                                    ? "warn"
                                    : "good"
                              }
                            >
                              {!u.enabled
                                ? "已停用"
                                : expired(u.expires_at)
                                  ? "已到期"
                                  : "正常"}
                            </Badge>
                          </td>
                          <td>
                            <div className="row-actions">
                              <IconButton
                                title={`为 ${u.name} 签发令牌`}
                                onClick={() =>
                                  open({
                                    kind: "token",
                                    item: { user_id: u.id },
                                  })
                                }
                              >
                                <KeyRound size={16} />
                              </IconButton>
                              <IconButton
                                title={`编辑用户 ${u.name}`}
                                onClick={() => open({ kind: "user", item: u })}
                              >
                                <Pencil size={15} />
                              </IconButton>
                              <IconButton
                                title={`删除用户 ${u.name}`}
                                danger
                                onClick={() =>
                                  open({
                                    kind: "delete",
                                    resource: "users",
                                    item: u,
                                  })
                                }
                              >
                                <Trash2 size={15} />
                              </IconButton>
                            </div>
                          </td>
                        </tr>
                      ))}
                  </Table>
                </section>
              )}
              {page === "tokens" && (
                <>
                  <div className="info-strip">
                    <ShieldCheck size={18} />
                    <span>
                      令牌完整内容仅在签发时显示一次。每个令牌可用于全部已接入的
                      DNS 节点。
                    </span>
                  </div>
                  <section className="panel">
                    <div className="panel-toolbar">
                      <div>
                        <h2>
                          访问凭据{" "}
                          <span className="count">{data.tokens.length}</span>
                        </h2>
                        <p>令牌控制解析权限，授权范围继承所属用户</p>
                      </div>
                      <SearchBox
                        value={search}
                        onChange={setSearch}
                        placeholder="搜索令牌或用户"
                      />
                    </div>
                    <Table
                      headers={[
                        "令牌名称",
                        "所属用户",
                        "令牌标识",
                        "到期时间",
                        "状态",
                        "操作",
                      ]}
                      empty="还没有访问令牌，先创建用户后签发"
                    >
                      {data.tokens
                        .filter((t) => matches(t.name, t.user_name, t.prefix))
                        .map((t) => (
                          <tr key={t.id}>
                            <td>
                              <div className="table-name">
                                <span className="table-icon purple">
                                  <KeyRound size={17} />
                                </span>
                                <span>
                                  <strong>{t.name}</strong>
                                  <small>创建于 {date(t.created_at)}</small>
                                </span>
                              </div>
                            </td>
                            <td>{t.user_name}</td>
                            <td>
                              <code className="token-prefix">
                                {t.prefix}••••••••
                              </code>
                            </td>
                            <td>{until(t.expires_at)}</td>
                            <td>
                              <Badge tone={tokenState(t).tone}>
                                {tokenState(t).label}
                              </Badge>
                            </td>
                            <td>
                              {t.enabled ? (
                                <button
                                  className="button small danger-ghost"
                                  onClick={() =>
                                    open({ kind: "revoke", item: t })
                                  }
                                >
                                  <ShieldX size={14} />
                                  撤销
                                </button>
                              ) : (
                                <span className="muted">已失效</span>
                              )}
                            </td>
                          </tr>
                        ))}
                    </Table>
                  </section>
                </>
              )}
              {page === "nodes" && (
                <ManagedNodes
                  nodes={data.nodes}
                  infra={data.infrastructure}
                  call={infraCall}
                  refresh={fetchState}
                  formOpen={nodeFormOpen}
                  onClose={() => setNodeFormOpen(false)}
                />
              )}
              {page === "audit" && (
                <section className="panel">
                  <div className="panel-toolbar">
                    <div>
                      <h2>最近操作</h2>
                      <p>
                        展示最近 100 条管理记录 · 数据保留{" "}
                        {data.settings.retention_days} 天
                      </p>
                    </div>
                    <SearchBox
                      value={search}
                      onChange={setSearch}
                      placeholder="搜索操作或目标"
                    />
                  </div>
                  <Table
                    headers={["操作", "目标", "操作人", "时间"]}
                    empty="暂无操作记录"
                  >
                    {data.audit
                      .filter((a) => matches(a.action, a.target, a.actor))
                      .map((a, i) => (
                        <tr key={i}>
                          <td>
                            <div className="table-name">
                              <span className="table-icon">
                                <FileClock size={16} />
                              </span>
                              <strong>{a.action}</strong>
                            </div>
                          </td>
                          <td className="mono wrap">{a.target}</td>
                          <td>
                            <span className="actor">
                              <span />
                              {a.actor}
                            </span>
                          </td>
                          <td>{date(a.created_at)}</td>
                        </tr>
                      ))}
                  </Table>
                </section>
              )}
              {page === "settings" && (
                <>
                  <Infrastructure
                    value={data.infrastructure}
                    call={infraCall}
                    refresh={fetchState}
                  />
                  <Settings data={data} run={run} notify={notify} open={open} />
                </>
              )}
            </>
          )}
          <footer className="page-footer">
            <span>
              <LockKeyhole size={13} /> DNSDOH · 私有解析基础设施
            </span>
            <span>
              {updated
                ? `最近更新 ${updated.toLocaleTimeString("zh-CN", { hour12: false })}`
                : "等待同步"}
              <i />每 10 秒自动刷新
            </span>
          </footer>
        </main>
      </div>
      {toast && (
        <div className="toast" role="status">
          <CheckCircle2 size={18} />
          {toast}
        </div>
      )}
      {modal && data && (
        <Dialog
          modal={modal}
          data={data}
          busy={busy}
          error={formError}
          submit={submit}
          close={() => {
            if (!busy) setModal(null);
          }}
          copy={copy}
          open={open}
        />
      )}
    </div>
  );
}

function SearchBox({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (s: string) => void;
  placeholder: string;
}) {
  return (
    <label className="search-box">
      <Search size={16} />
      <input
        aria-label={placeholder}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
      />
      {value && (
        <button onClick={() => onChange("")} aria-label="清空搜索">
          <X size={13} />
        </button>
      )}
    </label>
  );
}
function Table({
  headers,
  children,
  empty,
}: {
  headers: string[];
  children: ReactNode[];
  empty: string;
}) {
  return children.length ? (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            {headers.map((h) => (
              <th key={h}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  ) : (
    <Empty title={empty} description="记录会在创建后显示在这里。" />
  );
}

function Overview({
  data,
  navigate,
  open,
  tokenState,
}: {
  data: Data;
  navigate: (p: Page) => void;
  open: (m: Modal) => void;
  tokenState: (t: Token) => { tone: string };
}) {
  const total = data.metrics.reduce((a, m) => a + m.total, 0),
    success = data.metrics.reduce((a, m) => a + m.success, 0),
    latency = data.metrics.reduce((a, m) => a + m.latency_us, 0);
  const rate = total ? (success / total) * 100 : 0;
  const online = data.nodes.filter((n) => n.enabled && n.online).length;
  const enabled = data.nodes.filter((n) => n.enabled).length;
  const activeTokens = data.tokens.filter(
    (t) => tokenState(t).tone === "good",
  ).length;
  const stats = [
    {
      label: "DNS 查询",
      value: number(total),
      unit: "次",
      icon: Activity,
      color: "blue",
      detail: "过去 24 小时的实际查询",
      extra: total ? `${number(success)} 次成功` : "等待第一条查询",
    },
    {
      label: "解析成功率",
      value: total ? rate.toFixed(1) : "—",
      unit: total ? "%" : "",
      icon: ShieldCheck,
      color: "green",
      detail: "有效 DNS 响应占全部请求",
      extra: total ? `${number(total - success)} 次拒绝或异常` : "尚无查询样本",
    },
    {
      label: "在线解析节点",
      value: String(online + (data.system.ready ? 1 : 0)),
      unit: `/ ${enabled + 1}`,
      icon: Server,
      color: "purple",
      detail: "包含统一 DoH 入口",
      extra: `${data.settings.sync_seconds} 秒同步间隔`,
    },
    {
      label: "有效访问令牌",
      value: String(activeTokens),
      unit: "个",
      icon: KeyRound,
      color: "amber",
      detail: `已管理 ${data.users.length} 位用户`,
      extra: `${data.zones.length} 个私有分区`,
    },
  ];
  return (
    <>
      <div className="welcome-banner">
        <div className="welcome-symbol">
          <ShieldCheck size={28} />
        </div>
        <div>
          <strong>你的域名，由你决定谁能解析。</strong>
          <p>通过专属 DoH 访问令牌，将真实地址交给被授权的用户。</p>
        </div>
        <button onClick={() => open({ kind: "guide" })}>
          接入指南 <ArrowRight size={16} />
        </button>
        <div className="banner-orbit orbit-one" />
        <div className="banner-orbit orbit-two" />
      </div>
      <div className="stats-grid">
        {stats.map((s) => (
          <div className="stat-card" key={s.label}>
            <div className="stat-top">
              <span>{s.label}</span>
              <span className={`stat-icon ${s.color}`}>
                <s.icon size={19} />
              </span>
            </div>
            <div className="stat-value">
              {s.value}
              <span>{s.unit}</span>
            </div>
            <div className="stat-detail">{s.detail}</div>
            <div className="stat-bottom">
              <span className={`tiny-dot ${s.color}`} />
              {s.extra}
            </div>
          </div>
        ))}
      </div>
      <div className="overview-main">
        <section className="panel chart-panel">
          <div className="panel-heading">
            <div>
              <h2>解析请求趋势</h2>
              <p>从实际节点上报汇总，按小时展示</p>
            </div>
            <span className="period-pill">
              <Clock3 size={14} />
              最近 24 小时
            </span>
          </div>
          <QueryChart metrics={data.metrics} />
          <div className="chart-foot">
            <span>
              <i className="legend-dot" />
              全部查询
            </span>
            <span>
              <i className="legend-dot green" />
              成功响应
            </span>
            <span className="chart-latency">
              平均处理耗时{" "}
              <strong>
                {total ? (latency / total / 1000).toFixed(2) : "—"} ms
              </strong>
            </span>
          </div>
        </section>
        <section className="panel network-panel">
          <div className="panel-heading">
            <div>
              <h2>网络状态</h2>
              <p>控制平面与解析节点</p>
            </div>
            <span className="mini-icon">
              <Network size={18} />
            </span>
          </div>
          <div className="network-visual">
            <div className="network-ring ring-outer" />
            <div className="network-ring ring-inner" />
            <div className="network-center">
              <Network size={26} />
            </div>
            <span className="orbit-node n1">
              <Server size={17} />
            </span>
            <span className="orbit-node n2">
              <Server size={17} />
            </span>
            <span className="orbit-node n3">
              <Globe2 size={17} />
            </span>
            <span className="orbit-node n4">
              <KeyRound size={17} />
            </span>
          </div>
          <div className="network-state">
            <Badge tone={data.system.ready ? "good" : "bad"}>
              {data.system.ready ? "主控正常运行" : "主控配置不可用"}
            </Badge>
            <p>
              {online} 台独立节点在线 · 配置版本 v{data.settings.revision}
            </p>
          </div>
          <button className="panel-link" onClick={() => navigate("nodes")}>
            管理 DNS 服务器 <ArrowRight size={15} />
          </button>
        </section>
      </div>
      <div className="overview-bottom">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>DNS 服务器</h2>
              <p>节点同步与连接状态</p>
            </div>
            <button className="text-link" onClick={() => navigate("nodes")}>
              查看全部 <ArrowRight size={14} />
            </button>
          </div>
          <div className="compact-node">
            <span className="table-icon blue">
              <Database size={18} />
            </span>
            <div>
              <strong>统一 DoH · 直接解析</strong>
              <small>{data.system.doh_url}</small>
            </div>
            <Badge tone={data.system.ready ? "good" : "bad"}>
              {data.system.ready ? "就绪" : "不可用"}
            </Badge>
          </div>
          {data.nodes.slice(0, 3).map((n) => (
            <div className="compact-node" key={n.id}>
              <span className="table-icon">
                <Server size={18} />
              </span>
              <div>
                <strong>
                  {n.name}
                  <small className="inline-region">{n.region}</small>
                </strong>
                <small>{n.endpoint}</small>
              </div>
              <Badge
                tone={
                  !n.enabled
                    ? "neutral"
                    : !n.online
                      ? "warn"
                      : n.applied_revision === data.settings.revision
                        ? "good"
                        : "blue"
                }
              >
                {!n.enabled
                  ? "停用"
                  : !n.online
                    ? "未连接"
                    : n.applied_revision === data.settings.revision
                      ? "已同步"
                      : "同步中"}
              </Badge>
            </div>
          ))}
          {!data.nodes.length && (
            <div className="compact-placeholder">
              还没有独立节点，统一 DoH 入口已可使用。
              <button
                className="text-link"
                onClick={() => open({ kind: "node" })}
              >
                添加服务器 <Plus size={14} />
              </button>
            </div>
          )}
        </section>
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>最近活动</h2>
              <p>你的管理变更记录</p>
            </div>
            <button className="text-link" onClick={() => navigate("audit")}>
              全部记录 <ArrowRight size={14} />
            </button>
          </div>
          <div className="activity-list">
            {data.audit.length ? (
              data.audit.slice(0, 4).map((a, i) => (
                <div className="activity-item" key={i}>
                  <span className="activity-dot">
                    <Check size={12} />
                  </span>
                  <div>
                    <strong>{a.action}</strong>
                    <p>{a.target}</p>
                  </div>
                  <time>{date(a.created_at)}</time>
                </div>
              ))
            ) : (
              <div className="compact-placeholder">
                创建分区、用户或节点后，操作记录会出现在这里。
              </div>
            )}
          </div>
        </section>
      </div>
    </>
  );
}
function QueryChart({ metrics }: { metrics: Metric[] }) {
  const end = Math.floor(Date.now() / 3600000) * 3600;
  const points = Array.from(
    { length: 24 },
    (_, i) =>
      metrics.find((m) => m.bucket === end - (23 - i) * 3600) || {
        bucket: end - (23 - i) * 3600,
        total: 0,
        success: 0,
        denied: 0,
        errors: 0,
        latency_us: 0,
      },
  );
  const max = Math.max(4, ...points.map((m) => m.total));
  const w = 760,
    h = 180;
  const xy = (v: number, i: number) =>
    `${i * (w / 23)},${h - (v / max) * (h - 15)}`;
  const path = points.map((m, i) => xy(m.total, i)).join(" ");
  const ok = points.map((m, i) => xy(m.success, i)).join(" ");
  return (
    <div className="chart-wrap">
      <div className="chart-y">
        {[1, 0.75, 0.5, 0.25, 0].map((v) => (
          <span key={v}>{Math.round(max * v)}</span>
        ))}
      </div>
      <div className="chart-canvas">
        <svg
          viewBox={`0 0 ${w} ${h}`}
          role="img"
          aria-label="最近24小时每小时查询数"
          preserveAspectRatio="none"
        >
          <defs>
            <linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#5575fa" stopOpacity=".2" />
              <stop offset="100%" stopColor="#5575fa" stopOpacity=".01" />
            </linearGradient>
          </defs>
          {[0, 0.25, 0.5, 0.75, 1].map((v) => (
            <line
              key={v}
              x1="0"
              x2={w}
              y1={h - v * (h - 15)}
              y2={h - v * (h - 15)}
              stroke="#edf0f5"
              strokeDasharray="4 5"
            />
          ))}
          <polygon
            points={`0,${h} ${path} ${w},${h}`}
            fill="url(#chart-fill)"
          />
          <polyline
            points={path}
            fill="none"
            stroke="#5575fa"
            strokeWidth="2.5"
            vectorEffect="non-scaling-stroke"
            strokeLinejoin="round"
          />
          <polyline
            points={ok}
            fill="none"
            stroke="#36b89a"
            strokeWidth="1.5"
            vectorEffect="non-scaling-stroke"
            strokeDasharray="4 4"
          />
          {points.map((m, i) => (
            <circle
              key={i}
              cx={(i * w) / 23}
              cy={h - (m.total / max) * (h - 15)}
              r="3"
              fill="#5575fa"
              opacity={m.total ? 1 : 0}
            >
              <title>
                {new Date(m.bucket * 1000).toLocaleTimeString("zh-CN")}：
                {m.total} 次查询，{m.success} 次成功
              </title>
            </circle>
          ))}
        </svg>
        <div className="chart-x">
          {[0, 5, 11, 17, 23].map((i) => (
            <span key={i}>
              {new Date(points[i].bucket * 1000)
                .getHours()
                .toString()
                .padStart(2, "0")}
              :00
            </span>
          ))}
        </div>
        {points.every((p) => p.total === 0) && (
          <div className="chart-empty">
            <Activity size={17} />
            等待真实查询数据
          </div>
        )}
      </div>
    </div>
  );
}
function NodeCard({
  node,
  data,
  local = false,
  copy,
  edit,
  remove,
  rotate,
  install,
}: {
  node?: Node;
  data: Data;
  local?: boolean;
  copy: (s: string) => void;
  edit?: () => void;
  remove?: () => void;
  rotate?: () => void;
  install?: () => void;
}) {
  const name = local ? "统一 DoH · 直接解析" : node!.name;
  const endpoint = local ? data.system.doh_url : node!.endpoint;
  const probe = data.gateway.probes.find((p) => p.id === node?.id);
  const online = local ? data.system.ready : node!.online && node!.enabled;
  const revision = local ? data.settings.revision : node!.applied_revision;
  const total =
    data.node_metrics.find(
      (m) => m.node_id === (local ? "controller" : node!.id),
    )?.total || 0;
  return (
    <article className={`node-card ${online ? "online" : ""}`}>
      <div className="node-card-top">
        <span className={`node-symbol ${local ? "local" : ""}`}>
          {local ? <Database size={23} /> : <Server size={23} />}
        </span>
        <Badge
          tone={online ? "good" : node && !node.enabled ? "neutral" : "warn"}
        >
          {online ? "在线" : node && !node.enabled ? "已停用" : "未连接"}
        </Badge>
      </div>
      <h3>{name}</h3>
      <p className="node-region">
        {local
          ? "公共 DNS 返回节点 IP · HTTPS 直连"
          : node!.region || "未设置地区"}
      </p>
      <div className="node-endpoint">
        <span>{endpoint}</span>
        <IconButton title={`复制 ${name} 地址`} onClick={() => copy(endpoint)}>
          <Copy size={14} />
        </IconButton>
      </div>
      <div className="node-stats">
        <div>
          <small>24h 查询</small>
          <strong>{number(total)}</strong>
        </div>
        <div>
          <small>配置版本</small>
          <strong>
            v{revision}
            <i
              className={
                revision === data.settings.revision ? "live-dot" : "warn-dot"
              }
            />
          </strong>
        </div>
        <div>
          <small>最近心跳</small>
          <strong>
            {local
              ? "本机"
              : node!.last_seen
                ? `${Math.max(0, data.system.now - node!.last_seen)}s 前`
                : "等待接入"}
          </strong>
        </div>
      </div>
      {!local && (
        <p className="node-note">
          {node!.auth_mode === "ed25519" ? "Ed25519 签名认证" : "旧版密钥认证"}{" "}
          ·{" "}
          {probe?.healthy && probe.revision === data.settings.revision
            ? `入口 RTT ${probe.latency_ms.toFixed(1)} ms`
            : "等待健康探测"}
          {data.gateway.selected_node === node!.id ? " · 当前优选" : ""}
        </p>
      )}
      {!local && node!.enabled && (
        <button className="button secondary small" onClick={install}>
          <ArrowDownToLine size={15} />
          安装 / 重新接入
        </button>
      )}
      <div className="node-card-bottom">
        <span>
          {local
            ? `Rust ${data.system.version}`
            : node!.version
              ? `v${node!.version}`
              : "尚未注册心跳"}
        </span>
        {!local && (
          <div className="row-actions">
            <IconButton title={`编辑服务器 ${name}`} onClick={edit!}>
              <Pencil size={15} />
            </IconButton>
            <IconButton title={`轮换 ${name} 接入密钥`} onClick={rotate!}>
              <KeyRound size={15} />
            </IconButton>
            <IconButton title={`删除服务器 ${name}`} danger onClick={remove!}>
              <Trash2 size={15} />
            </IconButton>
          </div>
        )}
      </div>
      {node?.note && <p className="node-note">{node.note}</p>}
    </article>
  );
}

function Settings({
  data,
  run,
  notify,
  open,
}: {
  data: Data;
  run: (p: string, m: string, b?: unknown) => Promise<unknown>;
  notify: (s: string) => void;
  open: (m: Modal) => void;
}) {
  const [nodeFormOpen, setNodeFormOpen] = useState(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState("");
  return (
    <div className="settings-grid">
      <section className="panel">
        <div className="panel-heading">
          <div>
            <h2>查询与数据</h2>
            <p>设置会同步到所有在线解析节点</p>
          </div>
          <Settings2 size={21} />
        </div>
        <form
          className="settings-form"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError("");
            const f = new FormData(e.currentTarget);
            try {
              await run("/settings", "PUT", {
                token_qps: Number(f.get("token_qps")),
                retention_days: Number(f.get("retention_days")),
              });
              notify("系统设置已保存");
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <Field
            label="每个令牌的查询上限"
            hint="每个节点独立执行，单位为每秒请求数（QPS）"
          >
            <div className="input-unit">
              <input
                name="token_qps"
                type="number"
                min="1"
                max="1000"
                defaultValue={data.settings.token_qps}
                required
              />
              <span>次 / 秒</span>
            </div>
          </Field>
          <Field
            label="统计与操作记录保留时间"
            hint="系统定期清理过期统计和操作记录，不记录完整令牌或查询 URL"
          >
            <div className="input-unit">
              <input
                name="retention_days"
                type="number"
                min="1"
                max="90"
                defaultValue={data.settings.retention_days}
                required
              />
              <span>天</span>
            </div>
          </Field>
          {error && <div className="alert error">{error}</div>}
          <button className="button primary" disabled={busy}>
            {busy ? (
              <LoaderCircle size={16} className="spin" />
            ) : (
              <Check size={16} />
            )}
            保存设置
          </button>
        </form>
      </section>
      <div className="settings-side">
        <section className="panel">
          <div className="panel-heading">
            <div>
              <h2>系统信息</h2>
              <p>当前服务的实际运行状态</p>
            </div>
            <Database size={20} />
          </div>
          <dl className="system-info">
            <div>
              <dt>主程序</dt>
              <dd>DNSDOH v{data.system.version}</dd>
            </div>
            <div>
              <dt>数据库</dt>
              <dd>MariaDB</dd>
            </div>
            <div>
              <dt>持续运行</dt>
              <dd>
                {Math.floor(data.system.uptime_seconds / 3600)} 小时{" "}
                {Math.floor((data.system.uptime_seconds % 3600) / 60)} 分钟
              </dd>
            </div>
            <div>
              <dt>配置同步</dt>
              <dd>每 {data.settings.sync_seconds} 秒</dd>
            </div>
            <div>
              <dt>节点租约</dt>
              <dd>{data.settings.lease_seconds} 秒</dd>
            </div>
          </dl>
        </section>
        <section className="panel security-panel">
          <span className="stat-icon purple">
            <LockKeyhole size={20} />
          </span>
          <h3>账户安全</h3>
          <p>修改密码后，其他管理员登录会话将失效。</p>
          <button
            className="button secondary"
            onClick={() => open({ kind: "password" })}
          >
            修改登录密码 <ArrowRight size={15} />
          </button>
        </section>
      </div>
    </div>
  );
}

function Login({ onLogin }: { onLogin: (s: Session) => Promise<void> }) {
  const [nodeFormOpen, setNodeFormOpen] = useState(false);
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [visible, setVisible] = useState(false);
  return (
    <div className="login-page">
      <div className="login-brand">
        <Logo large />
      </div>
      <div className="login-art">
        <div className="login-grid" />
        <div className="login-orb o1" />
        <div className="login-orb o2" />
        <div className="login-art-text">
          <span className="login-kicker">PRIVATE BY DESIGN</span>
          <h1>
            你的解析网络，
            <br />
            始终由你掌控。
          </h1>
          <p>
            私有域名、独立令牌、多节点协同。
            <br />
            在一个清晰的控制台中，管理每一次授权。
          </p>
          <div className="login-features">
            <span>
              <ShieldCheck size={17} />
              授权解析
            </span>
            <span>
              <Network size={17} />
              多节点同步
            </span>
            <span>
              <Database size={17} />
              MariaDB
            </span>
          </div>
        </div>
      </div>
      <div className="login-form-wrap">
        <form
          className="login-form"
          onSubmit={async (e) => {
            e.preventDefault();
            setBusy(true);
            setError("");
            const f = new FormData(e.currentTarget);
            try {
              const s = await api("/login", "", "POST", {
                username: f.get("username"),
                password: f.get("password"),
              });
              await onLogin(s);
            } catch (e) {
              setError((e as Error).message);
            } finally {
              setBusy(false);
            }
          }}
        >
          <span className="login-lock">
            <LockKeyhole size={25} />
          </span>
          <h2>登录管理控制台</h2>
          <p>欢迎回来，继续管理你的私有解析服务。</p>
          <Field label="管理员账号">
            <input
              name="username"
              autoComplete="username"
              placeholder="输入管理员账号"
              required
              maxLength={80}
            />
          </Field>
          <Field label="密码">
            <div className="password-field">
              <input
                name="password"
                type={visible ? "text" : "password"}
                autoComplete="current-password"
                placeholder="输入登录密码"
                required
                maxLength={128}
              />
              <button
                type="button"
                aria-label={visible ? "隐藏密码" : "显示密码"}
                onClick={() => setVisible(!visible)}
              >
                {visible ? <EyeOff size={18} /> : <Eye size={18} />}
              </button>
            </div>
          </Field>
          {error && (
            <div className="alert error" role="alert">
              <AlertCircle size={17} />
              {error}
            </div>
          )}
          <button className="button primary login-submit" disabled={busy}>
            {busy ? <LoaderCircle size={18} className="spin" /> : "登录控制台"}
            {!busy && <ArrowRight size={17} />}
          </button>
          <div className="login-security">
            <ShieldCheck size={14} />
            仅授权管理员可访问此控制台
          </div>
        </form>
        <div className="login-footer">
          DNSDOH <span>·</span> Private DNS infrastructure
        </div>
      </div>
    </div>
  );
}

function Dialog({
  modal,
  data,
  busy,
  error,
  submit,
  close,
  copy,
  open,
}: {
  modal: Modal;
  data: Data;
  busy: boolean;
  error: string;
  submit: (e: FormEvent<HTMLFormElement>) => void;
  close: () => void;
  copy: (s: string) => void;
  open: (m: Modal) => void;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [selectedEndpoint, setSelectedEndpoint] = useState(data.system.doh_url);
  const item = modal.item || {};
  useEffect(() => {
    const before = document.activeElement as HTMLElement | null;
    const first = ref.current?.querySelector<HTMLElement>(
      "input,select,button",
    );
    first?.focus();
    const key = (e: KeyboardEvent) => {
      if (e.key === "Escape" && !busy) close();
      if (e.key === "Tab") {
        const list = Array.from(
          ref.current?.querySelectorAll<HTMLElement>(
            "button:not(:disabled),input:not(:disabled),select:not(:disabled),textarea:not(:disabled),a[href]",
          ) || [],
        );
        if (!list.length) return;
        const first = list[0],
          last = list[list.length - 1];
        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    document.addEventListener("keydown", key);
    return () => {
      document.removeEventListener("keydown", key);
      before?.focus();
    };
  }, [modal.kind, busy]);
  const titles = {
    user: item.id ? "编辑用户" : "添加用户",
    zone: item.id ? "编辑私有分区" : "新建私有分区",
    record: item.id ? "编辑解析记录" : "添加解析记录",
    token: "签发访问令牌",
    node: item.id ? "编辑 DNS 服务器" : "添加 DNS 服务器",
    secret:
      modal.secretType === "node" ? "DNS 节点已准备接入" : "访问令牌已签发",
    delete: "确认删除",
    revoke: "撤销访问令牌",
    rotate: "轮换节点接入密钥",
    password: "修改登录密码",
    guide: "接入你的私人 DoH",
  };
  const enabled = (
    <label className="checkbox-row">
      <input
        name="enabled"
        type="checkbox"
        defaultChecked={item.enabled !== false}
      />
      <span>
        启用
        {modal.kind === "user"
          ? "用户"
          : modal.kind === "node"
            ? "服务器"
            : modal.kind === "zone"
              ? "分区"
              : "记录"}
      </span>
    </label>
  );
  const expiry = (
    <Field label="到期时间" hint="留空表示长期有效">
      <input
        name="expires_at"
        type="datetime-local"
        defaultValue={dateInput(item.expires_at)}
      />
    </Field>
  );
  const note = (
    <Field label="备注">
      <textarea
        name="note"
        rows={2}
        maxLength={500}
        placeholder="可选，帮助你识别用途"
        defaultValue={item.note || ""}
      />
    </Field>
  );
  const dohUrl = `${selectedEndpoint}/dns-query/${modal.secret}`;
  const downloadInstall = () => {
    const blob = new Blob(
      [
        `DNSDOH 节点安装命令\n节点：${item.name || item.id}\n有效期至：${date(modal.installExpires ?? null)}\n请在对应服务器 root 终端执行；凭据单次有效，请勿转发。\n\n${modal.installCommand}\n`,
      ],
      { type: "text/plain;charset=utf-8" },
    );
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "DNSDOH-节点安装命令.txt";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };
  return (
    <div className="modal-overlay">
      <div
        className={`modal ${modal.kind === "secret" || modal.kind === "guide" ? "wide" : ""}`}
        ref={ref}
        role="dialog"
        aria-modal="true"
        aria-labelledby="dialog-title"
      >
        <div className="modal-heading">
          <div>
            <span className="eyebrow">DNSDOH / MANAGEMENT</span>
            <h2 id="dialog-title">{titles[modal.kind]}</h2>
          </div>
          <IconButton title="关闭窗口" onClick={close}>
            <X size={20} />
          </IconButton>
        </div>
        {modal.kind === "secret" ? (
          <div className="modal-body">
            <div className="secret-notice">
              <ShieldCheck size={21} />
              <div>
                <strong>请立即保存，此凭据只显示一次。</strong>
                <p>系统只保留摘要，关闭后无法再次查看完整内容。</p>
              </div>
            </div>
            {modal.secretType === "token" ? (
              <>
                <Field label="选择 DNS 服务器">
                  <select
                    value={selectedEndpoint}
                    onChange={(e) => setSelectedEndpoint(e.target.value)}
                  >
                    <option value={data.system.doh_url}>
                      统一 DoH 入口 · {data.system.doh_url}
                    </option>
                  </select>
                </Field>
                <Field
                  label="专属 DoH 地址"
                  hint="将此地址填入支持 DoH 的客户端；同一令牌可切换其他已授权节点入口"
                >
                  <div className="secret-block">
                    <code>{dohUrl}</code>
                    <button
                      className="button secondary small"
                      onClick={() => copy(dohUrl)}
                    >
                      <Copy size={15} />
                      复制地址
                    </button>
                  </div>
                </Field>
                <Field label="访问令牌">
                  <div className="secret-block">
                    <code>{modal.secret}</code>
                    <IconButton
                      title="复制访问令牌"
                      onClick={() => copy(modal.secret!)}
                    >
                      <Copy size={16} />
                    </IconButton>
                  </div>
                </Field>
                <p className="modal-help">
                  用户仍需具备对应域名分区权限。服务器地址可见，不代表节点域名会在公共
                  DNS 中公开。
                </p>
              </>
            ) : (
              <>
                <p className="modal-help">
                  先将节点独立域名的 A / AAAA 记录指向这台服务器，并开放 80、443
                  端口。然后在 Debian / Ubuntu x86_64 服务器的 root
                  终端执行以下命令。自动安装服务、申请 HTTPS
                  证书并启动签名同步。
                </p>
                {modal.installCommand ? (
                  <>
                    <p className="modal-help">
                      单次有效 · 到期时间 {date(modal.installExpires ?? null)}
                      。私钥在节点本机生成，不包含在命令中。
                    </p>
                    <pre className="code-block">{modal.installCommand}</pre>
                    <div className="row-actions">
                      <button
                        className="button secondary"
                        onClick={() => copy(modal.installCommand!)}
                      >
                        <Copy size={16} />
                        复制安装命令
                      </button>
                      <button
                        className="button secondary"
                        onClick={downloadInstall}
                      >
                        <ArrowDownToLine size={16} />
                        下载安装命令
                      </button>
                    </div>
                  </>
                ) : (
                  <p className="modal-help">
                    请先启用服务器，再点击“安装 / 重新接入”生成命令。
                  </p>
                )}
                <p className="modal-help">
                  凭据过期或安装失败时，可在服务器卡片重新生成。新凭据成功接入后会替换原节点身份。用户继续使用统一
                  DoH 域名，无需修改客户端。
                </p>
              </>
            )}
            <div className="modal-actions">
              <button className="button primary" onClick={close}>
                <Check size={16} />
                我已保存凭据
              </button>
            </div>
          </div>
        ) : modal.kind === "guide" ? (
          <div className="modal-body">
            <div className="guide-step">
              <span>01</span>
              <div>
                <h3>创建私有域名分区</h3>
                <p>
                  例如 nodes.example.com，然后添加节点的 A / AAAA 记录。公网权威
                  DNS 不发布这些地址。
                </p>
              </div>
            </div>
            <div className="guide-step">
              <span>02</span>
              <div>
                <h3>添加用户并授权分区</h3>
                <p>
                  每位用户仅能查询获准的分区，停用用户会同时使其全部令牌失效。
                </p>
              </div>
            </div>
            <div className="guide-step">
              <span>03</span>
              <div>
                <h3>签发专属 DoH 地址</h3>
                <p>
                  创建随机令牌，将生成的完整地址交给用户。用户在支持 DoH
                  的客户端中设置该地址。
                </p>
              </div>
            </div>
            <div className="guide-step">
              <span>04</span>
              <div>
                <h3>按需扩展解析节点</h3>
                <p>
                  在 DNS 服务器页面填写公网 IP，通过 SSH
                  自动部署，或选择一次性安装命令。各节点使用同一个 DoH 域名。
                </p>
              </div>
            </div>
            <div className="info-strip">
              <Clock3 size={18} />
              <span>
                撤销令牌只影响后续查询。节点同步和租约最多需要{" "}
                {data.settings.lease_seconds} 秒；已缓存 IP
                与已建立连接不会被主动清除。
              </span>
            </div>
            <div className="modal-actions">
              <button className="button primary" onClick={close}>
                开始使用 <ArrowRight size={16} />
              </button>
            </div>
          </div>
        ) : (
          <form key={modal.kind + (item.id || "")} onSubmit={submit}>
            <div className="modal-body">
              {modal.kind === "user" && (
                <>
                  <Field label="用户名称">
                    <input
                      name="name"
                      required
                      maxLength={100}
                      placeholder="例如：研发团队 / 我的笔记本"
                      defaultValue={item.name || ""}
                    />
                  </Field>
                  <fieldset className="grant-field">
                    <legend>授权私有分区</legend>
                    {data.zones.length ? (
                      data.zones.map((z) => (
                        <label className="grant-row" key={z.id}>
                          <input
                            type="checkbox"
                            name="zone_ids"
                            value={z.id}
                            defaultChecked={item.zone_ids?.includes(z.id)}
                          />
                          <Globe2 size={15} />
                          <span>{z.name}</span>
                          {!z.enabled && <small>已停用</small>}
                        </label>
                      ))
                    ) : (
                      <p className="muted">
                        还没有分区。可先创建用户，稍后再分配权限。
                      </p>
                    )}
                  </fieldset>
                  {expiry}
                  {note}
                  {enabled}
                </>
              )}
              {modal.kind === "zone" && (
                <>
                  <Field
                    label="分区域名"
                    hint="仅管理此域名及其子域，不会修改公共 DNS"
                  >
                    <input
                      name="name"
                      required
                      placeholder="nodes.example.com"
                      maxLength={253}
                      defaultValue={item.name || ""}
                    />
                  </Field>
                  {note}
                  {enabled}
                </>
              )}
              {modal.kind === "record" && (
                <>
                  {!data.zones.length ? (
                    <div className="alert">
                      <span>请先创建私有域名分区。</span>
                      <button
                        type="button"
                        onClick={() => open({ kind: "zone" })}
                      >
                        新建分区
                      </button>
                    </div>
                  ) : (
                    <>
                      <Field label="所属分区">
                        <select
                          name="zone_id"
                          defaultValue={item.zone_id || data.zones[0]?.id}
                          required
                        >
                          {data.zones.map((z) => (
                            <option key={z.id} value={z.id}>
                              {z.name}
                            </option>
                          ))}
                        </select>
                      </Field>
                      <Field label="完整记录域名">
                        <input
                          name="name"
                          required
                          maxLength={253}
                          placeholder="hk01.nodes.example.com"
                          defaultValue={item.name || ""}
                        />
                      </Field>
                      <div className="form-columns">
                        <Field label="记录类型">
                          <select
                            name="record_type"
                            defaultValue={item.record_type || "A"}
                          >
                            <option value="A">A · IPv4</option>
                            <option value="AAAA">AAAA · IPv6</option>
                          </select>
                        </Field>
                        <Field label="TTL（秒）">
                          <input
                            name="ttl"
                            type="number"
                            min={10}
                            max={86400}
                            required
                            defaultValue={item.ttl || 60}
                          />
                        </Field>
                      </div>
                      <Field label="真实 IP 地址">
                        <input
                          name="value"
                          required
                          placeholder="203.0.113.10"
                          maxLength={64}
                          defaultValue={item.value || ""}
                        />
                      </Field>
                      {enabled}
                    </>
                  )}
                </>
              )}
              {modal.kind === "token" && (
                <>
                  {!data.users.length ? (
                    <div className="alert">
                      <span>请先创建一个用户。</span>
                      <button
                        type="button"
                        onClick={() => open({ kind: "user" })}
                      >
                        添加用户
                      </button>
                    </div>
                  ) : (
                    <>
                      <Field label="所属用户">
                        <select
                          name="user_id"
                          required
                          defaultValue={item.user_id || data.users[0]?.id}
                        >
                          {data.users.map((u) => (
                            <option key={u.id} value={u.id}>
                              {u.name}
                              {!u.enabled ? "（已停用）" : ""}
                            </option>
                          ))}
                        </select>
                      </Field>
                      <Field label="令牌名称">
                        <input
                          name="name"
                          required
                          maxLength={100}
                          placeholder="例如：MacBook / 日常连接"
                        />
                      </Field>
                      {expiry}
                      <div className="info-strip">
                        <LockKeyhole size={17} />
                        <span>
                          创建后会显示专属 DoH 地址，请及时保存并交给用户。
                        </span>
                      </div>
                    </>
                  )}
                </>
              )}
              {modal.kind === "node" && (
                <>
                  <Field label="服务器名称">
                    <input
                      name="name"
                      required
                      maxLength={100}
                      placeholder="例如：香港 · DNS 01"
                      defaultValue={item.name || ""}
                    />
                  </Field>
                  <Field
                    label="节点独立 HTTPS 地址"
                    hint="填写节点专属根地址，不包含 /dns-query。先将域名指向节点 IP，用户仍使用统一 DoH 入口。"
                  >
                    <input
                      name="endpoint"
                      type="url"
                      required
                      placeholder="https://doh-hk.example.com"
                      defaultValue={item.endpoint || ""}
                    />
                  </Field>
                  <Field label="地区 / 位置">
                    <input
                      name="region"
                      maxLength={80}
                      placeholder="例如：香港 / HK"
                      defaultValue={item.region || ""}
                    />
                  </Field>
                  {note}
                  {enabled}
                  {!item.id && (
                    <div className="info-strip">
                      <KeyRound size={17} />
                      <span>
                        添加后自动生成一次性安装命令，配置 HTTPS 和安全接入。
                      </span>
                    </div>
                  )}
                </>
              )}
              {["delete", "revoke", "rotate"].includes(modal.kind) && (
                <>
                  <div className="confirm-icon">
                    <ShieldX size={29} />
                  </div>
                  <p className="confirm-text">
                    {modal.kind === "delete"
                      ? "确定删除"
                      : modal.kind === "revoke"
                        ? "确定撤销"
                        : "确定轮换接入密钥"}{" "}
                    <strong>{item.name}</strong>？
                  </p>
                  <p className="modal-help">
                    {modal.kind === "delete" && modal.resource === "users"
                      ? "此用户的全部令牌和分区授权也会被删除。"
                      : modal.kind === "delete" && modal.resource === "zones"
                        ? "此分区的所有解析记录和用户授权也会被删除。"
                        : modal.kind === "rotate"
                          ? "旧接入密钥将失效。你需要在节点服务器上更新新密钥后才能继续同步。"
                          : modal.kind === "revoke"
                            ? "令牌无法重新启用。节点会在同步或租约到期后拒绝新查询，最长 15 秒。"
                            : "此操作无法撤销，配置变更会同步到各节点。"}
                  </p>
                </>
              )}
              {modal.kind === "password" && (
                <>
                  <Field label="当前密码">
                    <input
                      type="password"
                      name="current_password"
                      autoComplete="current-password"
                      required
                    />
                  </Field>
                  <Field
                    label="新密码"
                    hint="至少 12 字节，建议使用密码管理器生成"
                  >
                    <input
                      type="password"
                      name="new_password"
                      autoComplete="new-password"
                      minLength={12}
                      maxLength={128}
                      required
                    />
                  </Field>
                </>
              )}
              {error && (
                <div className="alert error" role="alert">
                  <AlertCircle size={17} />
                  {error}
                </div>
              )}
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="button secondary"
                onClick={close}
                disabled={busy}
              >
                取消
              </button>
              <button
                className={`button ${["delete", "revoke", "rotate"].includes(modal.kind) ? "danger-solid" : "primary"}`}
                disabled={
                  busy ||
                  (modal.kind === "record" && !data.zones.length) ||
                  (modal.kind === "token" && !data.users.length)
                }
              >
                {busy ? (
                  <LoaderCircle size={16} className="spin" />
                ) : modal.kind === "token" ? (
                  <KeyRound size={16} />
                ) : (
                  <Check size={16} />
                )}{" "}
                {modal.kind === "delete"
                  ? "确认删除"
                  : modal.kind === "revoke"
                    ? "确认撤销"
                    : modal.kind === "rotate"
                      ? "确认轮换"
                      : modal.kind === "token"
                        ? "生成访问令牌"
                        : modal.kind === "node" && !item.id
                          ? "添加并生成接入配置"
                          : "保存"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
