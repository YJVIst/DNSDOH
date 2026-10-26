import { chromium, expect } from "@playwright/test";
import fs from "node:fs";
import path from "node:path";

// No traces or screenshots of credentials are retained.
const runtime = process.env.DNSDOH_RUNTIME || "/mnt/youlin-data/runtime";
const output = process.env.DNSDOH_ARTIFACTS || "/mnt/youlin-data/artifacts";
const env = Object.fromEntries(
  fs
    .readFileSync(path.join(runtime, "controller.env"), "utf8")
    .split("\n")
    .filter((l) => l && !l.startsWith("#"))
    .map((l) => {
      const i = l.indexOf("=");
      return [l.slice(0, i), l.slice(i + 1)];
    }),
);
const base =
  process.env.DNSDOH_UI_URL ||
  env.DNSDOH_PUBLIC_URL ||
  "http://127.0.0.1:18080";
fs.mkdirSync(output, { recursive: true });
const browser = await chromium.launch({
  headless: true,
  args: ["--no-sandbox"],
});
const context = await browser.newContext({
  viewport: { width: 1440, height: 1050 },
  timezoneId: "Asia/Shanghai",
  locale: "zh-CN",
});
const page = await context.newPage();
page.setDefaultTimeout(20000);
const errors = [];
const checks = [];
page.on("pageerror", (e) => errors.push(e.message));
const ok = (name) => {
  checks.push(name);
  console.log("PASS", name);
};
const nav = async (name) => {
  await page
    .locator(".sidebar nav")
    .getByRole("button", { name: new RegExp("^" + name) })
    .click();
  if (page.viewportSize().width < 1000)
    await expect
      .poll(async () =>
        page
          .locator(".sidebar")
          .evaluate((e) => e.getBoundingClientRect().right),
      )
      .toBeLessThanOrEqual(0);
};
const modal = () => page.getByRole("dialog");
const save = async () => {
  await modal().getByRole("button", { name: "保存", exact: true }).click();
  await expect(modal()).toHaveCount(0);
};
const noOverflow = async () =>
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= innerWidth,
    ),
  ).toBeTruthy();
const stamp = Date.now().toString(36);
const zone = `ui-${stamp}.example.com`,
  domain = `test.${zone}`,
  user = `界面验收 ${stamp}`;
let token = "";
try {
  await page.goto(base);
  await expect(
    page.getByRole("heading", { name: "登录管理控制台" }),
  ).toBeVisible();
  await page.screenshot({
    path: path.join(output, "login-desktop.png"),
    fullPage: true,
  });
  await page.locator('[name="username"]').fill(env.DNSDOH_ADMIN_USERNAME);
  await page.locator('[name="password"]').fill(env.DNSDOH_ADMIN_PASSWORD);
  await page.getByRole("button", { name: "登录控制台", exact: true }).click();
  await expect(page.getByRole("heading", { name: "网络概览" })).toBeVisible();
  await noOverflow();
  ok("administrator login and real overview");
  await nav("域名与记录");
  await page.getByRole("button", { name: "新建分区", exact: true }).click();
  await modal().locator('[name="name"]').fill(zone);
  await save();
  await page.getByRole("button", { name: "添加解析记录", exact: true }).click();
  await modal().locator('[name="zone_id"]').selectOption({ label: zone });
  await modal().locator('[name="name"]').fill(domain);
  await modal().locator('[name="value"]').fill("192.0.2.88");
  await save();
  await expect(page.getByText(domain, { exact: true }).first()).toBeVisible();
  ok("create private zone and IPv4 record through forms");
  await page
    .getByRole("button", { name: `编辑记录 ${domain}`, exact: true })
    .click();
  await modal().locator('[name="value"]').fill("192.0.2.89");
  await save();
  await expect(
    page
      .getByRole("row")
      .filter({ hasText: domain })
      .getByText("192.0.2.89", { exact: true }),
  ).toBeVisible();
  ok("edit record and persist address");
  await page
    .getByRole("textbox", { name: "搜索域名或 IP 地址" })
    .fill("no-match-at-all");
  await expect(page.getByText("暂无匹配的解析记录")).toBeVisible();
  await page.getByRole("button", { name: "清空搜索" }).click();
  ok("record search and empty state");
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "导出记录" }).click();
  const dl = await downloadPromise;
  const file = await dl.path();
  const exported = JSON.parse(fs.readFileSync(file, "utf8"));
  expect(exported.records.some((r) => r.name === domain)).toBeTruthy();
  ok("export records downloads valid actual JSON");
  await nav("用户管理");
  await page.getByRole("button", { name: "添加用户", exact: true }).click();
  await modal().locator('[name="name"]').fill(user);
  await modal().getByLabel(zone, { exact: true }).check();
  await save();
  ok("create user with zone grant");
  await page
    .getByRole("button", { name: `为 ${user} 签发令牌`, exact: true })
    .click();
  await modal().locator('[name="name"]').fill("浏览器验收临时令牌");
  await modal().getByRole("button", { name: "生成访问令牌" }).click();
  await expect(
    modal().getByRole("heading", { name: "访问令牌已签发" }),
  ).toBeVisible();
  token = (
    await modal().locator(".secret-block code").last().textContent()
  ).trim();
  expect(token).toHaveLength(43);
  expect(await modal().locator("select option").count()).toBe(1);
  await expect(modal().locator("select")).toHaveValue(env.DNSDOH_DOH_URL);
  await modal().getByRole("button", { name: "我已保存凭据" }).click();
  ok("issue one-time secret and default to the unified DoH entrance");
  // Query a genuine DNS message, without exposing the credential in tool output.
  const labels = Buffer.concat(
    domain
      .split(".")
      .map((s) => Buffer.concat([Buffer.from([s.length]), Buffer.from(s)])),
  );
  const query = Buffer.concat([
    Buffer.from([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]),
    labels,
    Buffer.from([0, 0, 1, 0, 1]),
  ]);
  let response = await context.request.post(`${base}/dns-query/${token}`, {
    data: query,
    headers: { "Content-Type": "application/dns-message" },
  });
  expect(response.status()).toBe(200);
  expect(
    (await response.body()).includes(Buffer.from([192, 0, 2, 89])),
  ).toBeTruthy();
  ok("browser-created token resolves browser-created private address");
  await nav("访问令牌");
  const tokenRow = page
    .getByRole("row")
    .filter({ hasText: "浏览器验收临时令牌" });
  await tokenRow.getByRole("button", { name: "撤销", exact: true }).click();
  await modal().getByRole("button", { name: "确认撤销" }).click();
  await expect(modal()).toHaveCount(0);
  await expect(tokenRow.getByText("已撤销")).toBeVisible();
  response = await context.request.post(`${base}/dns-query/${token}`, {
    data: query,
    headers: { "Content-Type": "application/dns-message" },
  });
  expect(response.status()).toBe(403);
  ok("revoke token in dashboard stops subsequent resolution");
  await nav("DNS 服务器");
  await expect(
    page.getByText("无主控转发", { exact: false }).first(),
  ).toBeVisible();
  await page.getByRole("button", { name: "添加服务器", exact: true }).click();
  await modal().locator('[name="name"]').fill("浏览器验收临时节点");
  await expect(modal().locator('[name="endpoint"]')).toHaveCount(0);
  await expect(
    modal().getByRole("button", { name: "开始自动部署" }),
  ).toBeDisabled();
  const currentState = await (
    await context.request.get(base + "/api/state")
  ).json();
  const probeIP =
    process.env.DNSDOH_TEST_SSH_IP ||
    currentState.nodes.find((n) => n.ip_address && n.enabled)?.ip_address;
  expect(probeIP).toBeTruthy();
  await modal().locator('[name="ip_address"]').fill(probeIP);
  await modal().getByRole("button", { name: "检测 SSH 指纹" }).click();
  await expect(modal().getByText("已匹配保存的服务器指纹")).toBeVisible({
    timeout: 20000,
  });
  await modal().locator("select").nth(1).selectOption("key");
  await expect(modal().locator('[name="private_key"]')).toBeVisible();
  ok(
    "SSH default, saved fingerprint probe and private-key form; no independent HTTPS field",
  );
  await modal().locator('[name="ip_address"]').fill("192.0.2.199");
  await modal().locator('[name="region"]').fill("尚未部署");
  await modal().locator("select").first().selectOption("script");
  await modal().getByRole("button", { name: "生成安装命令" }).click();
  await expect(
    modal().getByRole("heading", { name: "一次性安装命令" }),
  ).toBeVisible();
  await expect(modal().locator("pre")).toContainText("sha256sum --check");
  const installDownloadPromise = page.waitForEvent("download");
  await modal().getByRole("button", { name: "下载安装命令" }).click();
  const installDownload = await installDownloadPromise;
  expect(installDownload.suggestedFilename()).toBe("DNSDOH-节点安装命令.txt");
  await installDownload.delete();
  await modal().getByRole("button", { name: "关闭窗口" }).click();
  await expect(
    page
      .locator(".node-card")
      .filter({ hasText: "浏览器验收临时节点" })
      .getByText("等待安装"),
  ).toBeVisible();
  ok("optional single-use installation command download and waiting status");
  await page
    .locator(".node-card")
    .filter({ hasText: "浏览器验收临时节点" })
    .getByRole("button", { name: "删除", exact: true })
    .click();
  await modal().getByRole("button", { name: "确认删除并清理 DNS" }).click();
  await expect(modal()).toHaveCount(0);
  ok("delete managed server schedules provider record cleanup");
  await page.screenshot({
    path: path.join(output, "nodes-desktop.png"),
    fullPage: true,
  });
  await nav("系统设置");
  await page.locator('[name="token_qps"]').fill("30");
  await page.locator('[name="retention_days"]').fill("14");
  await page.getByRole("button", { name: "保存设置", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("已保存");
  ok("save runtime settings");
  await page.getByRole("button", { name: "修改登录密码" }).click();
  await expect(
    modal().getByRole("heading", { name: "修改登录密码" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(modal()).toHaveCount(0);
  ok("password dialog and keyboard dismissal");
  await nav("操作记录");
  await page.getByRole("textbox", { name: "搜索操作或目标" }).fill(user);
  await expect(page.getByText(user, { exact: true }).first()).toBeVisible();
  ok("audit contains actual management changes");
  await nav("用户管理");
  await page
    .getByRole("button", { name: `删除用户 ${user}`, exact: true })
    .click();
  await modal().getByRole("button", { name: "确认删除" }).click();
  await expect(modal()).toHaveCount(0);
  await nav("域名与记录");
  await page
    .getByRole("button", { name: zone, exact: false })
    .filter({ has: page.locator(".live-dot") })
    .first()
    .click();
  await page.getByRole("button", { name: "删除当前分区" }).click();
  await modal().getByRole("button", { name: "确认删除" }).click();
  await expect(modal()).toHaveCount(0);
  ok("delete fixture user and zone with cascading cleanup");
  await nav("概览");
  await page.waitForTimeout(3700);
  await page.screenshot({
    path: path.join(output, "overview-desktop.png"),
    fullPage: true,
  });
  await noOverflow();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.waitForTimeout(400);
  await noOverflow();
  expect(
    await page
      .locator(".sidebar")
      .evaluate((e) => e.getBoundingClientRect().right),
  ).toBeLessThanOrEqual(0);
  await page.screenshot({
    path: path.join(output, "overview-mobile.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "打开导航" }).click();
  await nav("DNS 服务器");
  await expect(page.locator(".sidebar")).not.toHaveClass(/open/);
  await noOverflow();
  await page.screenshot({
    path: path.join(output, "nodes-mobile.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "添加服务器", exact: true }).click();
  await expect(modal()).toBeVisible();
  await noOverflow();
  await page.screenshot({
    path: path.join(output, "node-form-mobile.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "关闭窗口" }).click();
  ok("390px mobile navigation, cards and modal without page overflow");
  await page.getByRole("button", { name: "打开导航" }).click();
  await nav("域名与记录");
  await noOverflow();
  await page.screenshot({
    path: path.join(output, "records-mobile.png"),
    fullPage: true,
  });
  ok("mobile records table scrolls within its container");
  await page.setViewportSize({ width: 1024, height: 768 });
  await noOverflow();
  await page.screenshot({
    path: path.join(output, "records-tablet.png"),
    fullPage: true,
  });
  ok("1024px tablet layout");
  await page.getByRole("button", { name: "退出登录" }).click();
  await expect(
    page.getByRole("heading", { name: "登录管理控制台" }),
  ).toBeVisible();
  ok("logout returns to login");
  expect(errors).toEqual([]);
  ok("no uncaught browser exceptions");
  fs.writeFileSync(
    path.join(output, "browser-report.json"),
    JSON.stringify(
      {
        passed: checks.length,
        checks,
        viewports: ["1440×1050", "1024×768", "390×844"],
        completed_at: new Date().toISOString(),
      },
      null,
      2,
    ),
  );
  console.log(`ALL ${checks.length} BROWSER CHECKS PASSED`);
} finally {
  try {
    const sr = await context.request.get(base + "/api/session");
    if (sr.ok()) {
      const session = await sr.json();
      const state = await (
        await context.request.get(base + "/api/state")
      ).json();
      for (const [resource, items] of [
        ["users", state.users.filter((x) => x.name === user)],
        ["zones", state.zones.filter((x) => x.name === zone)],
        [
          "managed-nodes",
          state.nodes.filter((x) => x.name === "浏览器验收临时节点"),
        ],
      ]) {
        for (const item of items)
          await context.request.delete(
            base + "/api/" + resource + "/" + item.id,
            { headers: { "X-CSRF-Token": session.csrf } },
          );
      }
    }
  } catch {}
  await browser.close();
}
