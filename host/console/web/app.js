"use strict";

// ---------------------------------------------------------------- 工具
const $ = (s, el = document) => el.querySelector(s);
const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);
const fmtBytes = (n) => {
  n = Number(n) || 0;
  if (n <= 0) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return (n / 1024 ** i).toFixed(i >= 3 ? 2 : i >= 2 ? 1 : 0) + " " + u[i];
};
const fmtPct = (n) => (Number(n) || 0).toFixed(1) + "%";
const fmtDur = (s) => {
  s = Math.max(0, Math.floor(Number(s) || 0));
  const d = Math.floor(s / 86400), h = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  return d ? `${d} 天 ${h} 小时` : h ? `${h} 小时 ${m} 分` : `${m} 分钟`;
};
const ago = (iso) => {
  if (!iso) return "—";
  const t = Date.parse(iso);
  if (!t || t < 86400000) return "—";
  const s = (Date.now() - t) / 1000;
  if (s < 60) return "刚刚";
  if (s < 3600) return Math.floor(s / 60) + " 分钟前";
  if (s < 86400) return Math.floor(s / 3600) + " 小时前";
  return Math.floor(s / 86400) + " 天前";
};
const level = (pct) => (pct >= 90 ? "crit" : pct >= 75 ? "warn" : "ok");
const bar = (pct, mark) => `<div class="bar ${level(pct)}"><span style="width:${Math.min(100, Math.max(0, pct)).toFixed(1)}%"></span>${mark ? `<i class="mark" style="left:${mark}%"></i>` : ""}</div>`;

function toast(msg, err) {
  const el = document.createElement("div");
  el.className = "toast" + (err ? " err" : "");
  el.textContent = msg;
  $("#toasts").append(el);
  setTimeout(() => el.remove(), err ? 6000 : 3500);
}

async function api(path, opts = {}) {
  const res = await fetch(path, { ...opts, headers: { "X-Moon-Console": "1", ...(opts.headers || {}) } });
  if (res.status === 401) { location.href = "/auth/login?next=" + encodeURIComponent(location.pathname + location.hash); throw new Error("未登录"); }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || res.statusText);
  return data;
}

function confirmDialog(title, text, okLabel = "确认", danger = true) {
  const d = $("#confirm");
  $("#confirm-title").textContent = title;
  $("#confirm-text").textContent = text;
  const ok = $("#confirm-ok");
  ok.textContent = okLabel;
  ok.className = "btn " + (danger ? "danger" : "primary");
  d.showModal();
  return new Promise((r) => d.addEventListener("close", () => r(d.returnValue === "ok"), { once: true }));
}

// ---------------------------------------------------------------- 状态显示
function containerPill(c) {
  if (c.state === "running") {
    if (c.health === "unhealthy") return `<span class="pill red">不健康</span>`;
    if (c.health === "starting") return `<span class="pill amber">启动中</span>`;
    return `<span class="pill green">运行中${c.health === "healthy" ? " · 健康" : ""}</span>`;
  }
  if (c.state === "restarting") return `<span class="pill amber">重启中</span>`;
  if (c.state === "exited") return `<span class="pill gray">已停止</span>`;
  return `<span class="pill gray">${esc(c.state)}</span>`;
}
function servicePill(s) {
  const map = { active: ["green", "运行中"], failed: ["red", "失败"], inactive: ["gray", "未运行"], activating: ["amber", "启动中"], deactivating: ["amber", "停止中"], reloading: ["blue", "重载中"] };
  const [c, t] = map[s.active] || ["gray", s.active];
  return `<span class="pill ${c}">${t}${s.active === "active" && s.sub !== "running" ? " · " + esc(s.sub) : ""}</span>`;
}
const managedTag = { cicd: `<span class="tag cicd">CI/CD</span>`, platform: `<span class="tag platform">平台</span>`, "podman-systemd": `<span class="tag">systemd</span>`, manual: `<span class="tag">手动</span>` };

// ---------------------------------------------------------------- 视图
const views = {};
const state = { containerFilter: "", containerScope: "all", serviceFilter: "", serviceScope: "all" };

views.overview = {
  title: "概览",
  async load() {
    const o = await api("/api/overview");
    $("#host-name").textContent = o.host.name;
    const memUsed = o.memory.total - o.memory.available;
    const memPct = (memUsed / o.memory.total) * 100;
    const diskPct = (o.disk.used / o.disk.total) * 100;
    const swapUsed = o.memory.swap_total - o.memory.swap_free;
    const swapPct = o.memory.swap_total ? (swapUsed / o.memory.swap_total) * 100 : 0;
    const c = o.counts;
    const slices = o.slices.map((s) => {
      const cap = s.max > 0 ? s.max : s.high > 0 ? s.high : o.memory.total;
      const pct = (s.current / cap) * 100;
      const mark = s.high > 0 && s.max > 0 ? (s.high / s.max) * 100 : 0;
      const limits = s.max > 0 ? `上限 ${fmtBytes(s.max)}${s.high > 0 ? ` · 软上限 ${fmtBytes(s.high)}` : ""}` : "无上限";
      return `<div class="slice-row"><div class="slice-top"><span><b>${esc(s.label)}</b> <span class="muted mono">${esc(s.name)}</span></span><span><b>${fmtBytes(s.current)}</b> <span class="muted">/ ${limits}</span></span></div>${bar(pct, mark)}</div>`;
    }).join("");
    const alerts = o.alerts && o.alerts.length ? `<ul class="alerts">${o.alerts.slice().reverse().map((a) => `<li>${esc(a)}</li>`).join("")}</ul>` : `<div class="empty">最近没有告警</div>`;
    return `
      ${o.security.reboot_required ? `<div class="notice warn">内核已更新，等待维护窗口重启后生效。</div>` : ""}
      <div class="grid kpis">
        <div class="card card-pad kpi"><div class="label">CPU（${o.host.cpus} 核）</div><div class="value">${fmtPct(o.host.cpu_pct)}</div><div class="sub">负载 ${o.host.load.map(esc).join(" / ")}</div>${bar(o.host.cpu_pct)}</div>
        <div class="card card-pad kpi"><div class="label">内存</div><div class="value">${fmtBytes(memUsed)}</div><div class="sub">共 ${fmtBytes(o.memory.total)} · 可用 ${fmtBytes(o.memory.available)}</div>${bar(memPct)}</div>
        <div class="card card-pad kpi"><div class="label">磁盘（/）</div><div class="value">${fmtPct(diskPct)}</div><div class="sub">已用 ${fmtBytes(o.disk.used)} · 剩余 ${fmtBytes(o.disk.avail)}</div>${bar(diskPct)}</div>
        <div class="card card-pad kpi"><div class="label">zram 压缩交换</div><div class="value">${fmtBytes(swapUsed)}</div><div class="sub">共 ${fmtBytes(o.memory.swap_total)}</div>${bar(swapPct)}</div>
      </div>
      <div class="grid kpis">
        <div class="card card-pad kpi"><div class="label">容器</div><div class="value">${c.running} <span class="muted small">/ ${c.containers}</span></div><div class="sub">${c.unhealthy ? `<span class="pill red">${c.unhealthy} 个异常</span>` : `<span class="pill green">全部正常</span>`}</div></div>
        <div class="card card-pad kpi"><div class="label">宿主服务</div><div class="value">${c.services_active} <span class="muted small">/ ${c.services}</span></div><div class="sub">${c.services_failed ? `<span class="pill red">${c.services_failed} 个失败</span>` : `<span class="pill green">无失败</span>`}</div></div>
        <div class="card card-pad kpi"><div class="label">运行时长</div><div class="value">${fmtDur(o.host.uptime_s)}</div><div class="sub mono">${esc(o.host.kernel)}</div></div>
        <div class="card card-pad kpi"><div class="label">防火墙</div><div class="value">${o.security.firewall === "active" ? "已启用" : "未启用"}</div><div class="sub">${o.security.firewall === "active" ? `<span class="pill green">默认拒绝入站</span>` : `<span class="pill red">请检查 moon-firewall</span>`}</div></div>
      </div>
      <div class="grid two">
        <div class="card"><div class="card-head"><h2>资源切片</h2><span class="muted small">竖线为软上限</span></div><div class="slices">${slices}</div></div>
        <div class="card"><div class="card-head"><h2>最近告警</h2><span class="muted small">磁盘、内存、OOM</span></div>${alerts}</div>
      </div>`;
  },
};

function filterBar(kind, scopes) {
  const st = state[kind + "Scope"];
  return `<div class="toolbar"><input type="search" placeholder="搜索名称…" value="${esc(state[kind + "Filter"])}" data-filter="${kind}">
    <div class="seg">${scopes.map(([k, t]) => `<button data-scope="${kind}" data-value="${k}" class="${st === k ? "on" : ""}">${t}</button>`).join("")}</div></div>`;
}

views.containers = {
  title: "容器",
  async load() {
    const d = await api("/api/containers");
    const q = state.containerFilter.toLowerCase();
    let list = d.containers || [];
    if (state.containerScope !== "all") list = list.filter((c) => (state.containerScope === "running" ? c.state === "running" : c.runtime === state.containerScope));
    if (q) list = list.filter((c) => (c.name + " " + c.project + " " + c.image).toLowerCase().includes(q));
    let lastProject = null;
    const rows = list.map((c) => {
      const head = c.project !== lastProject ? `<tr class="group-row"><td colspan="7">${esc(c.project || "独立容器")}</td></tr>` : "";
      lastProject = c.project;
      const memPct = c.mem_limit > 0 ? (c.mem_bytes / c.mem_limit) * 100 : 0;
      const running = c.state === "running";
      return `${head}<tr>
        <td class="name-cell">${esc(c.name)}<div class="muted small mono">${esc(c.image.length > 64 ? c.image.slice(0, 64) + "…" : c.image)}</div></td>
        <td>${containerPill(c)}<div class="muted small">${running ? "启动于 " + ago(c.started_at) : esc(c.status)}${c.restarts ? ` · 重启 ${c.restarts} 次` : ""}</div></td>
        <td><span class="tag">${esc(c.runtime)}</span> ${managedTag[c.managed] || ""}</td>
        <td class="num">${running ? fmtPct(c.cpu_pct) : "—"}</td>
        <td class="num">${running ? fmtBytes(c.mem_bytes) : "—"}${c.mem_limit > 0 ? `<div class="muted small">/ ${fmtBytes(c.mem_limit)} (${memPct.toFixed(0)}%)</div>` : ""}</td>
        <td class="mono small">${esc(c.ports) || "—"}</td>
        <td><div class="actions">
          <button class="btn small" data-logs="container" data-rt="${esc(c.runtime)}" data-id="${esc(c.id)}" data-name="${esc(c.name)}">日志</button>
          ${running ? `<button class="btn small" data-act="restart" data-rt="${esc(c.runtime)}" data-id="${esc(c.id)}" data-name="${esc(c.name)}">重启</button>
          <button class="btn small" data-act="stop" data-rt="${esc(c.runtime)}" data-id="${esc(c.id)}" data-name="${esc(c.name)}">停止</button>`
          : `<button class="btn small primary" data-act="start" data-rt="${esc(c.runtime)}" data-id="${esc(c.id)}" data-name="${esc(c.name)}">启动</button>`}
        </div></td></tr>`;
    }).join("");
    return `${d.error ? `<div class="error-box">读取容器失败：${esc(d.error)}</div>` : ""}
      <div class="card"><div class="card-head"><h2>全部容器 <span class="muted small">${list.length}</span></h2>${filterBar("container", [["all", "全部"], ["running", "运行中"], ["docker", "Docker"], ["podman", "podman"]])}</div>
      <div class="table-wrap"><table><thead><tr><th>名称 / 镜像</th><th>状态</th><th>来源</th><th class="num">CPU</th><th class="num">内存</th><th>端口</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="7" class="empty">没有匹配的容器</td></tr>`}</tbody></table></div></div>`;
  },
};

views.services = {
  title: "宿主服务",
  async load() {
    const d = await api("/api/services");
    const q = state.serviceFilter.toLowerCase();
    let list = d.services || [];
    if (state.serviceScope !== "all") list = list.filter((s) => (state.serviceScope === "failed" ? s.active === "failed" : s.category === state.serviceScope));
    if (q) list = list.filter((s) => (s.unit + " " + s.description).toLowerCase().includes(q));
    const order = { failed: 0, active: 1, activating: 1, inactive: 2 };
    list.sort((a, b) => (order[a.active] ?? 3) - (order[b.active] ?? 3) || a.unit.localeCompare(b.unit));
    const cat = { app: "应用", infra: "基础设施", ops: "运维" };
    const rows = list.map((s) => `<tr>
      <td class="name-cell">${esc(s.unit)}<div class="muted small">${esc(s.description)}</div></td>
      <td>${servicePill(s)}${s.restarts ? `<div class="muted small">自动重启 ${s.restarts} 次</div>` : ""}</td>
      <td><span class="tag">${cat[s.category] || esc(s.category)}</span></td>
      <td class="num">${s.active === "active" ? fmtPct(s.cpu_pct) : "—"}</td>
      <td class="num">${s.mem_bytes > 0 ? fmtBytes(s.mem_bytes) : "—"}</td>
      <td class="small muted">${esc(s.since || "—")}</td>
      <td><div class="actions">
        <button class="btn small" data-logs="service" data-unit="${esc(s.unit)}" data-name="${esc(s.unit)}">日志</button>
        ${s.active === "active" ? `<button class="btn small" data-sact="restart" data-unit="${esc(s.unit)}">重启</button>${s.protected ? "" : `<button class="btn small" data-sact="stop" data-unit="${esc(s.unit)}">停止</button>`}`
          : `<button class="btn small primary" data-sact="start" data-unit="${esc(s.unit)}">启动</button>`}
      </div></td></tr>`).join("");
    return `<div class="card"><div class="card-head"><h2>systemd 服务 <span class="muted small">${list.length}</span></h2>${filterBar("service", [["all", "全部"], ["app", "应用"], ["infra", "基础设施"], ["ops", "运维"], ["failed", "失败"]])}</div>
      <div class="table-wrap"><table><thead><tr><th>服务</th><th>状态</th><th>类别</th><th class="num">CPU</th><th class="num">内存</th><th>启动时间</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="7" class="empty">没有匹配的服务</td></tr>`}</tbody></table></div></div>`;
  },
};

views.projects = {
  title: "部署项目",
  async load() {
    const d = await api("/api/projects");
    const ps = d.projects || [];
    if (!ps.length) return `<div class="card empty">还没有通过 CI/CD 部署的项目。推送到 main 即自动部署，规则见 HinaKalo/moon-infra。</div>`;
    const budget = ps.reduce((a, p) => a + (p.mem_budget || 0), 0);
    return `<div class="notice">推送到 <b>main</b> 分支即自动构建并部署。已分配内存预算合计 <b>${fmtBytes(budget)}</b>。</div>` + ps.map((p) => {
      const cs = (p.containers || []).map((c) => `<span style="margin-right:10px">${containerPill(c)} <span class="mono small">${esc(c.name)}</span></span>`).join("") || `<span class="muted">无容器</span>`;
      const hist = (p.history || []).map((h) => `<tr><td class="small">${esc(h.at ? new Date(h.at).toLocaleString() : "—")}</td>
        <td>${h.result === "ok" ? `<span class="pill green">成功</span>` : `<span class="pill red">失败</span>`}</td>
        <td class="mono small">${esc((h.sha || "").slice(0, 10))}</td><td class="small">${esc(h.actor)}</td><td class="num small">${h.seconds || 0}s</td>
        <td class="small">${h.error ? esc(h.error) : ""}${p.repo && h.run_id ? ` <a href="https://github.com/${esc(p.repo)}/actions/runs/${esc(h.run_id)}" target="_blank" rel="noopener">运行记录</a>` : ""}</td></tr>`).join("");
      return `<div class="card"><div class="card-head"><div><h2>${esc(p.name)}</h2><div class="muted small">${p.repo ? `<a href="https://github.com/${esc(p.repo)}" target="_blank" rel="noopener">${esc(p.repo)}</a>` : ""}</div></div>
        <div class="toolbar">${p.domain ? `<a class="btn small" href="https://${esc(p.domain)}" target="_blank" rel="noopener">${esc(p.domain)} ↗</a>` : ""}</div></div>
        <dl class="kv"><dt>容器</dt><dd>${cs}</dd><dt>端口</dt><dd class="mono">${p.port ? "127.0.0.1:" + p.port : "—"}</dd>
        <dt>内存</dt><dd>实际 ${fmtBytes(p.mem_used)} / 预算 ${fmtBytes(p.mem_budget)}</dd><dt>最近部署</dt><dd>${ago(p.deployed_at)}</dd>
        <dt>镜像</dt><dd class="mono small">${esc(p.image || "—")}</dd></dl>
        ${hist ? `<div class="table-wrap"><table><thead><tr><th>时间</th><th>结果</th><th>提交</th><th>触发者</th><th class="num">耗时</th><th>说明</th></tr></thead><tbody>${hist}</tbody></table></div>` : ""}</div>`;
    }).join("");
  },
};

views.databases = {
  title: "数据库",
  async load() {
    const d = await api("/api/databases");
    const pg = d.postgres || {}, vk = d.valkey || {};
    const dbs = (pg.databases || []).map((x) => `<tr><td class="name-cell mono">${esc(x.name)}</td><td class="num">${fmtBytes(x.size)}</td><td class="num">${x.connections}</td></tr>`).join("");
    const ks = Object.entries(vk.keyspace || {}).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="mono small">${esc(v)}</td></tr>`).join("");
    const bks = (d.backups || []).slice(0, 14).map((b) => `<tr><td class="mono small">${esc(b.name)}</td><td class="num">${fmtBytes(b.size)}</td><td class="small">${ago(b.at)}</td></tr>`).join("");
    const vkPct = Number(vk.maxmemory) > 0 ? (Number(vk.used_memory) / Number(vk.maxmemory)) * 100 : 0;
    return `<div class="grid two">
      <div class="card"><div class="card-head"><h2>PostgreSQL（共享）</h2><span class="tag platform">${esc(pg.container)}</span></div>
        ${pg.error ? `<div class="error-box" style="margin:0 20px 16px">${esc(pg.error)}</div>` : `
        <dl class="kv"><dt>版本</dt><dd>${esc(pg.version)}</dd><dt>连接</dt><dd>${esc(pg.connections)} / ${esc(pg.max_connections)}</dd>
        <dt>缓存命中率</dt><dd>${esc(pg.cache_hit_pct)}%</dd><dt>运行时长</dt><dd>${fmtDur(pg.uptime_s)}</dd></dl>
        <div class="table-wrap"><table><thead><tr><th>数据库</th><th class="num">大小</th><th class="num">连接</th></tr></thead><tbody>${dbs}</tbody></table></div>`}</div>
      <div class="card"><div class="card-head"><h2>Valkey（共享缓存）</h2><span class="tag platform">${esc(vk.container)}</span></div>
        ${vk.error ? `<div class="error-box" style="margin:0 20px 16px">${esc(vk.error)}</div>` : `
        <dl class="kv"><dt>版本</dt><dd>${esc(vk.valkey_version)}</dd><dt>内存</dt><dd>${esc(vk.used_memory_human)} / ${esc(vk.maxmemory_human)}（${esc(vk.maxmemory_policy)}）</dd>
        <dt>客户端</dt><dd>${esc(vk.connected_clients)}</dd><dt>运行时长</dt><dd>${fmtDur(vk.uptime_in_seconds)}</dd></dl>
        <div style="padding:0 20px 14px">${bar(vkPct)}</div>
        ${ks ? `<div class="table-wrap"><table><thead><tr><th>库</th><th>键统计</th></tr></thead><tbody>${ks}</tbody></table></div>` : `<div class="empty">暂无数据</div>`}`}</div>
    </div>
    <div class="card"><div class="card-head"><h2>备份</h2><span class="muted small">每日 03:30 全量备份，保留 14 天</span></div>
      ${bks ? `<div class="table-wrap"><table><thead><tr><th>文件</th><th class="num">大小</th><th>时间</th></tr></thead><tbody>${bks}</tbody></table></div>` : `<div class="empty">没有可读取的备份</div>`}</div>`;
  },
};

views.disk = {
  title: "磁盘",
  async load() {
    const d = await api("/api/disk");
    const pct = d.disk.percent;
    const cats = (d.categories || []).slice().sort((a, b) => b.bytes - a.bytes);
    const maxCat = Math.max(1, ...cats.map((c) => c.bytes));
    const rows = cats.map((c) => `<div class="slice-row"><div class="slice-top"><span class="mono">${esc(c.path)}</span><b>${fmtBytes(c.bytes)}</b></div>${bar((c.bytes / maxCat) * 100)}</div>`).join("");
    const lc = d.last_clean;
    return `<div class="grid kpis">
        <div class="card card-pad kpi"><div class="label">根分区</div><div class="value">${pct}%</div><div class="sub">已用 ${fmtBytes(d.disk.used)} / ${fmtBytes(d.disk.total)}</div>${bar(pct)}</div>
        <div class="card card-pad kpi"><div class="label">剩余空间</div><div class="value">${fmtBytes(d.disk.avail)}</div><div class="sub">≥80% 推送提醒 · ≥85% 自动紧急清理</div></div>
        <div class="card card-pad kpi"><div class="label">上次清理</div><div class="value">${lc ? fmtBytes(lc.freed_bytes) : "—"}</div><div class="sub">${lc ? `${ago(lc.at)} · ${lc.items} 项` : "尚未运行"}</div></div>
      </div>
      <div class="grid two">
        <div class="card"><div class="card-head"><h2>空间分布</h2><span class="muted small">每日清理时统计</span></div><div class="slices">${rows}</div></div>
        <div class="card"><div class="card-head"><h2>清理策略</h2><button class="btn primary small" id="disk-clean" ${d.clean_running ? "disabled" : ""}>${d.clean_running ? "清理中…" : "立即清理"}</button></div>
          <dl class="kv"><dt>/tmp</dt><dd>超过 3 天未修改且无进程使用</dd><dt>/var/tmp</dt><dd>超过 14 天未修改且无进程使用</dd>
          <dt>发布目录</dt><dd>保留 current 与最新 3 个版本</dd><dt>镜像</dt><dd>3 天未使用的 Docker 镜像、悬空 podman 镜像</dd>
          <dt>apt 缓存</dt><dd>超过 300MB 时清空</dd><dt>日志</dt><dd>journald 上限 1G</dd>
          <dt>安全规则</dt><dd>任何被进程打开、作为工作目录或可执行文件的路径一律不删</dd></dl></div>
      </div>`;
  },
};

// ---------------------------------------------------------------- 路由与刷新
let current = "overview", timer = null, loading = false;

async function render() {
  const v = views[current];
  if (!v || loading) return;
  loading = true;
  try {
    const html = await v.load();
    const active = document.activeElement;
    const filterKey = active && active.dataset ? active.dataset.filter : null;
    const caret = filterKey ? active.selectionStart : null;
    $("#view").innerHTML = html;
    if (filterKey) { const el = $(`[data-filter="${filterKey}"]`); if (el) { el.focus(); el.setSelectionRange(caret, caret); } }
    $("#updated").textContent = "更新于 " + new Date().toLocaleTimeString();
    $("#live").classList.remove("stale");
  } catch (e) {
    $("#live").classList.add("stale");
    if (!$("#view").innerHTML) $("#view").innerHTML = `<div class="error-box">${esc(e.message)}</div>`;
  } finally {
    loading = false;
  }
}

function route() {
  const name = (location.hash.replace(/^#\//, "") || "overview").split("?")[0];
  current = views[name] ? name : "overview";
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === current));
  $("#title").textContent = views[current].title;
  document.title = views[current].title + " · Moon Console";
  $("#view").innerHTML = "";
  render();
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) render(); }, 5000);
}

// ---------------------------------------------------------------- 交互
document.addEventListener("input", (e) => {
  const k = e.target.dataset.filter;
  if (k) { state[k + "Filter"] = e.target.value; render(); }
});

document.addEventListener("click", async (e) => {
  const t = e.target.closest("button");
  if (!t) return;
  if (t.dataset.scope) { state[t.dataset.scope + "Scope"] = t.dataset.value; render(); return; }
  if (t.dataset.logs) { openLogs(t.dataset); return; }
  if (t.dataset.act) {
    const { act, rt, id, name } = t.dataset;
    const label = { start: "启动", stop: "停止", restart: "重启" }[act];
    if (act !== "start" && !(await confirmDialog(`${label}容器`, `确定要${label} ${name} 吗？`, label))) return;
    t.disabled = true;
    try { await api(`/api/containers/${rt}/${id}/${act}`, { method: "POST" }); toast(`已${label} ${name}`); }
    catch (err) { toast(`${label}失败：${err.message}`, true); }
    render();
    return;
  }
  if (t.dataset.sact) {
    const { sact, unit } = t.dataset;
    const label = { start: "启动", stop: "停止", restart: "重启" }[sact];
    if (sact !== "start" && !(await confirmDialog(`${label}服务`, `确定要${label} ${unit} 吗？`, label))) return;
    t.disabled = true;
    try { await api(`/api/services/${encodeURIComponent(unit)}/${sact}`, { method: "POST" }); toast(`已${label} ${unit}`); }
    catch (err) { toast(`${label}失败：${err.message}`, true); }
    render();
    return;
  }
  if (t.id === "disk-clean") {
    if (!(await confirmDialog("立即清理磁盘", "按保留策略清理临时文件、旧发布与无用镜像，正在使用的文件不会被删除。", "开始清理", false))) return;
    try { await api("/api/disk/clean", { method: "POST" }); toast("已开始清理，完成后数据会自动刷新"); } catch (err) { toast(err.message, true); }
    render();
  }
});

$("#logout").addEventListener("click", async () => {
  try { const r = await api("/auth/logout", { method: "POST" }); location.href = r.redirect || "/"; } catch { location.href = "/"; }
});

// ---------------------------------------------------------------- 日志抽屉
let es = null, logTarget = null;
function openLogs(ds) {
  logTarget = ds;
  $("#drawer-title").textContent = ds.name;
  $("#drawer-sub").textContent = ds.logs === "container" ? `${ds.rt} 容器日志` : "systemd 日志（journalctl）";
  $("#drawer").classList.add("open");
  $("#drawer").setAttribute("aria-hidden", "false");
  connectLogs();
}
function connectLogs() {
  if (es) es.close();
  const logs = $("#logs");
  logs.innerHTML = "";
  const follow = $("#follow").checked ? 1 : 0;
  const ds = logTarget;
  const url = ds.logs === "container" ? `/api/containers/${ds.rt}/${ds.id}/logs?tail=500&follow=${follow}` : `/api/services/${encodeURIComponent(ds.unit)}/logs?tail=500&follow=${follow}`;
  es = new EventSource(url);
  const filter = () => $("#log-filter").value.toLowerCase();
  const add = (cls) => (ev) => {
    const f = filter();
    if (f && !ev.data.toLowerCase().includes(f)) return;
    const atBottom = logs.scrollHeight - logs.scrollTop - logs.clientHeight < 40;
    const line = document.createElement("div");
    if (cls) line.className = cls;
    const m = ev.data.match(/^(\d{4}-\d\d-\d\dT[\d:.]+Z?|\d{4}-\d\d-\d\dT[\d:+-]+)\s(.*)$/);
    if (m) { const ts = document.createElement("span"); ts.className = "ts"; ts.textContent = m[1].slice(0, 19).replace("T", " ") + "  "; line.append(ts, m[2]); }
    else line.textContent = ev.data;
    logs.append(line);
    while (logs.childElementCount > 5000) logs.firstChild.remove();
    if (atBottom) logs.scrollTop = logs.scrollHeight;
  };
  es.addEventListener("stdout", add(""));
  es.addEventListener("line", add(""));
  es.addEventListener("stderr", add("err"));
  es.addEventListener("error", (ev) => { if (ev.data) add("err")(ev); });
  es.addEventListener("end", () => { es.close(); es = null; });
}
function closeLogs() {
  if (es) es.close();
  es = null;
  $("#drawer").classList.remove("open");
  $("#drawer").setAttribute("aria-hidden", "true");
}
$("#drawer-close").addEventListener("click", closeLogs);
$("#follow").addEventListener("change", () => logTarget && connectLogs());
$("#log-filter").addEventListener("input", () => logTarget && connectLogs());
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && $("#drawer").classList.contains("open")) closeLogs(); });

// ---------------------------------------------------------------- 启动
(async () => {
  try {
    const me = await api("/api/me");
    $("#user-name").textContent = me.username || me.name || "管理员";
    $("#avatar").textContent = (me.username || "?").slice(0, 1).toUpperCase();
  } catch {}
  window.addEventListener("hashchange", route);
  route();
})();
