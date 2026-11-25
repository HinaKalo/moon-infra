#!/usr/bin/env bash
# 安装/升级 moon-console 与 moon-deployd（root 运行，可重复执行）
# 用法: install.sh <源码根目录，含 console/ 与 deployd/>
set -euo pipefail
SRC=${1:-$(cd "$(dirname "$0")/.." && pwd)}
GO=/usr/local/go/bin/go

echo "== 构建"
( cd "$SRC/deployd" && [ -f go.mod ] || $GO mod init moon-deployd >/dev/null 2>&1; cd "$SRC/deployd" && $GO vet -buildvcs=false ./... && CGO_ENABLED=0 $GO build -buildvcs=false -trimpath -ldflags "-s -w" -o /tmp/moon-deployd.new . )
( cd "$SRC/console" && [ -f go.mod ] || $GO mod init moon-console >/dev/null 2>&1; cd "$SRC/console" && $GO vet -buildvcs=false ./... && CGO_ENABLED=0 $GO build -buildvcs=false -trimpath -ldflags "-s -w" -o /tmp/moon-console.new . )
install -m 755 /tmp/moon-deployd.new /usr/local/bin/moon-deployd
install -m 755 /tmp/moon-console.new /usr/local/bin/moon-console
rm -f /tmp/moon-deployd.new /tmp/moon-console.new

echo "== 系统用户与权限"
id moonconsole >/dev/null 2>&1 || useradd --system --home-dir /var/lib/moon-console --shell /usr/sbin/nologin moonconsole
usermod -aG docker,systemd-journal,deployer moonconsole
install -d -m 700 -o moonconsole -g moonconsole /var/lib/moon-console
chown root:moonconsole /etc/moon-console /etc/moon-console/oidc.env
chmod 750 /etc/moon-console; chmod 640 /etc/moon-console/oidc.env
# 只允许列出备份文件名与大小（备份内容本身仍是 root 600）
chmod 711 /srv/platform
chgrp moonconsole /srv/platform/backups && chmod 750 /srv/platform/backups
# 部署记录、端口、预算文件供面板读取（凭据 platform.env、compose.resolved.json 仍为 600）
find /srv/apps -mindepth 2 -maxdepth 2 \( -name history.jsonl -o -name app.port -o -name .moon-mem -o -name .env \) -exec chmod 640 {} +

# rootful podman API 套接字：允许 docker 组访问（docker 组本身已等同 root）
mkdir -p /etc/systemd/system/podman.socket.d
cat > /etc/systemd/system/podman.socket.d/50-moon-console.conf <<'X'
[Socket]
SocketGroup=docker
SocketMode=0660
X

cat > /etc/sudoers.d/92-moonconsole <<'X'
# moon-console：服务启停（面板内仅对已知服务生效，关键服务只允许重启）与磁盘清理
moonconsole ALL=(root) NOPASSWD: /usr/bin/systemctl start *, /usr/bin/systemctl stop *, /usr/bin/systemctl restart *
moonconsole ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block moon-diskguard-clean.service
X
chmod 440 /etc/sudoers.d/92-moonconsole
visudo -cf /etc/sudoers.d/92-moonconsole

echo "== systemd"
cat > /etc/systemd/system/moon-console.service <<'X'
[Unit]
Description=moon-console (operations panel)
After=network-online.target docker.service
Wants=network-online.target

[Service]
User=moonconsole
Group=moonconsole
SupplementaryGroups=docker systemd-journal deployer
EnvironmentFile=/etc/moon-console/oidc.env
Environment=CONSOLE_LISTEN=127.0.0.1:19710 CONSOLE_PUBLIC_URL=https://console.moonl.cloud
ExecStart=/usr/local/bin/moon-console
Restart=always
RestartSec=3
ProtectHome=true
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictRealtime=true
LockPersonality=true
MemoryMax=256M

[Install]
WantedBy=multi-user.target
X
systemctl daemon-reload
systemctl restart podman.socket
systemctl enable moon-console >/dev/null 2>&1
systemctl restart moon-deployd moon-console
sleep 2
curl -fsS http://127.0.0.1:19700/healthz
curl -fsS http://127.0.0.1:19710/healthz

echo "== Caddy"
cat > /etc/caddy/moon-console.caddy <<'X'
console.moonl.cloud {
	encode zstd gzip
	header {
		Strict-Transport-Security "max-age=63072000; includeSubDomains"
		X-Content-Type-Options nosniff
		Referrer-Policy no-referrer
		-Server
	}
	reverse_proxy 127.0.0.1:19710 {
		flush_interval -1
	}
}
X
grep -qxF 'import /etc/caddy/moon-console.caddy' /etc/caddy/Caddyfile || printf 'import /etc/caddy/moon-console.caddy\n' >> /etc/caddy/Caddyfile
sudo -u caddy /usr/bin/caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile 2>&1 | tail -1
systemctl reload caddy
echo "== 完成"
