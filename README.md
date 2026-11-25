# moon-infra

moon 服务器的中央 CI/CD。任何仓库推送到 `main` 即自动构建镜像并部署到 moon。

## 新项目接入

最省事：用模板创建仓库

```bash
gh repo create HinaKalo/<名称> --private --template HinaKalo/moon-app-template --clone
```

手动接入需要三个文件：

**`.github/workflows/deploy.yml`**

```yaml
name: Deploy
on:
  push:
    branches: [main]
  workflow_dispatch:
concurrency:
  group: moon-deploy
  cancel-in-progress: false
jobs:
  moon:
    if: ${{ !github.event.repository.is_template }}
    uses: HinaKalo/moon-infra/.github/workflows/deploy.yml@main
    permissions:
      contents: read
      packages: write
      id-token: write
```

**`Dockerfile`**：构建应用镜像。

**`compose.yaml`**：

```yaml
x-moon:
  upstream: 127.0.0.1:18100      # 公网入口，自动获得 https://<仓库名>.moonl.cloud
  # domain: other.moonl.cloud   # 可选：自定义子域名
  needs: [postgres, redis]       # 可选：共享平台，自动注入 DATABASE_URL / REDIS_URL

services:
  app:
    image: ${IMAGE}              # CI 构建的镜像，部署时自动填入
    ports: ["127.0.0.1:18100:8080"]
    mem_limit: 256m
    healthcheck:
      test: ["CMD", "/app", "-healthcheck"]
      interval: 10s
```

## moon 上的规则（moon-deployd 强制执行）

| 规则 | 说明 |
|---|---|
| 固定项目名 | compose 项目名 = 仓库名；每次部署原地替换，自动清理残留容器，不会重复启动 |
| 串行部署 | 全机一次只部署一个项目 |
| 内存上限 | 未声明 `mem_limit` 的服务默认 512M；所有项目合计不超过 2900M，超出拒绝部署 |
| 硬上限 | 所有 Docker 容器位于 `moonapps.slice`：总内存 4G、不使用 swap |
| 数据库 | 禁止自带 postgres/mysql/redis/mongo 镜像，使用 `needs` 共享平台（每项目独立库与账号） |
| 端口 | 只能绑定 `127.0.0.1`，公网流量统一经 Caddy HTTPS |
| 挂载 | 只能挂载命名卷或项目目录内路径 |
| 失败回滚 | 健康检查不通过自动回滚到上一个版本，GitHub 显示失败 |

应用私密配置（API Key 等）放在 moon 的 `/srv/apps/<名称>/secrets.env`，在 compose 中写 `env_file: [secrets.env]`。

## moon 上的组件

- `moon-deployd`：部署代理（`systemctl status moon-deployd`），入口 `https://deploy.moonl.cloud`
- `/srv/platform`：共享 Postgres 17（`moon-postgres`）与 Valkey 8（`moon-valkey`）
- `/srv/apps/<名称>`：各项目部署目录；`platform.env` 为自动生成的数据库凭据
- 定时任务：`moon-pg-backup.timer`（每日 03:30，保留 14 天）、`moon-docker-gc.timer`（每日清理 3 天前未用镜像）
