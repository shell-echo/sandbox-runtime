# Docker 应用部署

[English](docker.md)

本文说明如何使用 Docker 构建和运行 `sandbox-runtime` 应用本身。它不会把
Docker 自动变成沙箱执行后端。以下命令刻意使用内存 Fake Runtime，并且只开放
本地管理 API。

跨平台边界和支持矩阵参见[应用部署](deployment.zh-CN.md)。

## 已验证范围

仓库 Smoke Test 验证：

1. 根目录 `Dockerfile` 可以构建 Linux 应用镜像；
2. 镜像声明数字用户和用户组 `1000:1000`；
3. 容器使用只读根文件系统，删除全部 Linux capabilities，并禁止权限提升；
4. `8080` 端口只发布到宿主机回环地址；
5. `/health` 成功；
6. 可以创建并列出一个本地 Fake Instance。

它不验证受保护 Provider API、Docker 沙箱执行、多控制器、敌对多租户隔离或
生产就绪。

## 前置条件

- Docker CLI 和可访问的 Linux Docker Engine；
- `curl`；
- 一个空闲的回环 TCP 端口，默认使用 `18081`。

## 运行 Smoke Test

```bash
./scripts/docker-smoke.sh
```

脚本使用唯一的镜像标签和容器名，无论成功还是失败都会清理。如需保留镜像：

```bash
SANDBOX_RUNTIME_DOCKER_SMOKE_KEEP_IMAGE=1 \
  ./scripts/docker-smoke.sh
```

如需更换回环端口：

```bash
SANDBOX_RUNTIME_DOCKER_SMOKE_PORT=28081 \
  ./scripts/docker-smoke.sh
```

## 手动开发部署

```bash
docker build --tag sandbox-runtime:local .

docker run --rm \
  --name sandbox-runtime \
  --publish 127.0.0.1:8080:8080 \
  --env SANDBOX_RUNTIME_APPLICATION_MODE=development \
  --env SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0 \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  sandbox-runtime:local
```

在另一个终端中执行：

```bash
curl --fail http://127.0.0.1:8080/health
```

本地 `/instances` API 没有最终用户认证，不能把该端口发布到不受信任的网络。
受保护 Provider 部署需要单独配置凭据、持久状态、调用方身份和 Gateway。

## Docker 沙箱后端属于另一条能力链路

上述应用容器没有挂载 Docker Socket。挂载宿主机 Docker Socket 会赋予应用对
宿主机 Daemon 的大范围控制权，不属于本应用部署 Smoke Test。Docker Provider
能力必须使用经过独立审查的配置和集成测试。
