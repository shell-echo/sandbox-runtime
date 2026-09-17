# Apple Container

[English](apple-container.md)

本文说明如何通过 Apple Container 构建并运行 `sandbox-runtime` 应用本身。
它不描述 Apple Container 沙箱后端，也不授权实现这样的后端。

跨平台部署边界和当前支持矩阵参见[应用部署](deployment.zh-CN.md)。

## 支持范围

仓库中的 Dockerfile 会构建包含 `sandbox-runtime` 服务的 Linux OCI
镜像。本地 Smoke Test 验证 Apple Container 能够：

1. 把该 Dockerfile 构建为 Linux `arm64` OCI 镜像；
2. 以非 root 容器启动该镜像；
3. 把本地管理 API 发布到宿主机回环端口；
4. 成功访问 `/health`；
5. 通过默认内存 Fake Runtime 创建并查询一个实例。

这只是本地应用打包证据，不证明受保护 Provider 接口、依赖 Docker 的
exec、terminal、artifact、Browser、多控制器、Kubernetes、生产部署或敌对
多租户隔离能力。

## 前置条件

- Apple silicon；
- Apple Container 支持的 macOS 版本；
- Apple Container 已安装并处于运行状态；
- `curl`；
- 首次下载内核和镜像时可以访问网络。

检查环境：

```bash
container --version
container system status
```

如果 Apple Container 提示没有配置默认 `arm64` 内核，需要执行一次：

```bash
container system kernel set --recommended
```

该命令会修改当前用户的 Apple Container 配置并下载体积较大的外部内核
归档，因此仓库脚本不会自动执行它。

## 自动 Smoke Test

在仓库根目录运行：

```bash
./scripts/apple-container-smoke.sh
```

脚本默认占用宿主机端口 `18080`。端口已被占用时可以指定其他端口：

```bash
SANDBOX_RUNTIME_APPLE_SMOKE_PORT=28080 \
./scripts/apple-container-smoke.sh
```

脚本退出时会删除测试容器及其唯一命名的临时镜像。如需保留镜像以便检查：

```bash
SANDBOX_RUNTIME_APPLE_SMOKE_KEEP_IMAGE=1 \
./scripts/apple-container-smoke.sh
```

## 手动运行

使用现有 Dockerfile 构建镜像：

```bash
container build --progress plain \
  --tag sandbox-runtime:apple-local \
  .
```

启动服务：

```bash
container run \
  --detach \
  --remove \
  --name sandbox-runtime-apple \
  --publish 127.0.0.1:18080:8080 \
  --env SANDBOX_RUNTIME_APPLICATION_MODE=development \
  --env SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0 \
  sandbox-runtime:apple-local
```

从宿主机检查并停止服务：

```bash
curl --fail http://127.0.0.1:18080/health
container stop sandbox-runtime-apple
```

容器内必须显式监听 `0.0.0.0`，宿主机才能通过发布端口访问。宿主机端仍然
只绑定 `127.0.0.1`，因为本地管理 API 没有终端用户认证。

## 当前限制

- Dockerfile 仍使用可变的基础镜像标签。正式发布流程必须固定经过审查的
  基础镜像 digest，并发布不可变的多平台 OCI image index。
- Smoke Test 使用内存 Fake Runtime。完整编程/Shell Provider 组合当前仍依赖
  Docker 特有的运行时组件，不属于本 Apple Container 应用 Smoke Test 范围。
- 当前还没有 Apple Container CI Runner 或发布门槛。
- 本流程不能证明部署或生产就绪能力。

应用部署目标和沙箱执行后端是两个不同问题：在 Apple Container 中运行本服务，
不会让 Apple Container 自动成为 Provider Runtime Driver；本测试也不会尝试创建
嵌套的 Apple Container 服务。
