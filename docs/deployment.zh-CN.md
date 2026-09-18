# 应用部署

[English](deployment.md)

本文定义 `sandbox-runtime` 应用自身的部署边界，并明确区分“运行服务的环境”
和“服务执行沙箱工作负载所使用的后端”。

[ADR 0047](adr/0047-deployment-levels-slos-and-release-gates.md) 进一步定义了
`development`、`standalone`、`production` 和未来
`hostile-multitenant` 四个保障等级。本文现有的全部资源和结果都只属于
`development` 应用打包证据。

## 两个相互独立的问题

| 问题 | 含义 | 当前示例 |
| --- | --- | --- |
| 应用部署环境 | `sandbox-runtime` 服务进程运行在哪里？ | Docker、Apple Container 或 Kubernetes Pod |
| 沙箱执行后端 | Provider 在哪里、以什么方式执行请求的沙箱？ | 内存 Fake Adapter 或当前 Docker 开发 Adapter |

使用 Apple Container 或 Kubernetes 运行服务镜像，不会让它们自动成为沙箱
执行后端。反过来，只要服务可以访问经过明确配置和授权的 Docker Engine，选择
Docker 沙箱后端也不要求服务进程本身必须由 Docker 启动。

公开 Provider Contract 不得暴露部署平台身份或后端实现身份。

## 当前支持矩阵

| 部署环境 | 仓库资产 | 已验证范围 | 尚缺内容 |
| --- | --- | --- | --- |
| Docker 兼容 OCI Runtime | 根目录 `Dockerfile`、`.dockerignore`、中英文指南和 `scripts/docker-smoke.sh` | 本地 Linux `arm64` 镜像构建、数字化非 root 身份、受限容器启动，以及使用 Fake Runtime 的 health、create、list | 托管多架构 CI 和发布门槛 |
| Apple Container | 根目录 `Dockerfile`、中英文指南和 `scripts/apple-container-smoke.sh` | Apple silicon 本地构建、非 root 启动、回环端口发布，以及使用 Fake Runtime 的 health、create、list | 托管 CI 和发布门槛 |
| Kubernetes | 开发 Kustomize Base、中英文指南和 `scripts/kubernetes-smoke.sh` | 离线渲染/安全检查，以及本地集群中使用 Fake Runtime 的 health、create、list | 托管集群 CI、不可变 Registry 镜像、生产 Overlay 和发布门槛 |

目前没有发布通用的 `sandbox-runtime` 应用镜像。仓库中的编程/Shell 和 Browser
运行时镜像是其他制品，不能作为本应用镜像使用。

2026-09-17 的本地开发证据分别通过了 Docker Engine 29.7.2
（Linux/arm64）、Apple Container 1.4.1（macOS/arm64），以及 kind 0.33.0 和
Kubernetes 1.37.0 的实际集群 Smoke Test。这些只是当前工作区的应用打包检查，
不是托管发布或生产部署证据。

## 可移植应用容器约束

所有受支持的部署环境都应保持以下属性：

- 以数字化非 root 用户运行仓库构建的 `sandbox-runtime serve` 进程；
- 使用与目标架构匹配的 Linux 镜像；
- 只有需要通过发布端口或 Service 访问本地 API 时，才在容器内部设置
  `SANDBOX_RUNTIME_SERVER_API_HOST=0.0.0.0`；
- 未认证的本地 API 必须只暴露到宿主机回环地址，或放在受信任且经过认证的
  边界之后；
- 通过注入方式提供配置和凭据，不能把它们写入镜像；
- 只挂载明确需要的可写状态，并把 Secret 与普通配置分开；
- 保留进程信号和有界停止语义；
- `/health` 只用于本地应用健康检查，不能据此声称受保护 Provider 能力或外部
  依赖已经就绪。

生产 Provider 部署还必须具备架构和 Provider Contract 规定的完整受保护
Listener、身份、持久状态、能力、Gateway 和运维依赖。仅仅启动应用容器不代表
通过该部署门槛。

## 平台指南

- [Docker](docker.zh-CN.md)：本地应用 Smoke Test。
- [Apple Container](apple-container.zh-CN.md)：已完成本地应用 Smoke Test。
- [Kubernetes](kubernetes.zh-CN.md)：包含离线和实际集群 Smoke Test 的开发
  Kustomize Base。

## 已知缺口

- 根目录 Dockerfile 当前仍引用可变基础镜像标签。
- 尚未发布不可变的多平台应用镜像。
- Kubernetes 尚无生产 Overlay、Helm Chart、托管集群门槛或可用性证据。
- 当前 Apple Container 证据使用内存 Fake Runtime。
- Docker 和 Kubernetes 应用 Smoke Test 同样使用该 Fake Runtime。
- 多控制器、高可用、敌对多租户隔离、部署资格和生产就绪仍是相互独立的开放
  门槛。
