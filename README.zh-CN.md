# sandbox-runtime

[English](README.md)

`sandbox-runtime` 是一个使用 Go 编写、与后端实现解耦的沙箱 Provider 和本地运行时控制面。它通过仓库自有的 Provider Contract 为编程和远程 Shell 工作负载提供标准接口，同时把具体运行时细节隔离在可替换的驱动之后。

第一版的工程计划和独立外部调用方资格验证计划均已完成。这是一个有明确边界的互操作性结论，不代表项目已经具备通用生产就绪能力。

## 项目状态

| 项目 | 状态 |
| --- | --- |
| 主交付计划 | **24/24 已完成** |
| 独立 External Caller | **13/13 已完成** |
| Product v1 第三阶段 | 在有边界的 standalone 拓扑内 **13/13 已完成** |
| Product v1 第四阶段 Browser | 在有边界的同仓库独立进程拓扑内 **13/13 已完成** |
| Product v1 第五阶段 Desktop | **1/15 已完成**；仅完成 Provider Contract/投影权威，能力广告仍关闭 |
| 编程/Shell 资格验证 | 对下述精确调用方、Provider 版本、拓扑、Profile 和场景结果为 **Qualified** |
| 最新核心 CI | [已通过](https://github.com/shell-echo/sandbox-runtime/actions/runs/35204434771) |

最终托管资格验证执行了全部 15 个初始场景和 5 个重建场景，91 项必需观察结果全部匹配，并且测试拥有的资源范围连续 3 次稳定归零。

- [资格验证运行 35203241121](https://github.com/shell-echo/sandbox-runtime/actions/runs/35203241121)
- Provider 源码版本：`170459266af5f4fad359ca8c63f2ae19741055c5`
- External Caller 源码版本：`b3ebcc783e5db20395e29b029e0eb55f7819b49b`
- 证据 Artifact：`10488622806`
- 证据归档：`sha256:ada1cae128a41e6b694ff413aab179c0eff94b42663ece8233dbb358e319e9bd`
- 结果信封：`sha256:d5e6fd528f2302252a38f49aa466c85767106a8bcef430120f230a8127f96758`

完整证据账本参见[项目状态](docs/STATUS.md)，精确的结论边界参见[外部调用方资格验证](docs/qualification/external-caller-coding-shell-v1.md)。

独立的 [Product v1 架构第一阶段](docs/plan/product-v1-phase-1.md)也已经完成，
但其结论仅限于设计与 Product Contract 定义。它允许本仓库未来承载 Product
模块，同时保持 Provider 是受锁定网络 Contract 约束的独立边界，并定义了
Workspace/Slot 持久化、身份与 Agent 委托、Runtime Gateway 与录制，以及部署
等级。该阶段没有实现或验证 Product 服务、Product 数据库迁移、公开 Gateway、
Guest Agent 或生产部署。

独立的 [Product v1 第二阶段 Provider 生命周期计划](docs/plan/product-v1-phase-2-provider-lifecycle.md)
已经完成其固定九步范围，覆盖终止、暂停/恢复、租约过期、有限事件读取和终端
会话关闭，并通过锁定 Contract、Conformance、Docker 生命周期和独立进程参考门禁。

[Product v1 第三阶段](docs/plan/product-v1-phase-3-product-kernel-terminal-files-web.md)
已在有边界的 standalone 范围内完成 **13/13**。最终门禁在全新固定摘要
PostgreSQL 上，以四个独立 OS 进程运行 Product、Gateway、Guest 与锁定 Contract
的 Provider fixture，并通过 9 个黑盒场景。能力就绪状态现在按租户和完整依赖实时
派生。该结论不等同于可部署拓扑、独立实现调用方、HA、恶意多租户隔离或生产就绪。

[Product v1 第四阶段 Browser](docs/plan/product-v1-phase-4-browser.md)已在有边界的
发布拓扑内完成 **13/13**。最终标签门禁以独立的 Product、Gateway、Provider 和
Browser OS 进程，配合全新固定摘要 PostgreSQL、Valkey 与加密录制存储，通过了
12 个精确场景。严格证据清单覆盖重启、故障、认证、租户信息不泄露、自动化、
真实 WebRTC 查看/控制、录制完整性、背压、生命周期和精确清理。该结论不等同于
通过部署资格验证、独立实现调用方、HA、恶意多租户隔离或生产就绪。

[Product v1 第五阶段 Desktop](docs/plan/product-v1-phase-5-desktop-development-unified-product.md)
已完成 **1/15** 个依赖有序切片。切片 1 锁定了独立的 Provider Desktop
能力/Profile/运行时形状，以及完整的会话打开、读取、交接、关闭、过期、撤销、
用量、准入、安全和清理语义。精确权威为 Contract 版本
`720ad15c343e71f36615dc4499edd5e764178bca`、树
`343ffde0819207cf99c005096c336735dd33a735`，以及摘要为
`sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`
的 71 项本地 Suite。这仅是 Contract 与 Go 投影证据：尚无 Desktop 运行时、
Product Desktop 状态、公开数据面、Web 体验、路由组合或能力广告。

## 项目提供什么

- 本地实例管理 API，以及内存 Fake 驱动和 Docker 运行时驱动。
- 独立的 Provider API，支持 mTLS 身份检查和由 JWS 保护的操作准入。
- 异步生命周期、受限命令执行、保留结果、用量证据、制品暂存、终端会话和受保护终端连接。
- 不透明且会过期的运行时会话交接信息；后端 ID、主机路径和原始运行时端点不会进入公开 Provider 协议。
- 仓库自有的 OpenAPI、JSON Schema、语义规则、Fixtures，以及本地和远程 Conformance Suite。
- 独立建模并锁定的 Provider Desktop Contract 表面；其运行时与能力广告在后续第五阶段切片完成前保持关闭。
- 面向独立实现调用方的确定性资格验证工具。
- 可选的 Browser 参考组件和证据轨道；它们与已通过验证的编程/Shell Profile 分开管理。

适用场景包括远程开发环境、临时编程沙箱、终端服务、浏览器自动化基础设施，以及需要为 Agent 工作负载提供受控运行时边界的系统。

## 架构与职责边界

本地管理 API 和 Provider API 被刻意设计为两个不同接口：

| 接口 | 用途 | 权威来源 |
| --- | --- | --- |
| 本地 `/health` 和 `/instances` API | 操作单个本地运行时控制器 | 内部应用模型和配置 |
| Provider `/v1/*` API | 跨服务沙箱协议 | 锁定的仓库自有 Provider Contract |
| Product `/api/v1/*` API | 面向最终用户的 Workspace 控制面 | 独立锁定的 Product Contract；已有组件与 tagged standalone 门禁，但没有通过部署资格验证的监听器组合 |

```text
调用服务
  ├─ 业务状态、用户、租户、授权、计费和公开 Gateway
  └─ 聚合操作账本及 Provider 版本选择
                         │
                         │ Sandbox Provider Contract v1
                         ▼
sandbox-runtime Provider
  ├─ 准入和 Provider 本地操作状态
  ├─ 生命周期、命令执行、终端、制品和用量证据
  └─ 运行时驱动 ──► Docker / 未来的隔离后端
```

调用方需要适配本仓库的 Contract。Provider 不提供面向特定消费平台的私有协议，也不负责调用方的用户、业务工作流、计费或公开会话授权。

依赖方向从传输层向内指向应用策略、仓库和运行时驱动。完整边界参见[架构文档](docs/architecture.md)和 [ADR 0037](docs/adr/0037-sandbox-provider-calling-standard.md)。

## 快速开始

### 环境要求

- Go 1.26，或 `go.mod` 指定的精确版本
- 只有使用 Docker 后端或运行集成测试时才需要 Docker
- Apple Container 仅在运行本地 OCI 应用 Smoke Test 时需要
- `kubectl` 和集群仅在运行 Kubernetes 应用 Smoke Test 时需要

### 启动开发服务器

```bash
git clone https://github.com/shell-echo/sandbox-runtime.git
cd sandbox-runtime
go test ./...
go run . serve
```

默认配置使用内存 Fake 驱动，并监听 `127.0.0.1:8080`：

```bash
curl http://127.0.0.1:8080/health
```

默认不会启用 Provider 监听器及受保护的 Provider 功能。

### 使用 Docker 运行应用

Docker Smoke Test 会构建根目录 Dockerfile，并在数字化非 root 用户、只读根
文件系统和受限 Linux 权限下验证 `/health` 及最小本地 Instance 流程：

```bash
./scripts/docker-smoke.sh
```

详细说明参见[Docker 应用部署](docs/docker.zh-CN.md)。该测试验证使用 Fake
Runtime 的应用打包，不验证 Docker 沙箱执行。

### 使用 Apple Container 运行应用

现有 Dockerfile 可以通过 Apple Container 构建并运行成 Linux OCI
应用。仓库提供的 Smoke Test 会使用默认内存 Fake Runtime 验证
`/health` 和最小本地实例 API 往返：

```bash
./scripts/apple-container-smoke.sh
```

环境准备、手动命令、清理行为和精确证据边界参见
[Apple Container 文档](docs/apple-container.zh-CN.md)。该测试只证明应用打包和基础启动，
不证明受保护 Provider 接口或依赖 Docker 的能力可以在 Apple Container 中运行。

### 在 Kubernetes 上运行应用

无需集群即可渲染开发 Kustomize Base：

```bash
./scripts/kubernetes-smoke.sh
```

如果可访问的集群已经预载 `sandbox-runtime:local`：

```bash
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 \
  ./scripts/kubernetes-smoke.sh
```

详细说明参见[Kubernetes 应用部署](docs/kubernetes.zh-CN.md)。这些开发资源
使用 Fake Runtime，不是生产 Provider 部署。

### 使用配置文件

```bash
cp config.tpl.toml config.toml
go run . serve -c config.toml
```

当 `config.toml` 包含环境路径或凭据时，不要提交该文件。配置优先级由低到高为：

1. 内置默认值；
2. 可选 TOML 配置文件；
3. `SANDBOX_RUNTIME_` 环境变量。

示例：

```bash
SANDBOX_RUNTIME_APPLICATION_MODE=development \
SANDBOX_RUNTIME_LOGGER_LEVEL=debug \
SANDBOX_RUNTIME_SERVER_API_PORT=8081 \
go run . serve
```

### 本地管理 API

```http
GET    /health
POST   /instances
GET    /instances
GET    /instances/:id
POST   /instances/:id/start
POST   /instances/:id/stop
DELETE /instances/:id
```

实例创建请求示例：

```json
{
  "name": "my-shell",
  "workload": "shell"
}
```

Fake 驱动是安全的开发默认值。使用 Docker 时，需要配置文件仓库、由运维方选择且保持稳定的 Controller ID、资源限制，以及合适的镜像和启动命令。请从 [`config.tpl.toml`](config.tpl.toml) 中的配置和注释开始。

## Provider 集成

规范性集成权威位于 [`contract/`](contract/)：

- [Provider Calling Standard](contract/specification/provider-calling-standard-v1.md)
- [OpenAPI](contract/openapi/sandbox-runtime-provider-v1.yaml)
- `contract/schemas/` 和 `contract/fixtures/` 下的 JSON Schema 与 Fixtures
- `contract/semantic-rules/` 下的语义规则，以及 `contract/conformance/`
  下的 Conformance Suite
- [锁定的兼容性身份](compatibility/sandbox-runtime/contract.lock.json)

简洁的实现清单参见 [Provider 集成指南](docs/platform-integration-profile.md)。独立的公开仓库 [`sandbox-runtime-external-caller`](https://github.com/shell-echo/sandbox-runtime-external-caller) 是第一版经过资格验证的独立调用方；其他平台应实现或适配同一套调用标准。

Provider 监听器默认关闭，并且与本地 API 分离。受保护的部署必须自行提供证书、精确调用方身份、Issuer、Audience、验签公钥集合、Provider 版本、持久化状态和完整的能力依赖。配置模板不会提供可直接用于生产的凭据。

## 验证

运行常规 Go 检查：

```bash
go test -race -shuffle=on -count=1 ./...
go vet ./...
```

验证锁定的 Contract 并执行本地 Conformance Suite：

```bash
go run ./cmd/verify-contract -source-root .

runner_dir="$(mktemp -d)"
go build -buildvcs=true -o "$runner_dir/run-conformance" ./cmd/run-conformance
"$runner_dir/run-conformance" -source-root . -race -shuffle
```

Conformance Runner 必须是来自干净 Git 工作区并包含 VCS 信息的构建产物，因为它会校验并测试所记录源码版本的只读归档。这里不能用 `go run` 替代 Runner 构建步骤。

Docker 可用时运行：

```bash
SANDBOX_RUNTIME_DOCKER_INTEGRATION=1 \
go test -tags=integration -count=1 \
  ./cmd ./driver/docker ./provider/lifecycle/driver/docker
```

其他 Browser、External Caller 和资格验证门槛记录在[开发规范](docs/development.md)中。

## 安全与资格结论边界

服务会拒绝不安全的生产配置，并为 Docker 应用较为保守的默认设置，但这些控制本身不能让 Docker 成为能够承载敌对工作负载的强化安全边界。本地管理 API 没有内建的终端用户认证；应仅监听回环地址，或放在受信任且经过认证的边界之后。

第一版资格验证只证明指定的编程/Shell 调用方、Provider 版本、Contract/Profile 身份、制品、拓扑和场景。它**不证明**：

- 对所有潜在调用方的聚合兼容性；
- 多控制器正确性或高可用；
- 敌对多租户隔离；
- 完整的生产部署和运维模型；
- 通用生产就绪能力。

这些内容应作为新的项目范围，分别设计、实现和提供证据。

## 仓库导航

| 路径 | 用途 |
| --- | --- |
| `contract/` | Provider Contract 规范性权威 |
| `provider/`、`providerapi/` | Provider 领域、应用、适配器和传输层 |
| `instance/`、`driver/` | 本地实例服务和运行时驱动 |
| `qualification/`、`internal/qualification*` | External Caller 资格验证定义和工具 |
| `profiles/` | Runtime Profile 资产及锁定镜像定义 |
| `compatibility/` | Contract 身份和兼容性元数据 |
| `e2e/` | 同仓库参考调用方；不能作为独立互操作性证明 |
| `docs/` | 架构、ADR、计划、开发规则和证据状态 |

推荐阅读顺序：

1. [架构](docs/architecture.md)
2. [应用部署](docs/deployment.zh-CN.md)
3. [Provider 集成指南](docs/platform-integration-profile.md)
4. [开发规范](docs/development.md)
5. [项目状态与证据](docs/STATUS.md)

## 参与开发

请保持本地 API 与 Provider Wire Model 的分离；将传输、策略、仓库和驱动放在不同包中；保留 Deadline 和取消语义；拒绝未知或超大输入；不要把组件测试或同仓库测试描述成更广泛的兼容性结论。

修改行为前请先阅读 [`AGENTS.md`](AGENTS.md) 和[开发规范](docs/development.md)。

## 许可证

[MIT](LICENSE)
