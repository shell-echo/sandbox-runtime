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
| Product v1 第五阶段 Desktop | **15/15 已完成**（有边界的同仓库独立进程拓扑）；5 个角色、14 个严格场景及精确拓扑的依赖派生能力广告均通过 |
| Product v1 第六阶段生产加固 | **3/15 已完成**；Product 与 Provider 已具备独立的生产模式进程、TLS 1.3、分离数据库角色、事务化 Provider 状态、有界协调恢复和精确单 Profile 能力广告；尚不代表完整拓扑、部署或生产就绪 |
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

[Product v1 第六阶段](docs/plan/product-v1-phase-6-production-hardening.md)
当前完成 **3/15**。切片 1-2 提供独立的开发/生产内核 `product serve`，包括真实
PostgreSQL、TLS 1.3、签名身份、分离数据库角色、精确 Schema 检查及失败关闭的
就绪状态。切片 3 提供生产专用的独立 `provider serve`：TLS 1.3 mTLS、精确 JWS
准入、事务化 lifecycle/exec/Terminal/artifact/usage/Desktop 状态、有界协调恢复，
并且按锁定 Contract 只广告一个 `coding_shell` 或 `desktop` Profile。真实数据库
并发/故障/重启、真实进程重启、coding-shell Docker 生命周期和签名 Desktop broker
门禁均已通过。Product dispatch、公开数据面、部署、HA 与生产发布仍属于后续切片。

后续实现已补充 Slice 4 的独立 `gateway serve`、`guest serve`、`browser serve`
和 `desktop serve` 角色边界，以及严格的秘密引用、出站策略、制品摘要/签名、
隔离恢复顺序和低基数遥测基础。这些基础在真实角色图和独立进程门禁通过前，
不会被计入已完成切片。

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
已完成 **15/15** 个依赖有序切片（限有边界的发布拓扑）。切片 1 锁定了独立的 Provider Desktop
能力/Profile/运行时形状，以及完整的会话打开、读取、交接、关闭、过期、撤销、
用量、准入、安全和清理语义。精确权威为 Contract 版本
`720ad15c343e71f36615dc4499edd5e764178bca`、树
`343ffde0819207cf99c005096c336735dd33a735`，以及摘要为
`sha256:78e01cc5eb176083896baf8507c551d2ee88e56b93197321702748a88949e89d`
的 71 项本地 Suite。切片 2 在实现
`d2e7943f704e2eed6ea7b61a44ed2b6fa5510e00` 中加入严格的
Product Desktop slot/session 意图、PostgreSQL 迁移 8、原子的
operation/event/audit/outbox 持久化、独立 Desktop session 工作类型，以及
真实数据库的并发和重启证据。切片 3 的实现
`f96c06c3a50ade031e8ffbb4d8ea15e6ca8be7d5` 加入 Provider 本地 Desktop
领域/应用策略、内存与原子文件持久化、重启安全的协调恢复、operation 聚合和可选
受保护处理器。切片 4 候选实现
`163dd8a258a24cf4727169b1cbd8ed7c0fe29292` 加入锁定的双架构镜像输入、仅限
Unix 的有界 display/session broker、可复现的本地输出、已通过的原生 arm64
冒烟，以及手动原生发布/证明工作流。运行 `35447651328` 已在原生 amd64 与
arm64/v8 上通过并发布签名索引
`sha256:638e97c694ad4c9b9d750ae30dc6088ff5011af570ba1b12fdf3f0e35ffa0300`。
切片 5 实现 `0c30d6f5e6e0c6227069b8689668a1a0dcfb940b` 加入失效关闭的
Docker adapter、持久不透明 private resolver、每次 attach/reconnect 重新校验、
lifecycle readiness、先撤销后清理并确认缺席，以及精确 Desktop 时长用量。
切片 6 实现 `2d5bbaee2db2ab5c2a85f67e39acf2dd7b82a240` 加入锁定精确
版本的 Product 网络适配器、隔离的 Desktop 调度/观察、保留 operation 恢复、
独立 Product/Provider generation 和 Desktop 专属关闭清理；真实 PostgreSQL 与
HTTP Provider fixture 门禁已通过。切片 7 实现
`0649d62911abb89229de40136347286736152ec6` 加入 Product 自有 Desktop
viewer/controller grant、加密一次性 ticket、会话级单 controller fence、独立配额、
撤销、持续权威校验和仅元数据审计。在该边界，公开信令/媒体/输入、策略、Web、
生产组合和能力广告仍未完成。

切片 8 实现 `040c560f3701b7c972c25f05928dd435d9f55c20` 加入独立且有界的
Desktop WebRTC handler：带一次性 ticket 的 TLS 信令、精确 Origin、生产环境仅
TURN/TLS relay、仅接收 VP8 和可选 Opus、viewer/controller 分离、可靠有序的
fenced 输入、持续 grant 校验和慢消费者关闭。持久 Desktop 策略、真实 Provider
媒体桥接、恢复、录制、统一 Web、生产组合和能力广告仍未完成。

切片 9 实现 `24f5c741eb605614f77f8d9d546708b9993e42dd` 加入不可变且版本化的
Desktop 策略快照、PostgreSQL 迁移 11、默认拒绝的键盘/指针/触摸/剪贴板/传输
授权、激活与同意门禁、有界 workspace 路径和传输元数据、精确 Product transfer
记录绑定，以及持续策略版本撤销。真实 Provider 媒体/输入桥接、重连/恢复、录制、
统一 Web、生产组合和能力广告仍未完成。

切片 10 实现 `f23b16130c97e99d5d28008b01346779a0c681ee` 加入由数据库时间
驱动的 Desktop Gateway 租约、使用新 grant 的崩溃恢复、精确 authority/generation
重绑定、有界视觉/音频重同步、封闭的分辨率/音频输出切换、按连接 epoch 拒绝陈旧
输入，以及 replacement 时事务型 grant/handoff/session/binding 清理与唯一下一代
provision。在该边界，真实 Provider 媒体/输入桥接、录制、统一 Web、生产组合和能力
广告仍未完成。

切片 11 实现 `c5b045abc5192b76b7d615ddbb0858b998ef98d5` 把必需 Desktop
录制组合进 Gateway 准入与在线媒体/控制路径。信令显式携带同意引用并返回所选模式；
初始化失败或录制器丢失都会失效关闭。VP8/Opus RTP 与最小化的控制/同步事件复用
现有加密、配额有界、完整性链式的 Product 录制服务，并支持仅限 Workspace owner
的回放和保留期删除。剪贴板文本、传输路径/身份和内容不会进入目录或元数据审计。
真实 Provider 媒体/输入桥接、统一 Web、生产组合和能力广告仍未完成。

切片 12 实现 `490c2db96d6ba7a851d7846bc9e5f818dae2be77` 加入不可变的
`coding-shell-base-v1` 目录、迁移 13 的修订/开发环境持久化、受限的内容寻址
工作区流式物化、精确 Guest authority/health/mount/toolchain 校验，以及私有两阶段
Guest 回滚与重启恢复。主机路径、对象路径、凭据、Guest ID 和运行时坐标不会进入
公开 health 或审计/事件数据。真实 Provider 媒体/输入桥接、统一 Web、生产组合与
能力广告仍是后续门禁。

切片 13 实现 `84698c371d35edb862ffc81b484a3e31cc8120d9` 加入由能力快照派生的
统一认证 Product Web/BFF，覆盖 Workspace、Terminal、Files、Browser、Desktop
和录制。Desktop 查看/控制使用新鲜公开 grant、同源 HTTPS WebRTC、有序 fenced
输入、可见录制/控制状态、有界重连、流配置、剪贴板同意和摘要校验 Product 传输，
且不暴露 Provider handoff 或私有坐标。生成客户端、全仓 race/vet、Contract/历史
证据以及真实无头 Chrome 门禁均通过。在该切片边界，真实 Provider 媒体/输入桥接、
生产组合和广告、切片 14 组合故障/安全门禁及切片 15 独立进程发布门禁尚未完成。

切片 14 实现 `13385f6fdba2f78ff3bd7a7b9d1d2a2ea670271d` 加入封闭且有界的
私有 Provider 到 Product Gateway Desktop 媒体/控制桥，并保持 Product 与
Provider 权威包的依赖边界。真实 PostgreSQL 组合门禁把一次性 grant、持久策略、
公开 WebRTC、私有桥、VP8/可选 Opus、有序 fenced 输入、必需的加密录制、持续撤销、
重放/跨租户/跨 Origin 拒绝、容量恢复、保留期对象删除和精确租户行清理连接起来。
全仓 race/vet、双方 Contract 与保留的第三/第四阶段证据门禁均通过。独立的
Product/Gateway/Provider/Desktop/Guest 进程拓扑、真实显示/控制和开发场景、严格
发布证据包、部署、HA、恶意多租户隔离和生产就绪在该边界仍未成立。

切片 15 实现 `024a768d51965f8949bacf3c97e499fb26a6e648` 加入严格的独立
进程发布门禁。运行 `20260919T200125.484855000Z` 通过 14 个精确场景，分别以
Product、Gateway、Provider、Desktop 和 Guest 五个独立 OS 进程运行，使用全新固定
摘要 PostgreSQL、精确签名 Desktop 镜像、真实 X11 画面捕获与 fenced 指针控制、
公开 WebRTC/私有 mTLS 传输、加密录制回放、真实 Guest 开发工作区物化、Product/
Gateway/Guest 重启恢复、Provider 依赖丢失的失效关闭以及精确清理。只有该精确门禁
拓扑会根据在线依赖派生 Desktop/开发能力就绪；生产命令没有因此被组合或启用。
严格清单和结论边界见[第五阶段完成审计](docs/audits/product-phase-5-desktop-completion.md)。
该结果不等同于部署、HA、恶意多租户、独立实现调用方互操作或生产就绪证据。

## 项目提供什么

- 本地实例管理 API，以及内存 Fake 驱动和 Docker 运行时驱动。
- 独立的 Provider API，支持 mTLS 身份检查和由 JWS 保护的操作准入。
- 异步生命周期、受限命令执行、保留结果、用量证据、制品暂存、终端会话和受保护终端连接。
- 不透明且会过期的运行时会话交接信息；后端 ID、主机路径和原始运行时端点不会进入公开 Provider 协议。
- 仓库自有的 OpenAPI、JSON Schema、语义规则、Fixtures，以及本地和远程 Conformance Suite。
- 独立建模并锁定的 Provider Desktop Contract 表面；有边界的第五阶段发布拓扑已执行它，生产命令组合仍关闭。
- Product 自有的 Desktop slot/session 意图，包括精确 Profile、事务型 PostgreSQL 持久化、配额、审计和隔离的待处理 outbox 工作。
- 锁定且仅通过网络访问的 Product Desktop Provider adapter，包括独立 generation 权威、持久调度/观察恢复和 Desktop 专属会话清理；它尚未进入生产组合。
- Product 自有的 Desktop viewer/controller 连接权威，包括加密一次性 ticket、会话级 controller fencing、独立配额、撤销和仅元数据审计；该授权层不暴露 Provider 私有坐标。
- 独立且有界的 Product Desktop WebRTC handler，提供显示、可选输出音频和有序 controller 输入；当前仅为组件证据，尚未进入生产组合。
- 持久且版本化的 Product Desktop 输入/剪贴板/传输策略，包括精确 Product transfer 绑定和在线版本撤销；麦克风、摄像头和设备转发继续被拒绝。
- 使用新 grant 的有界 Desktop 重连与视觉/音频重同步、重启安全的 Gateway 租约回收、陈旧输入拒绝和确定性 slot replacement 清理。
- 带显式同意/模式的必需 Desktop 媒体/控制录制，包括加密完整性链式分段、owner 授权回放、有界配额、保留期删除，以及内容最小化的目录/审计元数据。
- 不可变开发模板与摘要校验的工作区物化、精确 Guest readiness、失败回滚、重启恢复，以及持久 PostgreSQL 尝试/修订状态；当前仍为组件证据。
- 能力派生的统一认证 Product Web/BFF，覆盖 Workspace、Terminal、Files、Browser、Desktop 和录制，提供新鲜 Desktop grant、有界恢复、无障碍控制且不投影私有运行时坐标。
- Provider 本地 Desktop operation 权威，包括持久化 replay/fencing、精确所有权的关闭/过期清理策略，以及尚未广告的受保护处理器。
- 精确签名的 Desktop 镜像，以及 Provider 本地 Docker adapter、private resolver、lifecycle、撤销/清理和时长用量组件；它们尚未进入生产启动组合或能力广告。
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

### 启动独立 Product 或 Provider 进程

第六阶段的角色进程使用各自独立配置启动：

```bash
go run . product serve -c /absolute/path/to/config.toml
go run . provider serve -c /absolute/path/to/config.toml
```

`provider serve` 的回环探针只提供 `/livez` 和 `/readyz`；mTLS 监听器只提供锁定的
Provider Contract，不提供 `/instances` 或 Product API。根 `serve`、`product serve`
和 `provider serve` 会拒绝混合角色 authority。精确配置与证据边界参见
[切片 3 记录](docs/audits/product-phase-6-slice-3.md)。

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
