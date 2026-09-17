# Kubernetes 应用部署

[English](kubernetes.md)

本文说明如何把 `sandbox-runtime` 应用本身部署到 Kubernetes。它不会把
Kubernetes 实现成沙箱执行后端。

`deploy/kubernetes/development` 中的资源刻意定义为开发配置：使用内存 Fake
Runtime 和本地管理 API，不是生产 Provider 部署。

跨平台边界参见[应用部署](deployment.zh-CN.md)。

## 包含的资源

Kustomize Base 包含：

- 一个选择开发模式和 `8080` 端口的 `ConfigMap`；
- 一个单副本 `Deployment`，包含启动、就绪和存活探针；
- 一个 `ClusterIP` `Service`；
- 一个默认限制入口的 `NetworkPolicy`，只允许同一 Namespace 中带有
  `sandbox-runtime.shell-echo.dev/client=true` 标签的 Pod 访问 `8080`；
- 数字化非 root 身份、默认 seccomp、禁用 ServiceAccount Token、只读根文件
  系统、禁止权限提升、删除全部 Linux capabilities；
- 明确的 CPU/内存边界；
- 只挂载到 `/tmp` 的限额 `emptyDir`。

开发 Fake Runtime 是进程内且不持久化的，因此单副本和 `Recreate` 策略是有意
选择，而不是生产高可用设计。

## 离线校验

无需集群即可渲染 Kustomize Base，并检查必须存在的安全约束：

```bash
./scripts/kubernetes-smoke.sh
```

这只是结构证据，不能证明 Kubernetes API、Scheduler、CNI、Kubelet 或容器
Runtime 已经接受并运行这些资源。

## 实际集群 Smoke Test

Live 模式需要：

- 当前 `kubectl` Context 指向可访问的集群；
- 一个空闲本地端口，默认 `18082`；
- 所有目标节点已经具有 `sandbox-runtime:local` 镜像。因为尚未发布应用镜像，
  开发 Deployment 使用 `imagePullPolicy: Never`。

执行：

```bash
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 \
  ./scripts/kubernetes-smoke.sh
```

脚本会创建唯一 Namespace、部署资源、等待 Rollout、转发 Service 端口、验证
health/create/list，并删除 Namespace。设置
`SANDBOX_RUNTIME_KUBERNETES_KEEP_NAMESPACE=1` 可以保留 Namespace。

如需使用另一个已经预载的标签：

```bash
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 \
SANDBOX_RUNTIME_KUBERNETES_IMAGE=sandbox-runtime:test \
  ./scripts/kubernetes-smoke.sh
```

## 本地 kind 示例

Docker 和 kind 可用时：

```bash
kind create cluster --name sandbox-runtime
docker build --tag sandbox-runtime:local .
kind load docker-image sandbox-runtime:local --name sandbox-runtime
SANDBOX_RUNTIME_KUBERNETES_LIVE=1 ./scripts/kubernetes-smoke.sh
kind delete cluster --name sandbox-runtime
```

Smoke Test 只负责其唯一 Namespace。创建集群、加载镜像和删除集群仍是明确的
操作者动作。

## 手动部署

创建 Namespace 并应用开发 Base：

```bash
kubectl create namespace sandbox-runtime
kubectl apply --namespace sandbox-runtime \
  --kustomize deploy/kubernetes/development
kubectl rollout status --namespace sandbox-runtime \
  deployment/sandbox-runtime --timeout=180s
```

使用远端 Registry 前，应在操作者拥有的 Overlay 中把
`sandbox-runtime:local` 替换为不可变 Digest，并修改 Pull Policy。不能把凭据
放入 `ConfigMap`；应使用独立 Secret 和受保护 Provider 配置模型。

## 安全和生产边界

本地管理 API 没有认证。`ClusterIP` 和 NetworkPolicy 可以缩小暴露范围，但不能
替代认证；NetworkPolicy 是否生效还依赖集群 CNI。不能为该开发配置增加 Ingress
或公开 LoadBalancer。

生产使用仍需单独审查身份、mTLS/JWS 准入、持久仓库、能力依赖、Gateway、
Secret 交付、可观测性、中断/可用性设计、备份恢复和不可变发布镜像。这些开发
Manifest 不证明上述能力。
