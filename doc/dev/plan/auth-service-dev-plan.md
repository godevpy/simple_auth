# Go 鉴权服务开发方案与开发计划

## 1. 背景与目标

本文基于 `doc/design/auth-service-design.md` 和当前 Kratos 项目骨架，制定一期开发方案和可执行开发计划。

当前项目状态：

- Go module 为 `simple_auth`。
- 当前入口目录为 `cmd/simple_auth`。
- 当前配置文件为 `configs/config.yaml`。
- 当前 Kratos 骨架仍保留 `helloworld/greeter` 示例代码。
- 当前 HTTP 监听地址为 `0.0.0.0:8000`。
- 当前还包含 gRPC server 骨架，但鉴权服务一期只需要 HTTP。

一期目标：

- 将 Kratos helloworld 骨架改造成 Nginx `auth_request` 鉴权服务。
- 实现登录页、登录提交、登出、`/auth/verify`、健康检查和就绪检查。
- 使用 YAML 配置用户、session、Redis、路径授权、登录失败封禁和审计日志。
- 使用 Redis 存储 session、登录失败计数和封禁状态。
- 登录失败审计按天写入独立 JSON Lines 文件，永久保留。
- 先实现 M1 闭环，不提供 Dockerfile、docker-compose、密码 hash 生成命令。

## 2. 开发方案设计

### 2.1 总体技术路线

一期采用 HTTP-only Kratos 服务，不使用 protobuf HTTP API 生成鉴权接口。

决策：

- 保留当前 `cmd/simple_auth` 入口目录，不强制改名为 `cmd/server`。
- 移除或停用 greeter 示例服务、greeter repo 和 greeter 路由。
- 一期关闭 gRPC server 注入和启动，只启动 Kratos HTTP server。
- 在 `internal/server/http.go` 中手动注册 HTTP 路由。
- 在 `internal/conf/conf.proto` 中扩展鉴权服务所需配置，并通过 `make config` 生成 `conf.pb.go`。
- 一期 Redis 只支持单机地址，不支持 Sentinel 和 Cluster。
- 一期密码校验使用 bcrypt。
- 配置文件默认读取 `configs` 目录，仍允许通过 `-conf` 启动参数覆盖。

### 2.2 Kratos 分层方案

建议目录和职责：

```text
cmd/simple_auth
internal/conf
internal/biz
internal/data
internal/service
internal/server
templates
deploy/nginx
doc/dev/plan
```

分层职责：

- `cmd/simple_auth`：Kratos 应用启动、配置加载、wire 注入入口。
- `internal/conf`：通过 proto 定义 YAML 配置结构。
- `internal/biz`：核心业务规则，包括认证、session、授权、登录失败封禁。
- `internal/data`：Redis、YAML 用户、按天文件审计日志等基础设施实现。
- `internal/service`：HTTP handler 编排，包括登录页、登录提交、登出、鉴权校验。
- `internal/server`：Kratos HTTP server 初始化、路由注册、中间件。
- `templates`：服务端 HTML 登录模板。
- `deploy/nginx`：Nginx `auth_request` 示例配置。

### 2.3 配置方案

需要将 `internal/conf/conf.proto` 从 helloworld 默认配置扩展为鉴权服务配置。

配置分组：

- `server.http`：HTTP 监听地址和超时。
- `data.redis`：Redis 单机连接参数。
- `templates`：登录页模板路径。
- `session`：Cookie 名称、空闲超时、绝对超时、滑动过期、Secure、SameSite、按域名隔离。
- `users`：YAML 用户列表，包含 ID、用户名、展示名、密码哈希、用户组。
- `authorization`：路径白名单授权规则。
- `security.login_failure`：失败次数、封禁窗口、白名单、密码尝试指纹策略。
- `logging.audit`：登录失败审计文件目录、文件名格式、按天切分、文件权限。

默认值决策：

- HTTP 监听地址沿用当前 Kratos 配置：`0.0.0.0:8000`。
- Redis 一期只支持单机：`127.0.0.1:6379`。
- session Cookie 名称：`auth_session`。
- session 空闲超时：语义为 `30m`，YAML 使用 protobuf duration 写法 `1800s`。
- session 绝对最长有效期：语义为 `24h`，YAML 使用 protobuf duration 写法 `86400s`。
- session 滑动过期：开启。
- Cookie `Domain`：不设置。
- Cookie `Secure`：配置化，生产为 `true`。
- 用户白名单：默认开启。
- 登录失败阈值：3 次。
- IP 和用户名封禁时间：30 分钟。
- 登录失败审计文件：`logs/login_failure_audit-2006-01-02.jsonl`。

### 2.4 数据层方案

`internal/data` 需要提供以下能力：

- Redis client 初始化和关闭。
- 用户配置加载和查询。
- session 存取、刷新 TTL、删除。
- 登录失败计数和封禁状态读写。
- 登录失败审计文件按天追加写入。

Redis key 约定：

```text
auth:session:<host-hash>:<session-hash>
auth:login:fail:ip:<ip-hash>
auth:login:fail:user:<username-hash>
auth:login:ban:ip:<ip-hash>
auth:login:ban:user:<username-hash>
```

实现决策：

- Redis key 中不放明文 session id，使用 SHA-256 或 HMAC 后的 session hash。
- IP 和用户名进入 Redis key 前先做 hash，避免 Redis key 暴露敏感信息。
- session value 使用 JSON，包含用户 ID、用户名、展示名、用户组、host、创建时间、最后访问时间、绝对过期时间。
- session TTL 刷新时取 `idle_timeout` 和剩余绝对有效期的较小值。
- 登录失败审计使用 JSON Lines，按本地日期切分文件。
- 文件审计 writer 内部用 mutex 保证并发写入安全。
- 服务只创建目录、打开当天文件、追加写入，不负责压缩和删除历史日志。

### 2.5 业务层方案

`internal/biz` 负责业务规则，不直接依赖 HTTP。

核心模型：

- `User`：ID、Username、DisplayName、PasswordHash、Groups。
- `Session`：SessionIDHash、User、Host、CreatedAt、LastSeenAt、ExpiresAt、ClientIP、UserAgent。
- `AuthorizationRule`：Name、Hosts、PathMatch、Paths、Methods、AllowGroups、AllowUsers、AllowUserIDs。
- `LoginFailureEvent`：Time、IP、Username、UserAgent、Reason、BanResult、PasswordAttemptHMAC。

核心接口：

- `UserRepo`：按用户名查询用户、判断白名单。
- `SessionRepo`：创建、读取、刷新、删除 session。
- `LoginFailureRepo`：检查封禁、增加失败、封禁 IP、封禁用户名、清理成功后的失败计数。
- `AuditRepo`：写入登录失败审计事件。

核心用例：

- `AuthUsecase.Login`：登录主流程。
- `AuthUsecase.Verify`：Nginx 鉴权校验。
- `AuthUsecase.Logout`：登出。
- `AuthUsecase.Me`：当前用户信息，可选。
- `AuthorizationUsecase.Allow`：白名单路径授权。
- `LoginFailureUsecase.RecordFailure`：失败计数、封禁和审计。

登录失败处理顺序：

1. 解析用户名、密码、客户端 IP、User-Agent。
2. 检查 IP 是否被封禁。
3. 检查用户名是否被封禁。
4. 检查用户名是否在 YAML 白名单。
5. 非白名单用户直接封禁 IP 30 分钟，并写入审计。
6. 用户不存在或密码错误时，增加 IP 和用户名失败计数。
7. 任一计数达到 3 次后，封禁对应 IP 和用户名 30 分钟。
8. 登录成功后清理该 IP 和用户名的失败计数。

### 2.6 HTTP 服务方案

`internal/service` 提供 handler，`internal/server/http.go` 负责注册。

路由：

```text
GET  /login
POST /login
GET  /auth/verify
POST /logout
GET  /me
GET  /healthz
GET  /readyz
```

接口行为：

- `GET /login`：渲染 `templates/login.html`。
- `POST /login`：接收 form 表单，成功设置 Cookie 并 302 跳转，失败返回 401。
- `GET /auth/verify`：校验 Cookie、Redis session 和路径白名单，成功返回 204，未登录返回 401，无权限返回 403。
- `POST /logout`：删除 Redis session，清理 Cookie，302 到 `/login`。
- `GET /me`：返回当前 session 用户信息，未登录返回 401。
- `GET /healthz`：进程存活检查，直接 200。
- `GET /readyz`：检查 Redis ping，成功 200，失败 503。

HTTP 实现决策：

- 不使用 gRPC。
- 不为 M1 新增鉴权 protobuf API。
- 使用 Kratos HTTP server 的路由能力手动注册 handler。
- Cookie 设置 `HttpOnly`。
- `Secure` 和 `SameSite` 从配置读取。
- redirect 只允许相对路径。
- `X-Original-URI` 为空时回退到当前请求 URL path。
- `X-Original-Host` 为空时回退到 `Host`。
- `X-Original-Method` 为空时回退到当前请求 method。

### 2.7 路径授权方案

授权采用白名单逻辑。

规则语义：

- `authorization.enabled=false`：只校验登录态。
- `authorization.enabled=true`：必须命中白名单规则才放行。
- 未命中任何规则：返回 403。
- 规则顺序从上到下，第一条匹配的允许规则生效。
- `methods` 为空表示所有方法。
- `allow_groups`、`allow_users`、`allow_user_ids` 全为空表示任意已登录用户。

路径匹配：

- `path_match=prefix`：使用 Nginx 普通前缀 location 语义。
- `path_match=wildcard`：使用 Nginx 正则 location `~ pattern` 风格。
- wildcard 规则的 pattern 允许写成 `~ ^/ops/[^/]+/dashboard$`。
- query string 不参与匹配。
- M1 只支持大小写敏感正则。

### 2.8 模板与静态资源方案

一期只提供服务端 HTML 模板。

模板文件：

```text
templates/login.html
```

模板要求：

- 包含 username、password、redirect 字段。
- 表单提交到 `POST /login`。
- 登录失败时可以显示通用失败提示。
- 不暴露具体失败原因。

### 2.9 Nginx 示例方案

新增示例：

```text
deploy/nginx/auth_request.conf
```

示例需要覆盖：

- 受保护 location。
- internal `/ _auth/verify` 或 `/_auth/verify` 子请求 location。
- `error_page 401 =302 /login?redirect=$request_uri`。
- `error_page 403`。
- `X-Original-URI`、`X-Original-Method`、`X-Original-Host` 透传。

## 3. 开发计划设计

### 第一步：整理当前 Kratos 骨架

目标：

- 明确一期为 HTTP-only 鉴权服务。
- 移除 helloworld 示例对主流程的影响。

具体动作：

1. 保留 `cmd/simple_auth` 作为入口。
2. 修改 `newApp` 和 wire 注入，只启动 HTTP server。
3. 从 `internal/server/http.go` 移除 Greeter HTTP 注册。
4. 从 provider set 中移除 Greeter usecase、repo、service。
5. 保留 `api/helloworld` 文件不作为编译依赖，后续可清理。

验收标准：

- `go test ./...` 不再依赖 Greeter 业务注入。
- 应用启动只监听 HTTP 配置端口。

### 第二步：扩展配置 schema

目标：

- 让 YAML 能表达设计文档中的所有 M1 配置。

具体动作：

1. 修改 `internal/conf/conf.proto`。
2. 增加 `Templates`、`Session`、`User`、`Authorization`、`Security`、`Logging` 配置。
3. 保留 `Server.HTTP`。
4. 保留 `Data.Redis`，移除或停用数据库配置。
5. 执行 `make config` 生成 `internal/conf/conf.pb.go`。
6. 更新 `configs/config.yaml` 为鉴权服务样例配置。

验收标准：

- 配置可以被 Kratos config 正常加载并扫描到 `conf.Bootstrap`。
- `configs/config.yaml` 包含登录用户、白名单、路径授权、session 和审计日志配置。

### 第三步：补齐依赖和基础设施

目标：

- 准备 Redis、bcrypt 和文件审计所需基础能力。

具体动作：

1. 添加 Redis 客户端依赖，建议 `github.com/redis/go-redis/v9`。
2. 添加 bcrypt 依赖，建议 `golang.org/x/crypto/bcrypt`。
3. 在 `internal/data.NewData` 中初始化 Redis client。
4. 在 cleanup 中关闭 Redis client。
5. 实现 Redis ping 能力供 `/readyz` 使用。

验收标准：

- Redis client 可以根据 YAML 配置初始化。
- Redis 不可用时 `/readyz` 能返回 503。

### 第四步：实现用户配置仓储

目标：

- 从 YAML 配置中提供用户查询和白名单判断。

具体动作：

1. 在 `internal/biz` 定义 `User` 和 `UserRepo`。
2. 在 `internal/data` 实现 `userConfigRepo`。
3. 支持按 username 查询用户。
4. 支持判断 username 是否在 `security.login_failure.user_whitelist` 中。
5. 用户名匹配采用大小写敏感策略。

验收标准：

- 可从配置中查询用户。
- 非白名单用户会被业务层识别。

### 第五步：实现 session 仓储

目标：

- 完成 Redis session 创建、读取、刷新和删除。

具体动作：

1. 在 `internal/biz` 定义 `Session` 和 `SessionRepo`。
2. 生成 session id 时使用加密安全随机数。
3. Redis key 使用 host hash 和 session hash。
4. session value 使用 JSON。
5. 创建 session 时设置 TTL 为 `min(idle_timeout, absolute_remaining)`。
6. 验证 session 时检查绝对过期时间。
7. 滑动过期时刷新 TTL 和 last seen。
8. 登出时删除 Redis session。

验收标准：

- 登录后 Redis 中出现 session。
- 空闲超时后 session 失效。
- 即使持续活跃，超过 24 小时也失效。

### 第六步：实现登录失败封禁与审计

目标：

- 完成 IP/用户名失败计数、封禁和按天审计日志。

具体动作：

1. 在 `internal/biz` 定义 `LoginFailureRepo` 和 `AuditRepo`。
2. 在 Redis 中实现 IP 和用户名失败计数。
3. 在 Redis 中实现 IP 和用户名 ban key。
4. 实现非白名单用户直接封禁 IP。
5. 实现登录失败达到 3 次后封禁 IP 和用户名。
6. 使用 HMAC-SHA256 生成密码尝试指纹。
7. 实现 `fileAuditRepo`，按天写入 JSON Lines。
8. 创建日志目录时使用配置的目录权限。
9. 创建日志文件时使用配置的文件权限。

验收标准：

- 连续 3 次密码失败后 IP 和用户名被封禁 30 分钟。
- 非白名单用户尝试登录后来源 IP 被封禁。
- 审计文件按天写入，且不包含明文密码。

### 第七步：实现路径白名单授权

目标：

- 实现 `/auth/verify` 所需路径授权。

具体动作：

1. 在 `internal/biz` 定义 `AuthorizationRule`。
2. 编译配置中的 wildcard 正则规则。
3. 实现 host、method、path、user、group 匹配。
4. 忽略 query string，只使用 URI path。
5. 未命中白名单时返回无权限。

验收标准：

- 命中 prefix 规则时允许访问。
- 命中 wildcard 正则规则时允许访问。
- 未命中任何规则时返回 403。
- 用户组不满足时返回 403。

### 第八步：实现认证用例

目标：

- 串联用户、密码、失败封禁、session 和授权逻辑。

具体动作：

1. 实现 `AuthUsecase.Login`。
2. 实现 `AuthUsecase.Verify`。
3. 实现 `AuthUsecase.Logout`。
4. 实现 `AuthUsecase.Me`。
5. 登录成功后清理该 IP 和用户名的失败计数。
6. 登录失败统一返回业务层认证失败，不向 service 暴露敏感细节。

验收标准：

- 登录成功可创建 session。
- 登录失败可触发计数和审计。
- verify 能区分 401 和 403。
- logout 能删除 session。

### 第九步：实现 HTTP handler 和模板

目标：

- 暴露设计文档定义的 HTTP 接口。

具体动作：

1. 新增 `templates/login.html`。
2. 实现 `GET /login`。
3. 实现 `POST /login`。
4. 实现 `GET /auth/verify`。
5. 实现 `POST /logout`。
6. 实现 `GET /me`。
7. 实现 `GET /healthz`。
8. 实现 `GET /readyz`。
9. 在 `internal/server/http.go` 注册以上路由。

验收标准：

- 未登录访问 `/auth/verify` 返回 401。
- 已登录且授权通过返回 204。
- 已登录但未授权返回 403。
- 登录页可渲染。
- 登录成功设置 Cookie 并跳转。
- 登出清理 Cookie。

### 第十步：补充 Nginx 示例

目标：

- 让服务可以直接接入 Nginx `auth_request`。

具体动作：

1. 新增 `deploy/nginx/auth_request.conf`。
2. 写明受保护 location 示例。
3. 写明 internal auth verify location 示例。
4. 写明 401 转 302 登录页配置。
5. 写明 403 拒绝访问配置。
6. 写明必要的 `X-Original-*` 请求头。

验收标准：

- Nginx 示例和服务接口路径一致。
- 示例能表达未登录跳转、已登录放行、无权限拒绝。

### 第十一步：测试

目标：

- 用测试覆盖核心业务规则，避免实现细节偏离设计。

测试范围：

1. 配置加载测试。
2. 用户白名单测试。
3. 密码校验测试。
4. session TTL 和绝对过期测试。
5. 登录失败 3 次封禁测试。
6. 非白名单用户封禁 IP 测试。
7. 审计日志不含明文密码测试。
8. prefix 授权测试。
9. wildcard 授权测试。
10. verify 401、403、204 状态码测试。
11. redirect 只允许相对路径测试。

验收标准：

- `go test ./...` 通过。
- 关键用例不依赖真实 Nginx。
- Redis 相关测试可以用可替换 repo 或测试 Redis。

### 第十二步：清理与验收

目标：

- 清理 Kratos 示例残留，保证一期交付可读可运行。

具体动作：

1. 移除不再使用的 Greeter provider 注入。
2. 移除无用 import。
3. 运行 `go mod tidy`。
4. 运行 `go test ./...`。
5. 运行 `go build ./...`。
6. 更新 README 的启动方式。

验收标准：

- 构建通过。
- 测试通过。
- README 能指导本地启动鉴权服务。
- `doc/design/auth-service-design.md` 和本开发计划保持一致。

## 4. 风险与处理策略

### 4.1 gRPC 骨架处理

风险：

- 当前项目默认包含 gRPC server 和 greeter 示例。

处理：

- 一期不启动 gRPC server，减少无关端口和无关服务。
- 相关文件可保留但不参与 wire 注入。

### 4.2 配置 proto 与 YAML 字段不一致

风险：

- Kratos config 依赖 `conf.proto` 生成结构，YAML 字段和 proto 不一致会导致配置扫描失败。

处理：

- 第二步先完成配置 schema。
- 每次改配置字段后执行 `make config`。
- 配置加载测试必须覆盖完整样例 YAML。

### 4.3 登录失败审计文件无限增长

风险：

- 永久保存且不自动删除会持续占用磁盘。

处理：

- 一期按天切分，降低单文件过大风险。
- 服务不删除历史文件，符合设计要求。
- 后续可由运维侧做归档和容量监控。

### 4.4 Nginx 风格 wildcard 理解偏差

风险：

- 设计中的 wildcard 实际采用 Nginx 正则 location `~ pattern` 风格。

处理：

- 配置示例必须使用 `~ ^...$` 形式。
- 启动时预编译正则，正则非法则启动失败。
- 文档和错误信息明确不支持 shell glob。

## 5. 最终实施顺序摘要

1. 整理 Kratos 骨架，停用 greeter 和 gRPC。
2. 扩展 `conf.proto`，生成配置代码，更新 YAML。
3. 初始化 Redis、bcrypt、审计文件基础设施。
4. 实现 YAML 用户仓储和白名单。
5. 实现 Redis session 仓储。
6. 实现登录失败封禁和按天审计日志。
7. 实现路径白名单授权。
8. 实现登录、verify、logout、me 用例。
9. 实现 HTTP handler、登录模板和路由注册。
10. 增加 Nginx `auth_request` 示例配置。
11. 补充单元测试和集成式 handler 测试。
12. 清理 greeter 残留，运行 `go test ./...` 和 `go build ./...`。
