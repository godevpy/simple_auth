# Nginx Auth Request 接入文档

本文说明如何将 Simple Auth 接入 Nginx `auth_request` 模块，为后端业务服务提供统一登录鉴权。

## 1. 接入目标

接入后，请求链路如下：

1. 浏览器访问 Nginx 上的受保护路径。
2. Nginx 发起内部子请求 `/_auth/verify`。
3. Simple Auth 校验 Cookie session 和路径白名单。
4. 鉴权通过时，Nginx 转发请求到后端业务服务。
5. 未登录时，Nginx 将 `401` 转成 `302` 并跳转到 `/login`。
6. 已登录但无权限时，Nginx 返回 `403`。

## 2. 服务接口

当前服务路由：

```text
GET  /login
POST /login
GET  /_auth/verify
POST /_auth/logout
GET  /_auth/me
GET  /_auth/healthz
GET  /_auth/readyz
```

状态码约定：

- `/_auth/verify` 返回 `204`：已登录且路径授权通过。
- `/_auth/verify` 返回 `401`：未登录、Cookie 缺失、session 过期或 session 无效。
- `/_auth/verify` 返回 `403`：已登录，但不满足路径白名单规则。
- `/login` 登录成功返回 `302` 并设置 `auth_session` Cookie。
- `POST /_auth/logout` 返回 `302` 并清理 `auth_session` Cookie。

## 3. 接入前检查

接入前请确认：

- Nginx 已启用 `ngx_http_auth_request_module`。
- 浏览器到 Nginx 的入口使用 HTTPS，生产环境保持 `secure_cookie: true`。
- Nginx 能访问 Simple Auth 服务，Simple Auth 能访问 Redis。
- `/login`、`/_auth/logout`、`/_auth/verify` 都必须透传原始业务域名，否则开启按域名隔离 session 后，登录和鉴权会落到不同域名命名空间。
- 业务服务如果希望完全无感，只需要接入 `auth_request`；如果希望读取当前用户，再额外透传 `X-Auth-*` 头。

## 4. 推荐 Nginx 配置

示例：

```nginx
# upstream 放在 http {} 内。
upstream auth_service {
    server 127.0.0.1:8000;
}

upstream backend {
    server 127.0.0.1:8080;
}

server {
    listen 443 ssl http2;
    server_name app.example.com;

    # ssl_certificate     /path/to/fullchain.pem;
    # ssl_certificate_key /path/to/privkey.pem;

    location /private/ {
        auth_request /_auth/verify;

        error_page 401 =302 /login?redirect=$request_uri;
        error_page 403 = /403.html;

        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        proxy_pass http://backend;
    }

    location = /_auth/verify {
        internal;
        proxy_pass http://auth_service/_auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";

        proxy_set_header Host $host;
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header X-Original-Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location /login {
        proxy_pass http://auth_service;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    location = /_auth/logout {
        proxy_pass http://auth_service;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

说明：

- `location = /_auth/verify` 建议配置为 `internal`，避免外部用户直接访问鉴权子请求。
- `proxy_pass_request_body off` 和空 `Content-Length` 可避免把原始请求体发送给鉴权服务。
- `X-Original-*` 请求头用于路径授权判断，必须传递。
- `/login` 不能配置 `internal`，浏览器需要直接访问登录页。
- `/login` 和 `/_auth/logout` 也要传 `Host` 或 `X-Forwarded-Host`，保证 session 的域名命名空间和 `/_auth/verify` 一致。
- `/_auth/logout` 只支持 `POST`，页面上建议用表单或前端请求触发登出。

## 5. 透传用户信息

如果后端业务服务需要用户信息，可以在受保护 location 中增加：

```nginx
auth_request_set $auth_user $upstream_http_x_auth_user;
auth_request_set $auth_user_id $upstream_http_x_auth_user_id;
auth_request_set $auth_groups $upstream_http_x_auth_groups;

proxy_set_header X-Auth-User $auth_user;
proxy_set_header X-Auth-User-ID $auth_user_id;
proxy_set_header X-Auth-Groups $auth_groups;
```

如果后端完全无感，可以不加这些头。

## 6. Simple Auth 配置

配置文件为 `configs/config.yaml`。

关键配置：

```yaml
session:
  cookie_name: auth_session
  cookie_domain: ""
  idle_timeout: 1800s
  absolute_timeout: 86400s
  sliding_expiration: true
  secure_cookie: true
  same_site: Lax
  per_host_namespace: true

authorization:
  enabled: true
  mode: whitelist

logging:
  # Empty means stdout. Set a file path to append service logs to that file.
  file_path: ""
```

注意：

- Kratos protobuf Duration 使用 `1800s`、`86400s` 这类写法，不使用 `30m`、`24h`。
- `cookie_domain: ""` 表示不设置 Cookie Domain，让 Cookie 按当前域名独立保存。
- `secure_cookie: true` 表示 Cookie 只会在 HTTPS 下发送。
- 本地 HTTP 联调时，如果依赖浏览器或 `requests.Session()` 自动带 Cookie，需要临时设置 `secure_cookie: false`，或者在测试脚本里显式传 `Cookie` 头。
- 多域名共用同一个鉴权服务时，推荐保持 `cookie_domain: ""` 和 `per_host_namespace: true`，每个域名独立登录、独立登出、独立 session。
- 如果前面还有 SLB、Ingress 或 CDN 终止 TLS，Nginx 到鉴权服务可以走内网 HTTP，但浏览器入口仍需要 HTTPS。
- `logging.file_path` 为空或 `stdout` 时服务运行日志输出到标准输出；也可以设置为 `logs/simple_auth.log` 这类文件路径。
- 登录失败审计日志和服务运行日志分开配置，审计日志目录由 `logging.audit.login_failure_dir` 控制。

## 7. 路径白名单

授权规则采用白名单逻辑：

- `authorization.enabled=false`：只校验登录态，不做路径授权。
- `authorization.enabled=true`：只有命中白名单规则才放行。
- 未命中任何规则时，返回 `403`。

示例：

```yaml
authorization:
  enabled: true
  mode: whitelist
  rules:
    - name: admin-only
      hosts:
        - admin.example.com
      path_match: prefix
      paths:
        - /admin/
      methods:
        - GET
        - POST
      allow_groups:
        - admin

    - name: ops-wildcard
      hosts:
        - app.example.com
      path_match: wildcard
      paths:
        - "~ ^/ops/[^/]+/dashboard$"
      methods:
        - GET
      allow_users:
        - alice
```

匹配规则：

- `prefix` 对齐 Nginx 普通前缀 location 语义。
- `wildcard` 使用 Nginx 正则 `location ~ pattern` 风格。
- query string 不参与匹配。
- `hosts`、`methods` 为空时表示不限制。
- `allow_groups`、`allow_users`、`allow_user_ids` 都为空时，表示任意已登录用户可访问该规则匹配的路径。
- `hosts` 会做小写和去端口归一化，例如 `APP.EXAMPLE.COM:443` 会按 `app.example.com` 匹配。

## 8. 用户和密码哈希

用户在 YAML 中配置：

```yaml
users:
  - id: user-001
    username: alice
    display_name: Alice
    password_hash: "$2a$10$..."
    groups:
      - admin
```

生成 bcrypt 密码哈希：

```bash
python3 tools/password_generate.py
```

或直接传入密码：

```bash
python3 tools/password_generate.py --password 'your-password'
```

生成登录失败审计用 HMAC 密钥：

```bash
python3 tools/password_generate.py --hmac-secret
```

填入：

```yaml
security:
  login_failure:
    password_attempt_hmac_secret: "生成的随机字符串"
```

说明：

- `password_hash` 使用 bcrypt，不保存明文密码。
- `password_attempt_hmac_secret` 用于给登录失败时尝试的密码生成 HMAC 指纹，方便审计相同密码尝试，同时不把明文密码写入日志。
- 生产环境请替换示例用户、示例密码和默认 `change-me-in-production`。

## 9. 本地启动和联调

启动 Redis：

```bash
redis-server
```

启动鉴权服务：

```bash
go run ./cmd/simple_auth -conf ./configs
```

运行 HTTP 测试脚本：

```bash
python3 tools/tests.py
```

如果本地使用 HTTP 且 `secure_cookie: true`，测试脚本会显式传递 Cookie；浏览器手工测试建议临时改成：

```yaml
session:
  secure_cookie: false
```

生产环境请保持：

```yaml
session:
  secure_cookie: true
```

## 10. 常见问题

### 10.1 登录成功后 `/_auth/verify` 仍然返回 401

常见原因：

- 本地使用 HTTP，但 Cookie 设置了 `Secure`，浏览器或 HTTP 客户端不会自动发送 Cookie。
- Nginx 子请求没有透传浏览器 Cookie。
- `proxy_pass` 路径写错，应该转发到 `http://auth_service/_auth/verify`。
- `/login` 没有透传原始 `Host` 或 `X-Forwarded-Host`，导致 session 保存到了 `auth_service` 域名命名空间。
- Redis 中 session 已过期或 Redis key 前缀配置不一致。

排查建议：

- 查看登录响应是否有 `Set-Cookie: auth_session=...`。
- 查看后续请求是否带 `Cookie: auth_session=...`。
- 查看 Nginx access log，确认 `/login`、`/_auth/logout`、`/_auth/verify` 使用同一个业务域名。
- 本地 HTTP 联调时临时设置 `secure_cookie: false`，或显式加 Cookie 头。

### 10.2 已登录但返回 403

常见原因：

- `X-Original-Host` 和 YAML 中 `authorization.rules.hosts` 不匹配。
- `X-Original-URI` 路径没有命中白名单。
- 用户不属于 `allow_groups`。
- 用户名不在 `allow_users`。
- HTTP method 不在规则的 `methods` 中。

排查建议：

- 检查 Nginx 是否设置了 `X-Original-Host $host`。
- 检查路径规则是否使用正确的 `prefix` 或 `wildcard`。
- 检查用户配置里的 `groups`。

### 10.3 登出返回 405

`/_auth/logout` 只支持 `POST`。如果页面上是普通链接跳转，会发起 `GET` 请求并返回 `405`。

推荐使用表单：

```html
<form method="post" action="/_auth/logout">
  <button type="submit">退出登录</button>
</form>
```

### 10.4 登录失败很快被封禁

默认策略：

- 登录失败达到 3 次后封禁 IP 和用户名 30 分钟。
- 非白名单用户尝试登录时直接封禁来源 IP。

本地调试可以临时放宽：

```yaml
security:
  login_failure:
    max_attempts: 300
    ban_ip: false
    ban_user: false
```

生产环境不建议关闭封禁。

### 10.5 Duration 配置报错

Kratos protobuf Duration 配置需要使用：

```yaml
idle_timeout: 1800s
absolute_timeout: 86400s
```

不要写：

```yaml
idle_timeout: 30m
absolute_timeout: 24h
```

## 11. 验收清单

接入完成后，建议检查：

- 未登录访问受保护路径会跳转 `/login`。
- 登录成功后返回原始 `redirect` 地址。
- 登录后访问允许路径，`/_auth/verify` 返回 `204`。
- 登录后访问未授权路径，`/_auth/verify` 返回 `403`。
- 登出后再次访问受保护路径会重新跳转登录。
- `/login`、`/_auth/logout`、`/_auth/verify` 透传的业务域名一致。
- 生产环境 Cookie 带 `Secure` 和 `HttpOnly`。
- 登录失败审计文件按天写入 `logs/login_failure_audit-YYYY-MM-DD.jsonl`。
- `/_auth/readyz` 在 Redis 不可用时返回 `503`，可用于发布前就绪检查。
