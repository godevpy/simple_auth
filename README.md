# Simple Auth

Go/Kratos 鉴权服务，用于对接 Nginx `auth_request` 模块。

## 功能

- 浏览器 Cookie session 登录。
- Redis 存储 session、登录失败计数和封禁状态。
- YAML 配置用户、用户白名单和路径授权规则。
- Nginx `auth_request` 鉴权接口：`GET /_auth/verify`。
- 登录失败 3 次封禁 IP 和用户名 30 分钟。
- 非白名单用户尝试登录时直接封禁来源 IP。
- 登录失败审计按天写入 JSON Lines 文件，不记录明文密码。

## 本地启动

准备 Redis：

```bash
redis-server
```

启动服务：

```bash
go run ./cmd/simple_auth -conf ./configs
```

默认 HTTP 监听地址为 `0.0.0.0:8000`。

## 主要接口

- `GET /login`：登录页。
- `POST /login`：登录提交，成功后设置 `auth_session` Cookie 并跳转。
- `GET /_auth/verify`：Nginx `auth_request` 子请求接口，成功 `204`，未登录 `401`，无权限 `403`。
- `POST /_auth/logout`：登出并清理 Cookie。
- `GET /_auth/me`：当前登录用户信息。
- `GET /_auth/healthz`：进程存活检查。
- `GET /_auth/readyz`：Redis 就绪检查。

## 配置

配置文件位于 `configs/config.yaml`。注意 Kratos protobuf Duration 使用 `1800s`、`86400s` 这类写法。

当前示例用户为 `alice`，示例密码哈希仅用于本地开发，请在生产环境替换。

服务运行日志默认输出到 stdout。如需写入指定文件，可以配置：

```yaml
logging:
  file_path: logs/simple_auth.log
```

登录失败审计日志仍由 `logging.audit.login_failure_dir` 单独控制。

## Nginx

完整接入文档见 `doc/integration/nginx-auth-request.md`，示例配置见 `deploy/nginx/auth_request.conf`。

核心约定：

- `/_auth/verify` 不直接返回 `302`。
- 未登录返回 `401`，由 Nginx 使用 `error_page 401 =302 /login?redirect=$request_uri` 跳转登录页。
- 已登录但无权限返回 `403`。
- `/login`、`/_auth/logout`、`/_auth/verify` 都需要透传原始业务域名，保证按域名隔离的 session 能正确匹配。

## 验证

```bash
go test ./...
go build ./...
```

## 安装

Linux/systemd 环境可以使用：

```bash
sudo make install
sudo systemctl enable --now simple_auth.service
sudo systemctl status simple_auth.service
```

默认安装位置：

- 二进制：`/usr/local/bin/simple_auth`。
- 应用资源：`/opt/simple_auth`。
- 配置文件：`/opt/simple_auth/configs/config.yaml`。
- systemd service：`/etc/systemd/system/simple_auth.service`。

`make install` 会自动执行 `make service-check`，检查二进制、配置、登录模板和 service 文件是否安装完整；如果本机存在 `systemd-analyze`，还会校验 service 文件。再次安装时不会覆盖已有 `config.yaml`，只会更新 `config.yaml.example`。

可以通过变量调整安装路径：

```bash
sudo make install PREFIX=/usr/local APP_DIR=/opt/simple_auth SYSTEMD_DIR=/etc/systemd/system
```

## 发布

推送任意 Git tag 会触发 GitHub Actions 自动发布 Release：

```bash
git tag v0.1.0
git push origin v0.1.0
```

Release 会包含 Linux、macOS、Windows 的 amd64 和 arm64 二进制包，以及 `SHA256SUMS` 校验文件。
