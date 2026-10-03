# StarAccount 新星账户

从零建设的 Go/chi/SQLite 账户服务，S01/S02 本地合成版本。正式规则来自 `D:/NewStarProject/SAfiles`。星图是独立的相邻 `AtlasSite` 仓库，两者不共享密码和数据库。

## 启动与验收

需要 Go 1.26.6 或更新版本，本次验证 Go 1.27.1。在本目录执行：

```powershell
go mod download
go run ./cmd/staraccount init-dev
go run ./cmd/staraccount
```

初始化只需一次，不覆盖已有配置和密钥。打开 http://127.0.0.1:4100 ，使用 `reader@example.com` 等虚构邮箱和至少 12 字符、至多 72 UTF-8 字节的测试密码。注册后等待约一秒，打开“合成测试收件箱”，确认验证，然后登录、退出、找回密码。邮件不外发。Ctrl+C 停止。

页面 `/register`、`/login`、`/forgot`、`/verify`、`/reset`、`/config` 均为无 JavaScript SSR 表单。令牌 GET 不消费，POST 需 CSRF。重复注册未验证邮箱使旧验证链接失效，重复点击已消费链接返回可理解错误。

## 检查

```powershell
go test ./... -count=1
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

测试用临时 SQLite 文件和合成数据，不读取运行中的演示账户。CI 还在 Linux 执行 race 检测；当前 Windows 未启用 CGO，不宣称本地 race 已通过。

## 配置、API 与数据

配置保存在 `.local/development.json`，密钥是 `.local/development.keys` 中 96 个随机字节。配置文件路径通过 `-config` 指定；development/test 只允许回环监听，生产模式拒绝启动。
测试实例请使用独立 database 和 key_file、端口/origin；不要复制开发数据库去做真实用户测试。

`GET /health`、`GET /api/v1/config` 提供状态；`GET /api/v1/csrf` 获得 API 请求的 CSRF token（同时保留 cookie），之后 POST 使用同源 Origin 与 X-CSRF-Token。
账户端点为 `/api/v1/auth/register`、`verify-email`、`login`、`logout`、`request-reset`、`reset-password` 和 GET `session`。字段为 email/password/token，按相应操作提供。
注册与找回统一返回 202 REQUEST_ACCEPTED，不暴露账户或 token。JSON 正文最多 8 KiB，登录与表单均限流。

密码使用 bcrypt cost 10；会话令牌与验证令牌只存哈希；待发邮件使用 AES-GCM 加密。单 SQLite 写连接，WAL/FULL/FK，2 秒忙等待。编号迁移 `internal/account/001_init.sql`，失败不会清空或替换损坏库。

会话 7 天；链接 1 小时；已失效会话与安全日志最长 30 天；未验证且无有效令牌账户 24 小时后清理。队列失败指数退避，第三次失败记录 permanent_failure，不返回账户专属失败状态给未认证请求。SMTP 模式成功后清空队列正文，合成邮箱仅本机可见。

真实 SMTP 适配器已写入但未联调；用户本轮选择仅本地验收。S03 已加入本地 OIDC 授权码 + PKCE、身份状态事件、会话列表与撤销、重新认证和注销恢复测试。运行 `go run ./cmd/staraccount init-oidc` 生成本地签名密钥和客户端配置，不输出密钥；真实域名、HTTPS、生产密钥和 S04 联调仍未完成。管理路由未开放。

## Git 与恢复

提交前运行上述检查，建议 `feat: establish S01 S02 local baseline`。`.local/`、data、数据库、日志、二进制与凭据不得入库；本次不自动提交或推送。
恢复本地合成版本时先停止进程，保存整个受限 `.local` 目录；通过配置的新数据库路径建立空白演示，旧库保留可恢复。不要删除未知数据库或手工修改迁移水位。正式备份恢复与强制撤销旧凭据在 S10 验收。

完整接口与交付记录位于相邻 `AtlasSite/docs/identity-contract.md`、`configuration.md`、`S01-S02.md`、`review-S01-S02.md`。实际 token 用量不可获取。
