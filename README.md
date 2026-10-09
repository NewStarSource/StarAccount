# StarAccount 新星账户

从零建设的 Go/chi/SQLite 账户服务，已完成本地邀请码账户、OIDC 联调、公开资料和恢复保护。正式规则来自 `D:/NewStarProject/SAfiles`。星图是独立的相邻 `AtlasSite` 仓库，两者不共享密码和数据库。

2026-10-06 更新见 [资料与恢复交付](docs/CORE_RECOVERY_2026-10-06.md)；跨服务验证和操作说明见相邻仓库的 [核心交付](../AtlasSite/docs/CORE_GAPS_2026-10-06.md) 与 [恢复步骤](../AtlasSite/docs/RUNBOOK_CORE.md)。数据库升级至 schema 5，迁移前先保存停机副本。当前仍仅允许回环 development/test，production 拒绝启动。

## 启动与验收

需要 Go 1.26.9 或更新版本；`go.mod` 推荐工具链为 Go 1.27.2，CI 使用相同版本。Go 1.27 分支应使用 1.27.2 或更新补丁，默认 `GOTOOLCHAIN=auto` 会按模块配置选择工具链。在本目录执行：

```powershell
go mod download
go run ./cmd/staraccount init-dev
go run ./cmd/staraccount
```

初始化只需一次，不覆盖已有配置和密钥。先生成一次性邀请码：`go run ./cmd/staraccount generate-invite`。打开 http://127.0.0.1:4100，使用用户名、至少 12 字符且不超过 72 UTF-8 字节的密码和邀请码注册；注册成功后自动登录。邀请码只可成功使用一次，明文只在命令输出中显示，数据库仅保存哈希。Ctrl+C 停止。

页面 `/register`、`/login`、`/security`、`/recover`、`/config` 均为无 JavaScript SSR 表单。注册只接受 `username/password/invite_code`；登录接受 `username/password`。邀请码消费与账户创建在同一事务中完成，重复使用、错误邀请码和已存在用户名均失败。

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
账户端点为 `/api/v1/auth/register`、`login`、`logout`、`request-reset`、`reset-password` 和 GET `session`。邀请码注册字段为 username/password/invite_code；登录字段为 username/password。新注册只接受邀请码方式，旧邮箱验证流程已移除。
注册与找回统一返回 202 REQUEST_ACCEPTED，不暴露账户或 token。JSON 正文最多 8 KiB，登录与表单均限流。

密码使用 bcrypt cost 10；会话令牌与验证令牌只存哈希；待发邮件使用 AES-GCM 加密。单 SQLite 写连接，WAL/FULL/FK，2 秒忙等待。编号迁移 `internal/account/001_init.sql`，失败不会清空或替换损坏库。

会话 7 天；链接 1 小时；已失效会话与一般安全日志最长 30 天；未验证且无有效令牌账户 24 小时后清理。注销恢复期 30 天，过期后清除凭据和个人资料。最小身份状态、会话撤销及凭据变更记录保留在独立签名清单中，不能随旧备份回滚。队列失败指数退避，第三次失败记录 permanent_failure，不返回账户专属失败状态给未认证请求。SMTP 模式成功后清空队列正文，合成邮箱仅本机可见。

真实 SMTP 适配器已写入但未联调；用户本轮选择仅本地验收。S03 已加入本地 OIDC 授权码 + PKCE、身份状态事件、会话列表与撤销、重新认证和注销恢复测试。运行 `go run ./cmd/staraccount init-oidc` 生成本地签名密钥和客户端配置，不输出密钥；真实域名、HTTPS、生产密钥和 S04 联调仍未完成。管理路由未开放。

## Git 与恢复

提交前运行上述检查。`.local/`、data、数据库、日志、二进制与凭据不得入库。
本地普通快照已采用加密备份和小时/日/月保留策略，提供 backup、diagnose、restore 命令。restore 只写新的隔离目标库，核对独立清单并清除旧会话；快照之后变更过密码的账户进入 recovery_pending，旧密码不能登录。不要删除未知数据库、回滚独立清单或手工修改迁移水位；完整步骤见相邻仓库运行手册。真实离机存储、灾难恢复和发布切换仍须实际配置与演练。

完整接口与交付记录位于相邻 `AtlasSite/docs/identity-contract.md`、`configuration.md`、`S01-S02.md`、`review-S01-S02.md`。实际 token 用量不可获取。
