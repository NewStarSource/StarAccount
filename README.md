# StarAccount 新星账户

独立 Go/chi/SQLite 账户与 OIDC 服务，配合相邻 AtlasSite 使用。数据库版本 **6**。支持邀请码注册、一次性恢复码、公开资料、会话撤销、注销恢复、加密备份与凭据防回滚。

## 本地启动

需要 Go **1.27.3 或更新的修复版本**，最低模块版本 1.26.10。

```powershell
go run ./cmd/staraccount init-dev
go run ./cmd/staraccount init-oidc
go run ./cmd/staraccount generate-invite
go run ./cmd/staraccount
```

打开 http://127.0.0.1:4100。用户名 3–32 字符，密码至少 12 字符且最多 72 UTF-8 字节。邀请码单次使用，明文仅生成时输出。配置与密钥位于忽略的 `.local/`；初始化不会覆盖旧文件。生产必须生成全新密钥和空数据库，不能沿用开发账户。

## 账户恢复

注册成功后会显示一枚恢复码，仅显示一次、最长一年有效、只能使用一次。请离线保存。忘记密码从 `/forgot` 使用用户名、恢复码与新密码找回；旧会话和恢复码立即失效。已有用户从 `/security/recovery` 验证当前密码后生成或替换恢复码，旧码随即失效。

`/recover` 用于在 30 天内恢复已注销账户，要求原密码；停用账户不能通过恢复入口解封。普通备份不保存恢复码。灾难恢复后 `recovery_pending` 账户必须经运行人员独立核验本人，再使用受控命令签发 15 分钟有效码。任何找回方式都不能替代停用/注销规则。

默认生产模式为 `mail_mode=disabled`，恢复不依赖 SMTP。开发 `synthetic` 模式提供本机合成收件箱，生产禁止该模式。若未来启用 SMTP，凭据由 `STARACCOUNT_SMTP_USER/PASSWORD` 提供，必须加密连接并完成真实投递验收；邀请码账户的内部邮箱不可用于真实邮件找回。

## 检查与正式运行

```powershell
go test ./... -count=1 -timeout 120s
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
```

两端完整发布检查位于 AtlasSite 的 `scripts/check_release.py`。服务器上的原生 Linux race、vet、漏洞扫描和 HTTPS/OIDC 联调已通过；Windows 无 CGO 时不运行 race。当前生产入口为 https://account.runnewstar.xyz，星图为 https://atlas.runnewstar.xyz。

生产只监听回环地址，由同机 HTTPS 代理覆盖转发头，Cookie 使用 Secure、HttpOnly、SameSite=Lax。生产初始化脚本与 systemd 模板位于相邻 AtlasSite 仓库的 `scripts/` 和 `deploy/ubuntu/`，两端遵循相同的身份约定：

- [身份约定](../AtlasSite/docs/identity-contract.md)

凭据、数据库、日志、恢复码、二进制和部署生成文件不得入库。此仓库仍需配置自己的 Git 远端，才能接入双仓库发布 CI。
