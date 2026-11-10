<div align="center">

# backend-security-audit

**面向 AI 编程助手的只读后端安全审计技能（skill）。**
每个漏洞都有证据，修复以 diff 形式给出，报告按优先级排序：几分钟完成，无需离开编辑器。

[English](README.md) · [Français](README.fr.md) · [Español](README.es.md) · [Português (BR)](README.pt-BR.md) · **简体中文**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Assistants](https://img.shields.io/badge/assistants-20-informational)
![Stacks](https://img.shields.io/badge/stacks-12-informational)

</div>

支持 **Claude Code、Cursor、Codex CLI、Gemini CLI、GitHub Copilot、Windsurf、Kiro** 等 20 个助手。只需说 *“审计这个项目的安全性”*，即可得到一份 `SECURITY_AUDIT.md`：100 分制评分、按严重程度和 OWASP 类别分类的漏洞、每个漏洞的 `文件:行号` 证据，以及可直接应用的修复。

> 📄 报告示例：[exemples/SECURITY_AUDIT.md](exemples/SECURITY_AUDIT.md)（法语；报告会使用你提问的语言）

## 它能为你带来什么

- **发现通用扫描器遗漏的问题。** Supabase RLS 策略、Firebase Security Rules、PocketBase API rules、MySQL 账户、Next.js server actions：这些平台特有的漏洞正是大多数真实数据泄露的来源。
- **不编造漏洞。** 每个发现都引用 `文件:行号` 和 AI 重新读取过的代码片段，并标记为 **已确认** 或 **需人工核实**（说明核实什么、如何核实）。
- **给出修复，而不只是警告。** 每个发现都附带最小 diff，必要时还包括代码之外的操作：轮换密钥、执行迁移、修改配置。
- **优先级清晰。** 100 分制评分、按严重程度统计、汇总表，以及附带工作量估计的 **前 5 项** 修复建议。
- **设计上安全。** 严格只读：从不修改被审计的代码，不向第三方系统发送任何内容，报告中的密钥会被遮蔽。数据库扫描只在 *你自己的* 数据库上、经你同意后运行。
- **发现泄露的密钥。** 已提交的 `.env`、API 密钥、JWT、私钥、Firebase 服务账号，以及仍留在 **git 历史** 中的密钥。
- **审计真实数据库，而不只是迁移文件。** `scan_rls.sql`（Postgres/Supabase）和 `scan_mysql.sql`（MySQL/MariaDB）列出未启用 RLS 的表、过于宽松的策略、暴露的 RPC、无密码账户、可远程登录的 root 和危险授权。
- **边审计边学习。** 12 份检查清单，每个问题都有 *漏洞代码与修复代码* 对照：适合学习、团队培训和教学。
- **不依赖 AI 也能用。** 检测脚本是纯 bash：可在 CI 或 pre-commit 钩子中运行。
- **免费开源**（MIT），无需账号，无外部服务，安装后可离线使用。

**适合谁？** 上线前的独立开发者和 “vibe coder” · 向客户交付的自由职业者 · 发布前的团队 · 学生和教师 · 接手旧项目、想知道漏洞在哪里的人。

## 支持的技术栈

| 类型 | 技术栈 |
|---|---|
| 数据库 / BaaS | Supabase（Postgres + RLS）、Firebase（Firestore、Realtime Database、Storage、Cloud Functions）、PocketBase、MySQL / MariaDB |
| 后端 | 原生 PHP、Laravel、Node.js（Express、Fastify、Koa、Hono、NestJS）、Next.js、Flask、FastAPI、Django、Go（net/http、Gin、Echo、Fiber、Chi） |
| 通用 | 已提交的密钥和 `.env`、git 历史、有漏洞的依赖（`bun audit`、`npm audit`、`composer audit`、`pip-audit`、`govulncheck`）、缺少限流 |

技术栈会被自动检测，并且 **只加载相关的检查清单**。

## 安装

用 `--ai` 选择你的助手（或 `--ai all`）。不加 `--ai` 时，安装器会检测项目中已在使用的助手。

```bash
# npm / Node ≥ 18
npx github:Deathgun07/backend-security-audit init --ai claude
# Bun
bunx github:Deathgun07/backend-security-audit init --ai claude
# pnpm
pnpm dlx github:Deathgun07/backend-security-audit init --ai claude
# Yarn (Berry)
yarn dlx -p backend-security-audit@github:Deathgun07/backend-security-audit backend-security-audit init --ai claude
# curl（无需 Node：bash + curl 或 wget）
curl -fsSL https://raw.githubusercontent.com/Deathgun07/backend-security-audit/main/install.sh | bash -s -- --ai claude
```

Claude Code 插件管理器：
```
/plugin marketplace add Deathgun07/backend-security-audit
/plugin install backend-security-audit@backend-security-audit
```

`--ai` 可选值：`claude` · `cursor` · `codex` · `gemini` · `copilot` · `windsurf` · `kiro` · `antigravity` · `opencode` · `roocode` · `kilocode` · `continue` · `trae` · `qoder` · `codebuddy` · `droid` · `augment` · `warp` · `amazonq` · `universal` · `all`。完整的安装目录表见 [英文 README](README.md#installation)。

选项：`--global`（用户目录，所有项目可用）· `--force`（更新）· `--dry-run` · `list` · `uninstall`。安装后请重启助手。

## 使用

在要审计的项目根目录下，对助手说：

> *“审计这个项目的安全性”*、*“检查我的 Supabase RLS 策略”*、*“我的 Firebase 规则安全吗？”*

在 Claude Code 中也可以输入 `/backend-security-audit`。报告 `SECURITY_AUDIT.md` 会写在项目根目录，语言与你的提问一致。

### 审计你的数据库（可选）

```bash
# Supabase / Postgres（结束时回滚事务）
psql "postgresql://postgres:postgres@127.0.0.1:54322/postgres" -f .claude/skills/backend-security-audit/scripts/scan_rls.sql
# MySQL / MariaDB（只有 SELECT）
mysql -u root -p -t < .claude/skills/backend-security-audit/scripts/scan_mysql.sql
```
仅限 **你自己的** 数据库。助手绝不会在未经你同意的情况下连接数据库。

## 技能遵循的规则

1. **只读**：从不修改被审计的代码；修复以 diff 形式提出。
2. **没有证据就不报告**：`文件:行号` 加上真正重新读取过的代码片段。
3. **只有两种状态**：*已确认* 或 *需人工核实*（附说明）。
4. **不做任何攻击性操作**：只分析本地代码和你提供的自有数据库。
5. **报告中遮蔽密钥。**

## 环境要求与局限

Linux、macOS（bash ≥ 4）或 Windows 上的 WSL / Git Bash。这是 AI 辅助的静态分析，不是渗透测试：不能替代动态测试或人工审查。

## 贡献

欢迎 PR：新的检测模式、新的检查清单（Rails、Spring、ASP.NET、MongoDB…）、减少误报，以及 **翻译**。提交 PR 前请运行 `bash tests/run_tests.sh && bash tests/test_cli.sh`。

## 许可证

[MIT](LICENSE) © Deathgun07
