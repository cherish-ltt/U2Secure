# U2Secure — Linux 服务器安全加固 CLI 工具

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

面向 Linux 运维人员的交互式安全加固工具。运行一次即可完成从系统更新、用户创建、SSH 深度加固、防火墙、入侵防御、审计到自动更新的完整安全基线建设。

## 目录

- [概述](#概述)
- [快速开始](#快速开始)
- [功能详解](#功能详解)
  - [Step 0：环境审计](#step-0环境审计)
  - [Step 1 ~ Step 12：加固步骤](#step-1--step-12加固步骤)
- [安全回退机制](#安全回退机制)
- [常见问题](#常见问题)

---

## 概述

### 设计目标

- 首次运行自动审计系统当前安全状态，对已加固项目标记"安全可靠"（**幂等**）
- 向导式交互（`dialoguer` 多选/输入/确认），每步执行前检测状态，不重复配置
- 所有系统修改前自动备份，Ctrl+C 中断或步骤失败时自动回退

### 适用范围

| 项目 | 支持情况 |
|------|---------|
| 发行版 | Debian/Ubuntu（首选），兼容 RHEL/CentOS（yum/dnf） |
| 权限 | **必须以 root 运行**，审计阶段只读不写 |
| 内核 | Linux 3.10+ |
| SSH 服务 | OpenSSH（sshd） |
| 防火墙 | UFW（首选），检测到 firewalld 时提示适配 |

### 项目结构

```
src/
├── main.rs                 # 入口：初始化信号处理器，启动 CLI
├── domain/                 # 领域层（零外部依赖）
│   ├── audit.rs            # AuditReport（审计报告实体）、AuditStatus、PackageManager
│   ├── steps.rs            # StepKind、HardeningStep trait、ExecuteParams、SshKeyAction
│   ├── errors.rs           # DomainError
│   └── undo.rs             # UndoAction（可撤销操作值对象）
├── application/            # 应用层
│   ├── orchestrator.rs     # HardeningOrchestrator：编排审计→选择→执行→回退
│   └── steps.rs            # 12 个步骤的具体实现
├── infrastructure/         # 基础设施
│   ├── system.rs           # 系统命令执行、配置解析、用户管理、密钥管理
│   ├── logger.rs           # 日志记录（含公钥脱敏）
│   └── rollback.rs         # 回退管理器：全局 undo 栈 + Ctrl+C 信号处理
└── presentation/           # 表示层
    └── cli.rs              # dialoguer 交互式 CLI：审计渲染、步骤选择、参数收集
```

---

## 快速开始

### 安装

```bash
# 克隆并编译
git clone <repo-url> u2secure
cd u2secure
cargo build --release

# 二进制位于 target/release/u2secure
sudo cp target/release/u2secure /usr/local/bin/
```

### 运行

```bash
sudo u2secure
```

首次运行会自动执行环境审计并展示报告，然后通过向导选择要执行的加固步骤。

### 完整示例

以下是一次典型运行过程（从审计到加固完成）：

```bash
# 1. 以 root 运行
$ sudo u2secure

# 2. 自动输出环境审计报告（只读）
# ──────────────────────────────────────────────
# ✅ 当前用户权限: 已以 root 运行
# ✅ 包管理器: 检测到 apt
# ❌ SSH 端口: 默认端口 22
# ❌ 密码登录: 密码登录未禁用
# ❌ root 登录: root 登录未禁止
# ❌ sudo 用户: 未检测到非 root 管理用户
# ❌ Fail2ban: 未安装
# ❌ UFW 防火墙: 未启用
# ❌ 自动安全更新: 未启用
# 🔄 系统更新状态: 缓存已过期
# ──────────────────────────────────────────────

# 3. 选择要执行的步骤（默认勾选未配置项）
# 4. 交互式输入参数（用户名、端口、密钥等）
# 5. 自动执行并输出总结报告
```

---

## 功能详解

### Step 0：环境审计

运行任何修改前，工具会**只读**扫描系统，输出"当前安全状态报告"。检测项包括：

| 检测项 | 方式 | 识别结果 |
|--------|------|---------|
| root 权限 | `id -u` | 非 root 禁止执行 |
| 包管理器 | `which apt/yum/dnf` | 确定后续安装命令 |
| SSH 端口 | 解析 `/etc/ssh/sshd_config` 中 `Port` | 非 22 标记"已自定义" |
| 密码登录 | 检查 `PasswordAuthentication` + `ChallengeResponseAuthentication` | 均为 no 标记"已禁用" |
| root 登录 | 检查 `PermitRootLogin` | no/prohibit-password 标记"已禁止" |
| sudo 用户 | `getent group sudo`，过滤 UID≥1000 | 标记已有管理用户列表 |
| fail2ban | `which fail2ban-server` | 标记状态及版本 |
| UFW | `ufw status` | 标记启用状态及规则摘要 |
| 自动更新 | 检查 `unattended-upgrades` 配置或 systemd timer | 标记启用状态 |
| 系统更新 | 检查缓存文件时间戳（7 天内为最新） | 标记"需要更新"或"已最新" |

### Step 1 ~ Step 12：加固步骤

| 步骤 | 功能 | 幂等检查 | 交互需求 | 回退操作 |
|------|------|---------|---------|---------|
| 1. 系统更新 | `apt update && apt upgrade -y` | 检查缓存是否过期 | 无 | 不可回退（仅记录日志） |
| 2. 非 root 用户创建 | `useradd` + `usermod -aG sudo` + `passwd -l` + 自动生成 ED25519 密钥 | 检查是否有 sudo 用户 | 用户名、是否锁定密码 | `userdel -r <username>` |
| 3. 禁止 root SSH 登录 | `sshd_config` 中 `PermitRootLogin prohibit-password` | 检查当前配置值 | 无 | 从 `.bak` 恢复 |
| 4. SSH 端口修改 | 修改 `Port` 指令，UFW 放行新端口 | 端口是否为 22 | 新端口号 | 恢复备份 + 删除 UFW 规则 |
| 5. 禁止密码登录 | 修改 `PasswordAuthentication` 和 `ChallengeResponseAuthentication` | 检查当前配置值 | **前置条件**：必须有 sudo 用户 | 从 `.bak` 恢复 |
| 6. ED25519 密钥设置 | 生成新密钥对 / 粘贴已有公钥到 `authorized_keys` | 检查 `authorized_keys` 是否存在 | 用户选择 + 密钥内容 | 删除生成的文件 |
| 7. UFW 防火墙配置 | `ufw allow {port}` + `ufw --force enable` | 检查 UFW 是否已启用 | 无 | 删除规则 + 关闭 UFW（如之前未启用） |
| 8. Fail2ban 安装配置 | 安装 fail2ban，配置监狱规则（用当前 SSH 端口） | 检查 `fail2ban-server` 路径 | 无 | `systemctl stop` + `apt remove` |
| 9. 自动安全更新 | 安装 `unattended-upgrades`，写入 APT 定时配置 | 检查服务或配置文件 | 无 | `systemctl stop` + `apt remove` |
| 10. 安全扫描 | 安装 lynis 并执行 `lynis audit system --quick` | 检查 `which lynis` | 无 | `apt remove lynis` |
| 11. 日志与审计增强 | 安装 logwatch + aide，配置 cron 日报，初始化 aide 数据库 | 检查 `which logwatch/aide` | 无 | `apt remove logwatch aide` |
| 12. SSH 服务重启 | `sshd -t` 验证语法 → `systemctl restart sshd` → 确认状态 | 始终执行（语法验证） | 无 | 从 `.bak` 恢复后重启 |

#### 步骤 2 详解：非 root 用户创建

```bash
# 工具内部实际执行的命令序列：
useradd -m -s /bin/bash deploy          # 创建用户
usermod -aG sudo deploy                 # 加入 sudo 组
passwd -l deploy                        # 锁定密码（强制密钥登录）
ssh-keygen -t ed25519 -f /home/deploy/.ssh/id_ed25519 -N "" -q  # 生成密钥
chmod 600 /home/deploy/.ssh/authorized_keys  # 权限修正
chown -R deploy:deploy /home/deploy/.ssh/
```

#### 步骤 4 详解：SSH 端口修改

```bash
# 工具内部逻辑：
# 1. 读取当前端口（默认 22）
# 2. 随机生成建议端口（1024-65535，避开常见服务端口）
# 3. 用户确认或输入新端口
# 4. 备份 /etc/ssh/sshd_config → /etc/ssh/sshd_config.bak.{时间戳}
# 5. 写入 Port {新端口}
# 6. 如果 UFW 已启用，执行 ufw allow {新端口}
```

#### 步骤 6 详解：ED25519 密钥设置

```bash
# 选项 A：生成新密钥对
ssh-keygen -t ed25519 -f /home/{user}/.ssh/id_ed25519 -N "" -q

# 选项 B：粘贴已有公钥
echo "{公钥内容}" >> /home/{user}/.ssh/authorized_keys
chmod 600 /home/{user}/.ssh/authorized_keys
chown {user}:{user} /home/{user}/.ssh/authorized_keys
```

---

## 安全回退机制

### 触发条件

| 场景 | 行为 |
|------|------|
| 用户在任意时刻按 `Ctrl+C` | 设置中断标记 → 当前步骤完成后，主线程检测到标记 → 逆序执行所有已注册的撤销操作 |
| 某一步骤执行失败（如 `apt install` 返回非零） | 停止后续步骤 → 自动调用 `undo_all()` → 逆序回退已完成步骤的修改 |

### 回退过程

回退按 **后进先出（LIFO）** 顺序执行。例如，如果用户依次执行了"创建用户"→"修改 SSH 端口"→"启用 UFW"，回退顺序为：

```
1. 关闭 UFW（如果之前未启用）
2. 删除 UFW 端口放行规则
3. 从备份恢复 sshd_config（撤销端口修改）
4. 删除用户
```

每个回退操作输出到 stderr：

```
  ⮐  恢复 sshd_config（Port）
  ⮐  停止 unattended-upgrades 服务
  ⮐  删除 unattended-upgrades
```

### 备份文件位置

修改 `sshd_config` 前自动备份到 `/etc/ssh/sshd_config.bak.{YYYYMMDDHHMMSS}`。回退时自动恢复备份并清理备份文件。

### 日志

所有操作记录到 `/var/log/secure-init.log`（不可用时 fallback 到 `./secure-init.log`）。日志中公钥内容自动脱敏（仅显示指纹或截断内容）。

---

## 常见问题

### Q：必须以 root 运行吗？

是的。审计阶段会检测 UID，非 root 用户直接退出。大部分操作（安装包、修改 `sshd_config`、管理用户、配置防火墙）均需要 root 权限。

### Q：遇到 `sshd_config 语法错误` 怎么办？

SSH 相关步骤在修改配置后会自动执行 `sshd -t` 验证语法。如验证失败，**不会**重启 SSH 服务，保护当前连接。备份文件位于 `/etc/ssh/sshd_config.bak.*`，可手动恢复：

```bash
# 查找最新备份
ls -t /etc/ssh/sshd_config.bak.* | head -1 | xargs -I{} cp {} /etc/ssh/sshd_config
systemctl restart sshd
```

### Q：密钥生成时提示 `私钥无密码短语保护`？

工具默认生成空密码的 ED25519 密钥（`-N ""`），方便自动化部署。如需密码短语保护：

```bash
ssh-keygen -p -f ~/.ssh/id_ed25519   # 之后设置密码
```

### Q：我手动修改了配置，工具会覆盖吗？

**不会**。每个步骤执行前会检测当前状态。例如 Step 3（禁止 root SSH 登录）检测到 `PermitRootLogin` 已设置为 `no` 或 `prohibit-password` 时，会标记为"✅ 已安全配置"并默认跳过。但用户可以在步骤选择界面**主动勾选**来重新执行覆盖。

### Q：Deiban 以外的发行版支持情况？

| 功能 | Debian/Ubuntu (apt) | RHEL/CentOS (yum/dnf) |
|------|--------------------|-----------------------|
| 系统更新 | ✅ | ✅ |
| 用户创建 | ✅ | ✅（sudo 组名可能需 wheel） |
| SSH 配置 | ✅ | ✅ |
| UFW | ✅ | ❌（检测到 firewalld 会提示） |
| Fail2ban | ✅ | ✅ |
| 自动更新 | ✅（unattended-upgrades） | ❌ |
| Lynis | ✅ | ✅ |

### Q：中断后如何确认系统状态？

```bash
# 查看操作日志
cat /var/log/secure-init.log

# 检查 SSH 配置是否被修改过
diff /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.*

# 检查用户是否被创建
getent group sudo

# 检查 UFW 状态
ufw status
```

## 许可证

[MIT](LICENSE) © 2026 u2secure

本软件按 MIT 许可证开源。使用时需保留版权声明和许可声明。

