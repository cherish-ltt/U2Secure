# AGENTS.md

本文件定义了本项目的 Rust 开发规范与自动化流程。所有贡献者必须严格遵守，并在每次修改代码后及时更新本文件（如有新增规范或调整）。

---

## 1. Git 提交规范

- **范围**：每次提交应独立且完整地对应一个逻辑变更（如单一功能点、缺陷修复或配置调整），禁止混合多个不相关改动；按功能批次顺序组织，单次提交代码变动量建议控制在 300 行以内(仅建议，非强制，可适当突破)，避免大批量改动挤在同一条提交信息中。
- **格式**：`<type>: <中文描述>`
- **常用 type**：
  - `feat` – 新功能
  - `fix` – 修复 bug
  - `docs` – 文档更新
  - `style` – 代码格式（不影响逻辑）
  - `refactor` – 重构
  - `perf` – 性能优化
  - `test` – 测试相关
  - `build` – 构建系统或外部依赖变更
  - `ci` – CI 配置变更
  - `chore` – 杂项（如工具、配置等）
  - `revert` – 回退提交

示例：`feat: 添加用户登录接口`

---

## 2. Rust CI 标准（GitHub Actions）

确保 `.github/workflows/rust-ci.yml` 存在，内容如下：

```yaml
name: Rust CI

on:
  push:
    branches: [ "main", "master" ]
    paths:
      - "**.rs"
      - "**.proto"
      - "**/Cargo.toml"
      - "**/Cargo.lock"
      - ".rustfmt.toml"
      - ".clippy.toml"
      - "rust-toolchain.toml"
      - ".github/workflows/rust-ci.yml"
  pull_request:
    branches: [ "main", "master" ]
    paths:
      - "**.rs"
      - "**.proto"
      - "**/Cargo.toml"
      - "**/Cargo.lock"
      - ".rustfmt.toml"
      - ".clippy.toml"
      - "rust-toolchain.toml"
      - ".github/workflows/rust-ci.yml"

env:
  CARGO_TERM_COLOR: always

concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true

jobs:
  check:
    name: Check & Test
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Install Rust toolchain
        uses: dtolnay/rust-toolchain@master
        with:
          toolchain: "1.98.1"
          components: rustfmt, clippy

      - name: Show rustup info
        run: rustup show

      - name: Cache Cargo dependencies
        uses: Swatinem/rust-cache@v2

      - name: Check formatting
        run: cargo fmt --all -- --check

      - name: Run Clippy (lints)
        run: cargo clippy --all-targets -- -D warnings

      - name: Build the project
        run: cargo build --verbose

      - name: Run tests
        run: cargo test --verbose

```

---

## 3. Cargo.toml 配置

- 必须包含完整的包元数据（满足可发布到 [crates.io](https://crates.io) 的要求），例如：
  - `name`、`version`、`edition`、`authors`、`description`、`license`、`repository` 等。
- 依赖项必须**归类**，使用 `#` 注释说明每组依赖的用途。
- 每个依赖必须使用 `version = "x.y.z"` **锁定具体版本**（使用 `=` 号），不得使用范围限定符。
- 使用 `edition = "2024"` 以及环境中的 Rust 版本，例如:`rust-version = "1.95"`

示例结构：

```toml
[package]
name = "my_crate"
version = "0.1.0"
edition = "2024"
rust-version = "1.95"
authors = ["Your Name <email@example.com>"]
description = "A short description"
license = "MIT OR Apache-2.0"
repository = "https://github.com/your/repo"

# 核心依赖
[dependencies]
# 序列化
serde = { version = "=1.0.210", features = ["derive"] }

# 异步并发
tokio = { version = "=1.42.0", features = ["full"] }

# 开发依赖
[dev-dependencies]
# 基准测试
criterion = { version = "=0.5.1" }

# 编译优化配置
[profile.dev]
opt-level = 1
[profile.dev.package."*"]
opt-level = 3
```

---

## 4. 代码格式化（.rustfmt.toml）

项目根目录必须包含 `.rustfmt.toml`，内容如下：

```toml
edition = "2024"
max_width = 100
tab_spaces = 4
reorder_imports = true
reorder_modules = true
newline_style = "Auto"
match_block_trailing_comma = true
```

所有代码必须通过 `cargo fmt --all -- --check` 检查。

---

## 5. Clippy 配置（.clippy.toml）

项目根目录必须包含 `.clippy.toml`，内容如下：

```toml
# ── Clippy Configuration ──
cognitive-complexity-threshold = 15
too-many-arguments-threshold = 5
too-many-lines-threshold = 30
allow-unwrap-in-tests = true
msrv = "1.98.1"
```

所有代码必须通过 `cargo clippy --all-targets -- -D warnings` 检查，无警告。

---

## 6. README.md

- 每次完成任务后需及时更新 `README.md`，至少包含：
  - 项目简介
  - 构建与运行说明
  - 主要功能或使用示例
  - 贡献指南（引用本 AGENTS.md）

---

## 7. .gitignore

必须排除以下内容（示例）：

```
# Rust
/target/
**/*.rs.bk
*.pdb

# macOS
.DS_Store

# IDE
.vscode/
.idea/
*.swp
```

---

## 8. 项目结构

- **使用DDD+洋葱结构，严格遵循此结构开发**
- **禁止单`mod.rs`文件写入大量代码，代码较多时候将代码拆分到更小的带具体名称的代码文件中(如 utils.rs)**
- **保持单代码文件简洁和更细致的 crate 划分以加速增量编译**

---

## 9. 通用原则

- **保持本文件（AGENTS.md）更新**：每次修正代码或引入新规范后，请同步更新此文档。
- **所有变更**必须通过 CI 检查（格式、lint、构建、测试）。
- **版本锁定**：工具链版本统一使用环境中的版本，但需>=1.98.1（如 CI 和 clippy 配置所示）。
- **遵循设计**：改动必须遵循原有结构设计，不得私自添加和修改，除非用户发出明确重构指令。
- **后续开发追加 AGENTS.md 内容**：写入第 10 章节。
- **测试**：编写单元测试，如果已经安装`cargo-llvm-cov`则检测测试覆盖率>=80%。
- **隐私**：任何文件/代码/图片/视频，应注意避免隐私泄露。(只关注项目文件本身，不关注 git 等外部工具)

---

**本文件是项目的“开发宪法”，所有 pull request 和代码审查均应参照其内容。**

## 10. 其他追加内容

### 后台事件接收

- `JobHandle::drain()` 是界面事件接收与断连判定的唯一入口；`is_disconnected()` 只读取最近一次 drain 的状态，禁止通过额外接收探测连接而丢弃业务事件。

### APT 索引刷新

- 镜像预热和系统更新统一通过 `build_pm_argv` 为 APT `update` 添加 `APT::Update::Error-Mode=any`，禁止按本地化 warning 文本推断成功。

### 受管命令生命周期

- Unix 长耗时命令必须使用独立进程组；超时、取消、无输出和等待失败统一终止该组并回收直接子进程，禁止按名称全局杀进程。
- `tests/process_tests.rs` 仅启动无害 shell 并写临时标记；主动脱离进程组的守护进程不属于普通派生进程保证。

### 批次撤销边界

- `StepRunner` 串行管理全局撤销栈与中断标记；失败或取消只撤销当前批次，正常完成后丢弃本批撤销记录但保留备份供人工恢复。
- 执行器回归测试必须在假步骤执行期间登记撤销，覆盖连续批次与可选步骤失败，禁止用真实加固命令验证。
- 可失败撤销使用 `UndoAction::try_new()` 返回错误；文件恢复失败必须保留备份，执行器将失败明细加入结果，禁止仅打印动作名或无条件宣称全部恢复。
- 用户撤销必须检查 `userdel` 启动和退出状态，保留用户名、原始错误及非零退出的输出；失败不得阻断其他独立撤销。

- SSH 配置语义委托 `sshd -T -f`，不得自造忽略 Include/Match 的文本审计；未验证连接上下文不能标为 Safe。
- SSH 修改先验证临时候选的语法及有效目标值，避免多 Port 监听与 KbdInteractive/ChallengeResponse 别名冲突；测试仅用显式临时路径和假命令。

### 配置备份唯一性

- 配置写入统一使用 `infrastructure::backup::backup_file()`，以排他创建的唯一文件保存快照；不得只用时钟命名或忽略备份错误后继续覆盖配置。
- 连续修改的回归测试须在临时目录调用生产配置写入函数，并验证回退后的完整原始字节。

### npm 下载完整性

- 安装脚本必须先写入独立临时文件，验证响应完整后再原子替换目标；响应、请求和写入错误必须非零退出且清理半成品。
- `node tests/npm_install_test.cjs` 使用内存响应和临时目录覆盖成功、中断、长度不符、HTTP/请求/落盘错误，禁止执行下载产物。

### 10.1 发布流程（Release）

- 版本号统一维护在 `Cargo.toml`（源码通过 `env!("CARGO_PKG_VERSION")` 读取）；每个版本的发布说明写入 `docs/versions/v{X.Y.Z}.md`。
- 推送 `v*` 标签后，发布流水线按**两阶段**执行，保证二进制先于包上线：
  - **第一阶段**：`binary-build.yml` 由 tag push 直接触发，构建 Linux 预编译二进制
    （x86_64 与 aarch64，各提供 GNU / musl，见 10.4 平台边界）并上传 GitHub Release，
    Release 正文优先读取 `docs/versions/<tag>.md`。
  - **第二阶段**：等二进制就绪后再发包：
    - `npm-publish-manual.yml`（npm 包 `@ghyper9023/u2secure`，Trusted Publishing）监听
      `workflow_run`（`workflows: ["Binary Build"]`、`types: [completed]`），
      仅在 `workflow_run.conclusion == 'success'` 时发布
    - `cargo-publish.yml`（crates.io）的既有 `workflow_run` 路径虽然等待 Binary Build 成功，
      但 **crates.io Trusted Publishing 明确拒绝该事件的 OIDC**，轮询不能解决鉴权限制。
      当前可用路径是维护者确认构建成功、该版本矩阵中的 Linux Release 资产齐全后手动执行
      `gh workflow run cargo-publish.yml --repo cherish-ltt/U2Secure --ref main -f tag_name=vX.Y.Z`。
    - **crates.io 不能用 `release: [published]`**：Release 由
      `softprops/action-gh-release` 用 GITHUB_TOKEN 创建，而 GitHub 规定
      GITHUB_TOKEN 触发的事件不会创建新的 workflow run（仅 workflow_dispatch /
      repository_dispatch 例外），实测 release 事件不产生任何运行；
      改回 `release` 触发器会导致 crates.io 永不发布
    - 两者都避免出现"npm 版本号已上线、GitHub Release 二进制还是 404"导致
      postinstall 安装失败
  - 两个发布工作流都保留 `workflow_dispatch`；对 crates.io 这是当前正式发布入口，
    对 npm 是自动路径失败时的补发入口。手动触发不会替维护者检查上游构建，必须先确认二进制就绪。
    自动路径的标签读取对应 Binary Build run 的 `release-tag` artifact，不能使用
    `workflow_run.head_branch`（手动构建时它可能是 main）。缺失或非法时立即失败；
    两个发布器都检出同一解析标签。旧运行没有 artifact 时使用手动补发入口。
  - `workflow_run` 执行的是**默认分支**上的工作流文件，因此修复 npm 发布流程只需推送主分支，
    不必重新打标签；重跑依赖幂等保护（npm 已存在同版本则跳过发布）。
- 支持 `cargo binstall u2secure` 安装预编译二进制（依赖 `[package.metadata.binstall]` 元数据，资产命名须保持 `u2secure-<target>[.exe]`）。
- 发布顺序：推送 tag → 等待 Binary Build 全部成功 → npm 自动发布 + 维护者派发 crates.io。
  Binary Build 失败时不得手动发包；不能把创建标签或 Release 等同于两个包都已发布，
  必须核对工作流结论与 npm/crates.io 实际版本元数据。
- 发布前必须确认 `Cargo.toml`、`Cargo.lock` 的本包版本及标签一致，且版本说明存在；
  不得给仍是旧版本的提交打新标签。覆盖率门槛满足并合入后才准备版本提交。
- 修改发布工作流后必须核对 `workflows: ["Binary Build"]` 与 `binary-build.yml` 的 `name:`
  **完全一致**：不一致会导致发布流水线**永不触发且不报错**。

### 10.2 加固流程约定（v0.4.0 起）

新增或修改加固步骤时，必须遵守以下约定：

1. **状态真值唯一**：步骤的安全状态只在 `AuditReport::status_for()` 中判定，禁止在步骤实现里重复写状态判断
   （trait 不再提供 `check_status`）。审计需要的系统检测统一放在 `infrastructure::system::run_full_audit()`。
2. **步骤登记**：新步骤必须在 `StepKind` 中登记并补齐 `label` / `slug` / `is_opt_in` /
   `touches_package_manager`，同时加入 `application::steps::step_for`，否则不会被执行器调度。
3. **可选步骤**：需要联网安装或耗时较长的步骤必须 `is_opt_in() == true`（默认不勾选）；
   `is_optional()` 为 true 的步骤失败时**不触发全局回滚**，只记录失败并继续。
4. **长耗时命令**：禁止裸用 `Command::output()` 执行可能长时间阻塞的命令，
   必须使用 `system::run_streaming_argv()` 并显式给出超时，输出写入 `params.live_log`（UI 会实时尾随）。
5. **产物持久化**：扫描类产物写入 `infrastructure::artifacts` 报告目录，
   并在 `StepResult::artifacts` 中返回路径；结果摘要只放关键信息 + 路径（用户用 `less` 查看完整内容）。
6. **结果语义显式**：使用 `StepOutcome::{Changed, Skipped, Failed}` 表达结局，
   禁止用 `changes_made = false` 同时表示"跳过"和"失败"；能预期的问题不要包装成 `Err`（那会触发全局回滚）。
7. **不覆盖发行版文件**：写系统配置文件前先 `backup_file()` 并 `rollback::register_file_backup()`；
   发行版已有的文件不要覆盖，改用独立命名（如 `/etc/cron.daily/99u2secure-*`）。
8. **包管理器调用**：统一通过 `package_mirror::build_pm_argv()` / `install_argv()` 构造命令，
   以便临时软件源生效；禁止直接拼接 `apt install` 之类命令。
9. **i18n 三语齐全**：所有用户可见文案必须同时写入 zh_cn / en / zh_tw 三张表，
   缺失的键会原样显示 key（CI 不报错，但属于缺陷）。
10. **测试约束**：测试中**禁止**执行会修改真实系统的命令（尤其 macOS 开发机）；
    执行策略类测试使用假步骤（`tests/job_tests.rs`），文件操作用 `tempfile` 临时目录，
    报告目录通过 `StepRunner::with_report_dir()` 注入，禁止写 `/var/log`、`/etc`。
11. **临时软件源失败语义**：连接镜像源失败（含 30 秒无输出）必须
    **自动重试 3 次后交由用户决策**（重试 / 更换源 / 取消执行），**不得静默回退**原始源；
    仅"用户取消选择"与"临时源准备失败"才回退原始源继续执行。相关常量见
    `infrastructure::package_mirror::{WARM_UP_ATTEMPTS, WARM_UP_STALL}`。
12. **外部工具的配置文件可能由独立包提供（v0.4.1 起）**：调用前必须探测并校验配置，
    不能假定"装了主包就有配置"。典型例子：Debian/Ubuntu 的 `aide` 包只装二进制，
    配置与 `aideinit` 由 `aide-common` 提供，缺失时 `aide --init` 以退出码 17
    （Configuration error）失败。约定：
    - 配套包通过 `infrastructure::aide::companion_packages()` 声明并安装；
      没有可执行文件的包必须用 `system::package_installed()` 判断，不能用 `which()`
    - 配置路径必须探测（工具自带默认值 → 发行版标准路径），并把 `--config` **显式**传给
      初始化、检查与每日任务，禁止依赖"裸命令的隐式默认值"
    - 生成兜底配置时只使用跨版本通用配置项（不得依赖发行版 `conf.d`），
      产物文件名与系统既有文件区分（如 `aide-u2secure.db`），且**绝不覆盖**用户已有配置
    - "执行成功"不等于"可用"：初始化后必须再做一次只读校验，并正确解释工具退出码
      （AIDE：1–7 表示发现文件差异属正常，≥14 才是错误）
    - 失败报告必须包含原始错误、退出码与日志路径，禁止只写"失败"

### 10.3 代码检查（prek / ast-grep）

`prek run --all-files` 覆盖：空白与冲突标记、TOML/YAML/JSON 语法、私钥与密钥泄露（betterleaks）、
ast-grep 规则、`cargo fmt` / `check` / `clippy -D warnings` / `test`。提交前必须全绿。

ast-grep 规则（`joshuadavidthomas/ast-grep-rules`）中以下告警为**项目有意保留**，不视为缺陷：

| 规则 | 保留原因 |
|------|---------|
| `rust-no-public-struct-fields` | 领域层 DTO / 值对象本就是被动数据类型（规则注释亦豁免）；改为私有字段 + getter 只增加样板代码 |
| `rust-require-thiserror-error-enum`、`rust-no-string-error-variant` | 领域层要求零外部依赖（见 `domain` 模块说明），`DomainError` 携带上下文字符串是有意设计 |
| `rust-no-anyhow-in-public-api` | 仅 `presentation::tui::run_tui` 使用 `anyhow::Result`，属表示层入口，封装类型化错误收益有限 |
| `rust-no-single-field-struct` | `HardeningOrchestrator` 是持有具名依赖（logger）的应用服务，不是 newtype |
| `rust-no-code-barricade` | 仅 `tui.rs` 模块文档中的界面布局示意图（盒线字符），非装饰性分隔线 |

除上述豁免外，新增代码不得引入新的 ast-grep 告警；`error` 级规则必须全部修复
（当前唯一 error 级规则为 `rust-no-panicking-fallback`）。

### 10.4 平台支持边界（v0.4.1 起）

- SSH 生效决策由共用执行器处理：步骤通过 `StepResult::ssh_restart_required` 报告实际配置写入，CLI/TUI 必须在执行前收集 `apply_ssh_changes` 明确授权；无授权只能标记待生效，禁止暗中重启。计划测试使用 `execution_plan` 配合假步骤。

- UFW 规则修改必须先备份 `user.rules` / `user6.rules` / `ufw.conf` 并登记可报告失败的恢复动作；禁止用无条件 `delete allow` 撤销。端口配置仅在已启用防火墙放行成功后写入。

**本项目只支持 Linux，只发布 Linux 二进制**。理由：核心能力依赖 Linux 专有组件
（apt/dnf、ufw、sshd、systemd、`/var/log`、`/etc`），部分检测逻辑（如比较
`/etc/ssh/sshd_config` 与 `/proc/<pid>` 时间戳）在其它平台不成立。

- 构建矩阵只允许 `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、
  `x86_64-unknown-linux-musl` 与 `aarch64-unknown-linux-musl`
  （见 `.github/workflows/binary-build.yml`）；不得重新加入 macOS / Windows 目标。
  musl 目标使用对应架构的 GitHub runner、`musl-tools` 和 `musl-gcc`，不得将 x86_64
  的 musl 工具链误用于 ARM64。`python3 tests/release_tag_test.py` 同时校验矩阵与链接器配置。
- musl 只扩展二进制链接目标，不扩大加固发行版支持范围；npm 仍选择 GNU 资产。
  v0.5.0 已发布资产保持不变，后续发布需确认四个资产齐全。
- `src/main.rs` 有 `#[cfg(windows)] compile_error!` 守卫，防止误产出 Windows 二进制
- **macOS 仍必须可编译**：开发机是 macOS，`cargo test` / `clippy` / `prek` 都在其上运行。
  因此**禁止**无 `#[cfg]` 保护地使用 unix-only API（`std::os::unix`）；
  需要时收敛到带 `#[cfg(unix)]` 的小辅助函数（如 `steps::set_executable`、
  `artifacts::restrict_file`、`aide::restrict`），非 unix 分支留空实现
- npm 包 `postinstall` 在非 Linux 平台必须**明确报错**，不得去下载不存在的资产
- 新增任何平台相关代码后，必须确认这三件事：`cargo test`（macOS）通过、
  `cargo check --target x86_64-unknown-linux-gnu` 通过、构建矩阵未被加入其它平台

### 10.5 用户创建的撤销边界

- `useradd` 成功后立即登记删除本次新用户的撤销，再执行加组、目录权限及密钥初始化；创建失败不得登记用户删除。

### 10.6 SSH 服务选择与验证

- 重启通过 `infrastructure::ssh_service` 处理；只对明确的 `LoadState=not-found` 回退服务名，
  已存在服务的加载、重启或状态查询失败必须显式报告，不得用另一个服务名掩盖错误。
- 重启命令必须限时并保留日志，成功后校验同一服务的退出状态及 `active` 文本；测试只能注入假命令。
- SSH 开始尝试重启是整批提交边界：通过 `StepResult::ssh_activation_attempted` 保留边界后的成功、失败与中断信息；禁止再单独回退配置和防火墙。边界前失败仍回退，边界后失败须明确报告修改保留及人工检查要求。

### 10.7 批次密钥生成

- 同批次成功创建用户后，该用户的重复 `GenerateNew` 由执行器明确跳过；不同用户、粘贴公钥或独立密钥步骤不受影响。

### 10.8 SSH 公钥文件边界

- 公钥追加从账户数据库解析 home/UID/GID，逐级禁止目录符号链接，并只对已验证的单链接普通文件描述符写入和设置权限。
- 既有 home、`.ssh`、`authorized_keys` 必须归目标账户所有，home 与 `.ssh` 不得允许组或其他用户写入；拒绝危险目标时不得修改旁路文件。
- 缺失 `.ssh` 时仅以目标账户身份创建，不允许 root 按可控路径执行递归 chown。
- 用户创建只负责账户与管理员组；后续密钥步骤统一复用 `KeyDirectory` 初始化 `.ssh`，禁止在账户初始化中先执行路径式 mkdir/chown/chmod 绕过校验。
- 密钥生成必须在私有临时目录完成；表示层不得直接删除旧密钥，覆盖必须显式授权并保留可恢复备份；撤销只处理本次已验证文件。

### 10.9 覆盖率与隔离测试

- 全项目行覆盖率门槛为 80%，统一命令为 `cargo llvm-cov --locked --all-targets --all-features --summary-only`；不得通过排除文件、禁用生产代码或缩减统计范围达标。
- CLI/TUI 测试不得调用真实启动入口、终端控制、系统审计或加固；渲染传入报告目录与检测结果，TUI 使用内存 `TestBackend`，断言输出内容、状态和错误语义。
- 系统命令测试在独立子进程注入私有 PATH，禁止在并行测试进程中修改全局环境；固定绝对路径的配置或程序必须通过最小内部参数注入临时替代，不得绕过假命令执行宿主工具。
- macOS 测试须使用禁止联网、禁止写入系统目录的额外沙箱；允许写入的范围只包含独立测试工作区、缓存与临时产物，不运行实际加固命令。

### 10.10 独立只读审计

- `u2secure audit [--format text|json]` 在日志器、CLI/TUI 和加固执行器初始化前路由；先校验参数，再以 root 进行共享采集。命令无需 TTY，不创建日志、报告目录、备份或扫描产物；stdout 仅报告、stderr 仅诊断，文件保存由调用方重定向。
- 独立审计与交互式审计复用系统检测及 `AuditReport::status_for()`，禁止复制状态判断。JSON `schema_version = 1`，检查 ID 使用 `StepKind::slug()`，键、状态与最小类型化详情不受语言影响；禁止输出原始 `AuditItem` 文案、配置、密钥或命令原始输出。文本文案必须三语齐全。
- 正常发现与采集失败分开：未安装、未配置及 SSH Include/Match/多端口未验证可成功生成报告；必要探测失败、超时、超限或配置读取错误必须显式失败。SSH 未验证值不得使用默认端口或布尔值伪装成已知结果。退出 0 只表示报告输出成功，写入或刷新失败也必须非零退出。
- 外部探测统一使用内存有界采集，每条限时 5 秒、stdout/stderr 合计不超过 1 MiB；正常退出和失败均清理同一进程组并回收直接子进程，不使用落盘执行日志。检查范围必须说明缓存年龄、管理组、工具安装与 SSH 时间戳均不构成完整安全或远程登录保证。
- UFW 审计使用 `iptables-save` / `ip6tables-save` 并传 `-M /bin/false`，不得使用 `-t` / `-f` 或会创建锁文件的 `ufw status`；只检查 filter 表的 UFW 用户链存在性，必须说明不验证完整规则或并发重载时的原子一致快照。
- 审计测试注入报告与 writer，系统采集使用临时配置及独立子进程私有 PATH 的假命令；三语在隔离子进程初始化。覆盖无 TTY、无默认文件、稳定 JSON、错误不输出报告和写入失败，不调用宿主真实审计或加固，继续遵守 10.9 的 macOS 沙箱约束。

### 系统待重启提示

- 更新步骤与审计统一使用 `infrastructure::reboot::detect()`；仅按 os-release 的精确 Debian/Ubuntu ID 检查约定标记存在性，不以 APT 或 ID_LIKE 扩大支持范围，不读取包清单、不重启系统。
- `RebootHint` 只补充来源与维护提示，不改变 `AuditReport::status_for()`、APT 缓存或 SSH 生效语义；未发现不保证无需重启，三语与 schema 1 的 `reboot_hint` 字段须表达同一范围。
- 配置读取及标记探测失败必须显式报告。独立审计失败不输出正常报告；更新成功后的辅助探测失败保留 `Changed`，不掩盖原更新失败、不触发回退。测试只用临时根路径、注入报告和假更新命令。

