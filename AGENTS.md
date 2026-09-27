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

### 10.1 发布流程（Release）

- 版本号统一维护在 `Cargo.toml`（源码通过 `env!("CARGO_PKG_VERSION")` 读取）；每个版本的发布说明写入 `docs/versions/v{X.Y.Z}.md`。
- 推送 `v*` 标签后，发布流水线按**两阶段**执行，保证二进制先于包上线：
  - **第一阶段**：`binary-build.yml` 由 tag push 直接触发，构建 5 个平台的预编译二进制
    （Linux/macOS 各 x86_64+ARM64、Windows x64）并上传 GitHub Release，
    Release 正文优先读取 `docs/versions/<tag>.md`。
  - **第二阶段**：`npm-publish-manual.yml`（npm 包 `@ghyper9023/u2secure`，走 Trusted Publishing）
    与 `cargo-publish.yml`（crates.io）改为监听 `workflow_run`
    （`workflows: ["Binary Build"]`、`types: [completed]`），仅在
    `workflow_run.conclusion == 'success'` 时发布；避免出现"npm 版本号已上线、
    GitHub Release 二进制还是 404"导致用户 postinstall 安装失败。
  - 两个发布工作流都保留 `workflow_dispatch` 作为应急手动补发入口。
    `head_branch` 是 `workflow_run` payload 中唯一的标签来源（该事件不含
    `ref_type` / `ref_name`），解析失败会立即报错退出，不会误发。
  - `workflow_run` 执行的是**默认分支**上的工作流文件，因此修复发布流程只需推送主分支，
    不必重新打标签；重跑依赖幂等保护（npm 已存在同版本则跳过发布）。
- 支持 `cargo binstall u2secure` 安装预编译二进制（依赖 `[package.metadata.binstall]` 元数据，资产命名须保持 `u2secure-<target>[.exe]`）。
- 发布顺序无需人工干预：推送 tag → 等待 Binary Build 全部成功 → npm 与 crates.io 自动发布。
  若 Binary Build 失败，两个包都不会发布（crates.io 本身不依赖 GitHub Release 资产，
  此处对齐顺序是为了流程语义一致）。
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

### 10.4 追加内容xxx

...
