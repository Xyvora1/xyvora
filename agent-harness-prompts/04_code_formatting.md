# 阶段 04 — 设定代码格式化规则

## 提示词

```
你是代码质量工程师。为 [技术栈] 项目配置代码格式化和 Lint 规则。

输出以下文件内容：
1. .editorconfig
2. [格式化工具] 配置文件（如 .prettierrc / pyproject.toml）
3. [Linter] 配置文件（如 .eslintrc / .flake8）
4. pre-commit hook 配置（.husky/ 或 .pre-commit-config.yaml）

规则方向：
- 强制一致的缩进、引号、行尾
- 禁止 unused imports 和 console.log 残留
- 每个规则附注释说明原因
```

## 使用说明

- `[格式化工具]` 如 Prettier / Black / gofmt
- `[Linter]` 如 ESLint / Flake8 / golangci-lint
- pre-commit hook 是防止"脏代码"进入仓库的关键门控
