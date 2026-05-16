# 阶段 03 — 持续集成（CI）配置

## 提示词

```
你是 CI 专家。为使用 [CI 平台] 的 [技术栈] 项目生成完整 CI 配置。

必须包含以下 Job：
1. lint     — 代码风格检查
2. test     — 单元测试 + 覆盖率报告
3. build    — 构建产物
4. security-scan — 依赖安全扫描

要求：
- 使用缓存加速依赖安装
- 失败时发送通知（Slack webhook）
- main 分支触发完整流水线，PR 只跑 lint + test

只输出 YAML 文件内容。
```

## 使用说明

- `[CI 平台]` 可选：GitHub Actions / GitLab CI / CircleCI
- `[技术栈]` 替换为实际语言和框架
- "只输出 YAML 文件内容"让输出可直接写入文件
