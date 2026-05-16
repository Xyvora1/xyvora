# 阶段 12 — 为 Agent 接入 UI 调试工具

## 提示词

```
你是前端工具链工程师。为 Agent 配置可在 headless 环境中使用的 UI 调试能力。

任务：
1. 集成 [Playwright / Puppeteer] 并生成基础测试夹具
2. 配置截图对比工具（如 Percy / Pixelmatch）
3. 编写 Agent 可调用的辅助函数：
   - takeScreenshot(page, name)
   - assertNoConsoleErrors(page)
   - measureCoreWebVitals(url)
4. 生成调试报告输出格式（JSON + HTML）

Agent 必须通过这些函数验证 UI，不得手动猜测渲染结果。
```

## 使用说明

- Agent 没有眼睛，这套工具就是它的"视觉"
- "不得手动猜测渲染结果"是强制约束，防止 Agent 编造验证结论
- JSON 格式报告便于后续自动处理和 CI 集成

---

# 阶段 13 — 为 Agent 部署本地可观测栈

## 提示词

```
你是 SRE 工程师。为本地开发环境配置轻量可观测栈。

使用 Docker Compose 部署：
- Prometheus（指标采集）
- Grafana（可视化，预配置 [技术栈] Dashboard）
- Loki（日志聚合）
- OpenTelemetry Collector（链路追踪）

同时：
1. 在应用代码中注入 OTel SDK 初始化代码
2. 生成 Grafana Dashboard JSON（含请求量、延迟、错误率面板）
3. 配置告警规则：错误率超过 1% 触发

输出 docker-compose.observability.yml 和集成说明。
```

## 使用说明

- Agent 验证性能和错误率需要真实数据，而非猜测
- 本地 Obs 栈与生产环境保持一致，减少"本地好 CI 坏"问题
- 告警规则 1% 阈值可根据项目调整

---

# 阶段 14 — 起草开发任务执行计划

## 提示词

```
你是技术项目经理。将以下需求分解为 Agent 可执行的任务列表。

需求：[粘贴需求描述]

分解规则：
- 每个任务单一职责，预计完成时间 < 2 小时
- 明确每个任务的输入、输出、验收标准
- 标注任务依赖关系（DAG）
- 区分：可并行任务 vs 必须串行任务

输出格式：YAML，每个任务包含：
id, title, depends_on, input, output, acceptance_criteria
```

## 使用说明

- 结构化任务分解是 Agent 自主执行的前提，粒度决定成败
- "< 2 小时"是经验值，防止任务过大导致 Agent 上下文溢出
- YAML 格式让任务可被程序解析，用于调度和追踪
- depends_on 字段支持构建 DAG，识别可并行执行的任务

示例输出结构：
```yaml
tasks:
  - id: T001
    title: 实现用户注册 API
    depends_on: []
    input: 用户注册需求文档
    output: POST /auth/register 端点，包含单元测试
    acceptance_criteria:
      - 返回 201 状态码
      - 密码哈希存储
      - 邮箱唯一性校验
```
