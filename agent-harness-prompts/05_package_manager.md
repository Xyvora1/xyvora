# 阶段 05 — 包管理器设置

## 提示词

```
你是构建系统专家。为 [技术栈] 项目配置包管理器。

任务：
1. 生成 package.json / pyproject.toml / go.mod 骨架
2. 锁定核心依赖版本
3. 定义以下标准脚本：dev、build、test、lint、typecheck
4. 配置私有 registry（如有）
5. 说明依赖分层策略：dependencies vs devDependencies

以 Markdown 输出，每段配置前说明用途。
```

## 使用说明

- 明确区分运行时依赖和开发依赖，影响镜像体积和安全面
- `[技术栈]` 决定使用哪个包管理器（npm/pip/go mod）
