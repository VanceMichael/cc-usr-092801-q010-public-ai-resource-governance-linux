# 协同事务平台

协同事务平台为需要多机构参与的业务提供统一的机构、授权、案件、证据、审批、资源预约、资金分录、消息归并、通知、定时任务和历史回放能力。项目只使用 Python 标准库与 SQLite，适合在单个 Linux 应用容器内运行。

## 目录

- `src/civicflow/`：领域服务、SQLite 持久化、权限和命令行入口。
- `tests/`：核心流程、边界条件和异常路径测试。
- `examples/`：本地演示输入。

## 配置

通过 `CIVICFLOW_DB` 指定 SQLite 文件路径；不设置时命令行使用当前目录下的 `civicflow.sqlite3`。所有时间使用带时区的 ISO 8601 字符串。

## 测试

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## 编译或构建

```bash
PYTHONPATH=src python3 -m compileall -q src
```

## 使用

初始化数据库并运行离线演示：

```bash
PYTHONPATH=src python3 -m civicflow.cli --db /tmp/civicflow-demo.sqlite3 demo
```

查看当前案件：

```bash
PYTHONPATH=src python3 -m civicflow.cli --db /tmp/civicflow-demo.sqlite3 list-cases
```

## 人工智能成果开放共享治理

`civicflow.ai_sharing` 在协同事务平台上扩展了模型、数据集和算力工具的授权与公平可及能力：

- **成果目录与冻结发布**：`register_artifact`、`publish_release` 一次冻结模型、数据集、安全说明的引用、版本与摘要组合，生成不可逆的清单摘要。
- **权利来源与收窄/撤回**：权利事件以追加链记录；`narrow_release` 只影响后续访问，并为仍有效的派生成果生成处置任务；`revoke_release` 撤销有效凭据、释放配额、阻止失效版本继续发放，既有回执与审计事实保持可追溯。
- **周期配额**：`put_quota_policy` 按机构与受益群体设置月度上限，占用（hold）与释放（release）使用不可变配额流水记账。
- **申请与三角色分离**：提交者、权益审核人、安全复核人不能互相代批；安全复核通过时在单个事务内完成许可判断（适用人群、用途、场景、区域）、配额占用、凭据签发和审计分录。
- **紧急公共用途例外**：`emergency=True` 可暂时超出许可或配额范围，判断结果与理由固定在裁决上下文里。
- **使用回执**：同一回执键重试沿用原结果；同键不同内容进入 `ai_receipt_quarantine` 隔离并拒绝。
- **再申请与申诉**：`appeal_view` 呈现裁决时的成果组合、许可判断、群体配额、剩余额度、凭据与使用事实。
- **可恢复队列**：到期、撤回处置、审核超时等工作持久化在 `ai_work_queue`，按保存的队列位置领取租约，进程中断后可接续。

运行离线演示：

```bash
PYTHONPATH=src python3 -m civicflow.cli --db /tmp/civicflow-ai-demo.sqlite3 ai-demo
```
