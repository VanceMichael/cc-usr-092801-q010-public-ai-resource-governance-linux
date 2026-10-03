# 协同事务平台

协同事务平台为需要多机构参与的业务提供统一的机构、授权、案件、证据、审批、资源预约、资金分录、消息归并、通知、定时任务和历史回放能力。项目只使用 Python 标准库与 SQLite，适合在单个 Linux 应用容器内运行。

## 人工智能成果开放共享治理

在通用协同事务能力之上，平台内置国有企业人工智能成果开放共享的完整闭环，回答“一次访问是否符合成果许可、区域限制和公平可及要求”：

- `airules.py`：许可判断（适用人群、用途、区域）、月度/季度配额周期与权利收窄校验规则。
- `achievements.py`：成果目录（模型、数据集、算力工具、安全说明）与成果版本。发布即冻结模型、数据与安全说明的组合并生成组合摘要；权利收窄只影响后续访问，并为仍有效的派生成果生成处置任务；撤回立即停止后续发放，既有使用事实保持可追溯。
- `access_requests.py`：访问申请与分级复核。提交者、权益审核人、安全复核人不得互相代批；紧急公共用途可提出例外，但仍需两个环节的独立复核。
- `grants.py`：授权核心。配额占用、凭据签发与审计分录在同一事务内原子提交；按机构与受益群体计算周期配额；同一回执重试沿用原结果、异文进入隔离；批量授权与许可撤回并发时阻止失效版本继续发放；到期、撤回与待审工作从保存的队列位置接续；`explain` 再现当时的成果组合、许可判断、群体配额与剩余额度，供再次申请或申诉核对。

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

运行人工智能成果开放共享全流程演示（目录上架、发布冻结、申请复核、授权签发、回执登记与时点再现）：

```bash
PYTHONPATH=src python3 -m civicflow.cli --db /tmp/civicflow-demo.sqlite3 demo-ai
```

查看当前案件：

```bash
PYTHONPATH=src python3 -m civicflow.cli --db /tmp/civicflow-demo.sqlite3 list-cases
```
