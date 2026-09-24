# 野生菌样本联检证据链

急诊、疾控和实验室围绕一次误食事件交接样本、分送多类检测，并在结果晚到时
修订联检结论。系统把“证据入口—保管链—结论—恢复”四层分开，任何有歧义或
违例的输入都在**形成领域记录之前**被稳定、可定位地拒绝。

## 业务规则（实现即不变量）

1. **证据入口严格唯一**：一个文件必须恰好是一个完整的 UTF-8 JSON 值。
   重复键（不再静默采用后一个）、尾随内容、非 UTF-8、NaN/裸控制字符直接拒绝；
   字段合同是封闭集合，未知字段、类型错误、缺字段、非法时间（必须带显式时区）
   全部拒绝。所有问题一次性收集，携带 1 基行号、0 基列号和 JSON 指针。
2. **隔离留存**：被拒文件形成 `QuarantineEntry`，保留**原始字节、SHA-256
   摘要、字节长度、拒收阶段（json/schema/registry）与全部问题位置**，不产生
   任何领域状态变更。
3. **登记幂等与同名暂停**：以原始字节 SHA-256 为身份，同一文件原样重送识别为
   `duplicate`，绝不重复登记；文件名相同但内容不同时 `name_content_conflict`
   并**暂停该文件名的关联**，后续送达以 `name_hold` 拒绝，直到人工裁决
   （`release_hold`）。
4. **父子数量守恒**：一次事件分送形态学、毒素、分子多个子样。每个样本实时满足
   `接收 + 补样 == 耗用 + 拆出 + 结余`；家族层面满足
   `外部进入（根样交接 + 补样） == 累计耗用 + 总结余`，且内部拆出总量等于
   子样接收总量。超量拆分/耗用、负库存、单位不一致、保管方断裂一律拒绝。
5. **保管链连续**：拆分只能由当前保管方执行，耗用只能由当前保管方登记；
   保管转移记录在链式台账中，每条目带操作后的结余与保管方。
6. **晚到结果规则**：结果只能进入声明依赖它的结论。结论**未签发**时晚到结果
   更新草稿；一旦向临床签发，版本内容（含结果指纹集合）即**冻结**，晚到结果
   只能追加 `Amendment` 更正和 `Receipt` 接收回执，历史版本不可覆盖。
7. **崩溃恢复恰好一次**：所有状态改变先写 WAL（每行 fsync）后改内存。重放按
   `event_id`/`result_id` 幂等——继续未完成联检不会再次消耗样本；危急通知以
   `critical:<事件>:<检测>:<结果>` 去重，崩溃发生在“结果落 WAL 后、通知落
   WAL 前”的窗口时恢复只补发一次，已落 WAL 的通知重放时绝不重发。

## 模块

| 文件 | 职责 |
| --- | --- |
| `errors.py` | `Problem`（含行列/指针）与分级异常 `StrictJsonError`/`SchemaRejected`/`ChainViolation`/`WorkflowConflict` |
| `strictjson.py` | 位置感知、拒绝重复键与尾随内容的严格 JSON 解析器 |
| `timeutil.py` | 只接受带显式时区的 ISO 8601 瞬间 |
| `intake.py` | 封闭字段合同校验、`QuarantineEntry`、内容哈希幂等与同名暂停 |
| `contracts.py` | 既有最小合同 `DomainRecord` 与加固后的 `load_record`（标识与时间含义不变） |
| `chain.py` | 交接/拆分/耗用/补样事件账本、父子数量守恒与保管链 |
| `conclusions.py` | 联检结论、草稿、签发冻结、晚到结果更正与接收回执 |
| `wal.py` | 只追加 JSON Lines WAL，严格解析与序号连续性检查 |
| `workflow.py` | `IncidentHub`：先试算后写 WAL 的协调器与危急通知去重 |

`schema_version` 当前仅支持 `1`；新增字段必须进入封闭合同，新增状态需在本文件
说明迁移方式。检测枚举固定为 `morphology` / `toxin` / `molecular`。

## 快速使用

```python
from fungus_chain import IncidentHub

with IncidentHub("state/wal.jsonl") as hub:
    hub.ingest_bytes(raw, "handoff.json")                 # accepted / duplicate / quarantined
    hub.apply_chain_event(handoff_event)                  # 交接
    hub.split_for_assay("INC1", "toxin", ...)             # 分样（确定性 event_id）
    hub.consume_for_assay("INC1", "toxin", ...)           # 耗用
    hub.open_panel("C1", "INC1")
    hub.record_result("INC1", toxin_result)               # 危急时恰好通知一次
    hub.issue_conclusion("INC1", issued_at, summary=...)  # 依赖齐全才能签发
    hub.record_result("INC1", late_result)                # 已签发 -> 追加更正+回执
    hub.assert_integrity()                                # 全家族守恒检查
```

拒收诊断示例：

```python
try:
    load_record(path)
except EvidenceError as exc:
    for p in exc.problems:
        print(p.code, p.pointer, p.line, p.column, p.message)
```

## 测试与构建

执行测试（unittest 与 pytest 均可）：

```bash
python3 -m unittest discover -s tests
python3 -m pytest tests -q
```

编译检查：

```bash
python3 -m compileall -q src tests
```

测试覆盖：混合文件批次归位、重复键/尾随内容/未知字段/非法时间定位与原始字节
留存、同名异内容暂停、分样守恒（含补样与超量拒绝）、晚到结果的草稿更新与
签发后更正、以及服务中断恢复（不重复耗用、不重复通知、崩溃窗口补发一次、
WAL 损坏定位）。
