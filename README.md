注册接口加了人机校验，脚本拿一个验证成功的票据反复提交，照样批量注册成功：票据只绑定挑战不绑定场景，注册票据可用于改密码；票据不绑定客户端，可被转发给脚本使用；签名校验在消费之后，复用票据时已通过校验；签名比较用普通等号；消费不是原子操作，并发两次都能成功；消费不记录已用票据，重放窗口无限；场景校验用前缀，注册与注册转正互相通用；难度档位忽略风险等级，永远最低档；策略校验不检查一次性；批量处理复用票据，后一个请求命中前一个请求的票据。engine/human/ticket.py 是核心，tests/human/test_ticket.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式
在仓库根目录执行：pytest tests -q
当前基线：15 failed，0 error，失败原因全部是桩抛出 NotImplementedError。
修复目标：按题面顺序修掉 10 个缺陷，让 15 个测试全部通过。

字段表
方向：安全
考点：漏洞检测与攻防
类型：Bugfix
环境：Python 3, pytest
依赖：无外部依赖

目录布局
本仓库采用 engine 嵌套布局：实现包 engine 与测试目录 tests 平级，engine 内再嵌套 human 子包。
sec-captcha-token/
    README.md
    conftest.py
    engine/
        __init__.py
        human/
            __init__.py
            ticket.py
    tests/
        human/
            test_ticket.py

测试约定
tests 目录下的测试不可修改。15 个测试由 10 条缺陷回归与 5 条基础行为组成，修复时只能改 engine/human/ticket.py。## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

