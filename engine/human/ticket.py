"""人机校验票据：签发、客户端与场景绑定、验签、原子消费、难度与策略。

安全契约：
- 票据同时绑定挑战与场景，场景必须精确匹配，禁止跨场景复用。
- 票据必须绑定客户端，换一个客户端使用即失败，禁止转发给脚本。
- 签名使用 HMAC-SHA256，签名比较使用 hmac.compare_digest，禁止普通等号。
- 消费是原子的：先验签，再登记已用，二次消费与并发消费都必须失败。
- 过期容差为 0：now 大于等于 expires_at 即视为过期，没有任何宽限。
- 所有时间由调用方通过 now 显式传入，实现不得读取系统时钟，不得使用随机数；
  相同输入必须得到相同的 ticket_id、签名与绑定串。

store 约定：服务端状态字典，形如
    {"issued": {ticket_id: ticket}, "used": {ticket_id: now}, "key": entropy}
其中 issued 保存已签发但未必已消费的票据，used 保存已消费票据，key 是签名密钥。
"""


def issue(store, challenge_id, action, entropy, now) -> dict:
    """签发票据，并把票据绑定到挑战与场景。

    参数:
        store: 服务端状态字典；issue 负责初始化 issued 映射，并把签名密钥写入 key。
        challenge_id: 挑战标识，票据签发后与它绑定。
        action: 场景标识，例如 register 或 reset-password，签发后不可更改。
        entropy: 签名密钥材料，显式传入以保证确定性与离线可测，不得使用随机数。
        now: 当前时间戳，单位秒，显式传入，不得读取系统时钟。

    返回:
        票据字典，至少包含 ticket_id、challenge_id、action、issued_at、expires_at 与 signature。
        ticket_id 由 challenge_id、action、now、entropy 确定性派生。
        issued_at 等于 now，expires_at 等于 now 加 120 秒有效期，过期容差为 0。
        票据登记进 store 的 issued，此时不得登记为已用。

    契约:
        票据绑定挑战与场景，绑定串必须同时覆盖 action，注册票据不得改绑改密场景。
    """
    raise NotImplementedError


def bind(ticket, client, action) -> str:
    """把票据绑定到客户端与场景，返回确定性的绑定串。

    参数:
        ticket: issue 返回的票据字典。
        client: 客户端标识，绑定后写入 ticket 的 client 字段，供 consume 比对。
        action: 场景标识，必须与票据签发时的 action 精确一致。

    返回:
        绑定串，同时包含票据标识、client 与 action，三者任一不同则绑定串不同。
        相同输入必须得到相同绑定串，不得使用随机数。

    异常:
        action 与票据签发场景不一致时抛出 ValueError，防止注册票据改绑到改密场景。
    """
    raise NotImplementedError


def verify_signature(ticket, key) -> bool:
    """校验票据签名，使用恒定时间比较。

    使用 key 对 ticket_id、challenge_id、action、issued_at、expires_at 做规范化序列化，
    计算 HMAC-SHA256，并用 hmac.compare_digest 与 ticket 的 signature 字段比较，
    不得使用普通等号比较签名。

    返回:
        签名一致返回 True；签名缺失、格式不符或不一致返回 False，不抛异常。
    """
    raise NotImplementedError


def consume(store, ticket, client, action, now) -> dict:
    """原子消费票据，同一票据只能成功一次。

    按以下顺序执行，任一步失败立即返回失败结果，且不得把票据登记为已用：
        1. 票据必须已登记在 store 的 issued 中，否则 reason 为 unknown。
        2. 先调用 verify_signature 校验签名，失败 reason 为 signature；
           验签必须发生在任何状态变更之前，复用票据不得绕过验签。
        3. 场景必须精确匹配，否则 reason 为 action。
        4. 客户端必须与 bind 时写入的 client 一致，否则 reason 为 client。
        5. 过期容差为 0：now 大于等于 expires_at 即过期，reason 为 expired。
        6. 原子登记已用：用单步操作写入 store 的 used，同一 ticket_id 只能成功一次，
           已经登记过的票据 reason 为 reused。

    参数:
        store: 服务端状态字典，包含 issued、used 与 key。
        ticket: 待消费票据。
        client: 当前客户端标识。
        action: 当前场景标识。
        now: 当前时间戳，单位秒，显式传入。

    返回:
        成功返回 {"ok": True, "ticket_id": ..., "challenge_id": ..., "consumed_at": now}，
        同时把 ticket_id 写入 store 的 used。
        失败返回 {"ok": False, "reason": 上述原因码之一}。
    """
    raise NotImplementedError


def check_action(ticket, action) -> bool:
    """校验场景是否精确匹配。

    票据的 action 与传入的 action 完全相等才返回 True。
    禁止前缀匹配：register 与 register_activate 是两个不同场景，不得互相通用。
    """
    raise NotImplementedError


def difficulty_for(risk, policy) -> int:
    """按风险等级返回难度档位。

    policy 的 levels 字段把风险等级映射为难度整数，例如
    {"low": 1, "medium": 2, "high": 3}。

    返回:
        对应风险等级的难度整数，风险越高档位越高，不得忽略风险等级返回固定最低档。

    异常:
        未知风险等级抛出 KeyError。
    """
    raise NotImplementedError


def validate_policy(policy) -> list[str]:
    """检查票据策略，返回问题码列表，空列表表示合规。

    检查项与问题码，顺序固定：
        cross_action：票据允许跨场景时加入，合规策略必须为 False。
        not_one_time：票据不是一次性时加入，合规策略必须为 True。
        no_expiry：ttl_seconds 缺失、不是整数或不大于 0 时加入。
    """
    raise NotImplementedError


def ticket_batch(requests, policy, now) -> dict:
    """批量处理票据请求，各请求完全独立。

    每个请求是字典，包含 challenge_id、action、client、entropy 与 risk。
    对每个请求：用 difficulty_for 按 risk 取难度；用独立的临时 store 调用 issue；
    再调用 bind 绑定 client 与 action。

    返回:
        {"results": [...], "problems": validate_policy(policy)}。
        results 每项包含 index、challenge_id、action、client、difficulty、binding 与 ticket。
        后一个请求不得命中或复用前一个请求的票据；相同输入与 now 必须得到相同结果。
    """
    raise NotImplementedError