"""engine/human/ticket.py 的 15 条红测试：10 条对应缺陷，5 条基础行为。"""

import hmac
import threading

import pytest

from engine.human.ticket import (
    bind,
    check_action,
    consume,
    difficulty_for,
    issue,
    ticket_batch,
    validate_policy,
    verify_signature,
)

GOOD_POLICY = {
    "levels": {"low": 1, "medium": 2, "high": 3},
    "cross_action": False,
    "one_time": True,
    "ttl_seconds": 120,
}


def test_registration_ticket_cannot_be_rebound_to_password_reset():
    """缺陷 1：票据必须绑定场景，注册票据不得用于改密码。"""
    store = {}
    ticket = issue(store, "challenge-1", "register", "entropy-1", 1000)

    assert bind(ticket, "client-a", "register")
    with pytest.raises(ValueError):
        bind(ticket, "client-a", "reset-password")
    assert check_action(ticket, "reset-password") is False


def test_ticket_is_bound_to_client():
    """缺陷 2：票据必须绑定客户端，换客户端消费必须失败。"""
    store = {}
    ticket = issue(store, "challenge-2", "register", "entropy-2", 1000)
    assert bind(ticket, "client-a", "register")
    assert ticket["client"] == "client-a"

    stolen = consume(store, ticket, "client-b", "register", 1001)
    assert stolen["ok"] is False
    assert stolen["reason"] == "client"
    assert consume(store, ticket, "client-a", "register", 1002)["ok"] is True


def test_signature_is_verified_before_consumption():
    """缺陷 3：验签必须发生在消费登记之前，伪造签名不得污染已用状态。"""
    store = {}
    ticket = issue(store, "challenge-3", "register", "entropy-3", 1000)
    bind(ticket, "client-a", "register")

    forged = dict(ticket)
    forged["signature"] = "0" * len(ticket["signature"])
    result = consume(store, forged, "client-a", "register", 1001)
    assert result["ok"] is False
    assert result["reason"] == "signature"
    assert ticket["ticket_id"] not in store.get("used", {})

    assert consume(store, ticket, "client-a", "register", 1002)["ok"] is True


def test_signature_uses_constant_time_compare(monkeypatch):
    """缺陷 4：签名比较必须使用 hmac.compare_digest，不能使用普通等号。"""
    calls = []
    real_compare = hmac.compare_digest

    def spy(left, right):
        calls.append((left, right))
        return real_compare(left, right)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    store = {}
    ticket = issue(store, "challenge-4", "register", "entropy-4", 1000)
    assert verify_signature(ticket, "entropy-4") is True
    assert verify_signature(ticket, "wrong-key") is False
    assert len(calls) >= 2


def test_consume_is_atomic_under_concurrency():
    """缺陷 5：并发消费只能成功一次，不能两次都成功。"""
    store = {}
    ticket = issue(store, "challenge-5", "register", "entropy-5", 1000)
    bind(ticket, "client-a", "register")

    barrier = threading.Barrier(2)
    results = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait(timeout=5)
        try:
            result = consume(store, ticket, "client-a", "register", 1001)
        except Exception as exc:  # 记录桩异常，让断言失败而不是让测试挂起
            result = {"ok": False, "error": type(exc).__name__}
        with results_lock:
            results.append(result)

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=5)

    assert len(results) == 2
    assert sum(1 for result in results if result.get("ok") is True) == 1


def test_consumed_ticket_is_recorded_for_replay_detection():
    """缺陷 6：消费必须记录已用票据，关闭无限重放窗口。"""
    store = {}
    ticket = issue(store, "challenge-6", "register", "entropy-6", 1000)
    bind(ticket, "client-a", "register")

    first = consume(store, ticket, "client-a", "register", 1001)
    assert first["ok"] is True
    assert ticket["ticket_id"] in store["used"]

    second = consume(store, ticket, "client-a", "register", 1002)
    assert second["ok"] is False
    assert second["reason"] == "reused"


def test_check_action_uses_exact_match_not_prefix():
    """缺陷 7：场景校验必须精确匹配，注册与注册转正不得互相通用。"""
    store = {}
    ticket = issue(store, "challenge-7", "register", "entropy-7", 1000)

    assert check_action(ticket, "register") is True
    assert check_action(ticket, "register_activate") is False
    assert check_action(ticket, "reg") is False


def test_difficulty_tracks_risk_level():
    """缺陷 8：难度档位必须由风险等级决定，不能永远返回最低档。"""
    assert difficulty_for("low", GOOD_POLICY) == 1
    assert difficulty_for("medium", GOOD_POLICY) == 2
    assert difficulty_for("high", GOOD_POLICY) == 3
    assert difficulty_for("high", GOOD_POLICY) > difficulty_for("low", GOOD_POLICY)


def test_validate_policy_rejects_non_one_time_ticket():
    """缺陷 9：策略校验必须检查票据一次性。"""
    policy = dict(GOOD_POLICY)
    policy["one_time"] = False
    assert validate_policy(policy) == ["not_one_time"]

    policy["one_time"] = True
    assert validate_policy(policy) == []


def test_batch_does_not_reuse_previous_ticket():
    """缺陷 10：批量处理各请求独立，后一个请求不得命中前一个请求的票据。"""
    requests = [
        {
            "challenge_id": "challenge-10-a",
            "action": "register",
            "client": "client-a",
            "entropy": "entropy-10-a",
            "risk": "low",
        },
        {
            "challenge_id": "challenge-10-b",
            "action": "register",
            "client": "client-b",
            "entropy": "entropy-10-b",
            "risk": "high",
        },
    ]
    result = ticket_batch(requests, GOOD_POLICY, 1000)
    first, second = result["results"]
    assert first["ticket"]["ticket_id"] != second["ticket"]["ticket_id"]
    assert first["ticket"]["challenge_id"] == "challenge-10-a"
    assert second["ticket"]["challenge_id"] == "challenge-10-b"
    assert first["difficulty"] == 1
    assert second["difficulty"] == 3


def test_issue_and_consume_success():
    """基础行为：正常签发、绑定、验签与消费成功。"""
    store = {}
    ticket = issue(store, "challenge-11", "register", "entropy-11", 1000)
    assert ticket["challenge_id"] == "challenge-11"
    assert ticket["action"] == "register"
    assert ticket["issued_at"] == 1000
    assert ticket["expires_at"] > ticket["issued_at"]
    assert bind(ticket, "client-a", "register")
    assert verify_signature(ticket, "entropy-11") is True

    result = consume(store, ticket, "client-a", "register", 1001)
    assert result["ok"] is True
    assert result["ticket_id"] == ticket["ticket_id"]


def test_cross_scenario_reuse_rejected():
    """基础行为：跨场景复用被拒，且失败尝试不消耗票据。"""
    store = {}
    ticket = issue(store, "challenge-12", "register", "entropy-12", 1000)
    bind(ticket, "client-a", "register")
    assert check_action(ticket, "register") is True
    assert check_action(ticket, "reset-password") is False

    cross = consume(store, ticket, "client-a", "reset-password", 1001)
    assert cross["ok"] is False
    assert cross["reason"] == "action"
    assert consume(store, ticket, "client-a", "register", 1002)["ok"] is True


def test_second_consumption_rejected():
    """基础行为：二次消费被拒。"""
    store = {}
    ticket = issue(store, "challenge-13", "register", "entropy-13", 1000)
    bind(ticket, "client-a", "register")
    assert consume(store, ticket, "client-a", "register", 1001)["ok"] is True

    second = consume(store, ticket, "client-a", "register", 1002)
    assert second["ok"] is False
    assert second["reason"] == "reused"


def test_expired_ticket_rejected():
    """基础行为：过期票据被拒，过期容差为 0。"""
    store = {}
    ticket = issue(store, "challenge-14", "register", "entropy-14", 1000)
    bind(ticket, "client-a", "register")
    expires_at = ticket["expires_at"]

    at_boundary = consume(store, ticket, "client-a", "register", expires_at)
    assert at_boundary["ok"] is False
    assert at_boundary["reason"] == "expired"

    fresh_store = {}
    fresh = issue(fresh_store, "challenge-14-fresh", "register", "entropy-14", 2000)
    bind(fresh, "client-a", "register")
    assert consume(fresh_store, fresh, "client-a", "register", fresh["expires_at"] - 1)["ok"] is True


def test_two_batches_match_individual_processing():
    """基础行为：两批独立处理与单独处理结果相同。"""
    requests = [
        {
            "challenge_id": "challenge-15-a",
            "action": "register",
            "client": "client-a",
            "entropy": "entropy-15-a",
            "risk": "low",
        },
        {
            "challenge_id": "challenge-15-b",
            "action": "register",
            "client": "client-b",
            "entropy": "entropy-15-b",
            "risk": "high",
        },
    ]
    batch = ticket_batch(requests, GOOD_POLICY, 1000)
    single_first = ticket_batch([requests[0]], GOOD_POLICY, 1000)
    single_second = ticket_batch([requests[1]], GOOD_POLICY, 1000)

    assert batch["results"][0] == single_first["results"][0]
    assert batch["results"][1] == single_second["results"][0]
    assert ticket_batch(requests, GOOD_POLICY, 1000) == batch
    assert batch["results"][0]["ticket"]["ticket_id"] != batch["results"][1]["ticket"]["ticket_id"]