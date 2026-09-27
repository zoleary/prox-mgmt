from types import SimpleNamespace as NS

from labpilot.chat import ChatService
from labpilot.config import Settings
from labpilot.db import DB

from .test_actions import FakeState


class FakeClient:
    """Replays scripted responses and records each request's messages."""

    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []
        self.messages = self
        self.beta = NS(messages=self)

    def create(self, **kwargs):
        self.requests.append([dict(m) for m in kwargs["messages"]])
        return self.responses.pop(0)


def tool_use(id_, name, inp):
    return NS(type="tool_use", id=id_, name=name, input=inp)


def text(t):
    return NS(type="text", text=t)


def test_write_tool_is_queued_not_run(tmp_path):
    state, db = FakeState(), DB(str(tmp_path))
    svc = ChatService(Settings(anthropic_api_key="x"), state, db)
    svc.client = FakeClient([
        NS(stop_reason="tool_use", content=[tool_use("t1", "guest_power", {"guest": "web", "action": "reboot"})]),
        NS(stop_reason="end_turn", content=[text("Queued reboot of web as change #1; approve it to run.")]),
    ])
    out = svc.send(None, "reboot web")
    assert out["proposed"] == [{"id": 1, "summary": "Reboot qemu/101 web on pve1"}]
    assert state.integrations["proxmox"].calls == []
    assert db.get_action(1)["status"] == "pending"
    # the tool result sent back to the model says it's queued
    result = svc.client.requests[1][-1]["content"][0]
    assert result["tool_use_id"] == "t1" and "queued_for_approval" in result["content"]


def test_bad_tool_input_returns_error_result(tmp_path):
    state, db = FakeState(), DB(str(tmp_path))
    svc = ChatService(Settings(anthropic_api_key="x"), state, db)
    svc.client = FakeClient([
        NS(stop_reason="tool_use", content=[tool_use("t1", "get_guest", {"guest": "nope"})]),
        NS(stop_reason="end_turn", content=[text("No such guest.")]),
    ])
    out = svc.send(None, "show nope")
    result = svc.client.requests[1][-1]["content"][0]
    assert result["is_error"] and out["reply"] == "No such guest."
