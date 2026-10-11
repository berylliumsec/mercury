from smolagents import CodeAgent
from smolagents.models import ChatMessage, MessageRole, Model


class FixedModel(Model):
    def __init__(self, code: str) -> None:
        super().__init__(model_id="fixed")
        self.code = code

    def generate(
        self,
        messages,
        stop_sequences=None,
        response_format=None,
        tools_to_call_from=None,
        **kwargs,
    ):
        return ChatMessage(
            role=MessageRole.ASSISTANT,
            content=f"<code>{self.code}</code>",
        )


CODE = (
    "import socket\n"
    "try:\n"
    "    s = socket.socket()\n"
    "    s.settimeout(3)\n"
    "    s.connect(('1.1.1.1', 80))\n"
    "    final_answer('connected')\n"
    "except Exception as e:\n"
    "    final_answer(str(e))"
)

agent = CodeAgent(
    tools=[],
    model=FixedModel(CODE),
    max_steps=1,
    additional_authorized_imports=["socket"],
)

result = agent.run("Try network connect")
print("SMOL_NET_RESULT", result)

if not any(token in str(result) for token in ["Operation not permitted", "PermissionError", "Errno 1"]):
    raise SystemExit(2)

print("SMOL_NET_DENY_OK")
