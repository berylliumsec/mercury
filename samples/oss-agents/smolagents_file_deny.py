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
    "import os\n"
    "rc = os.system('cat /etc/hosts >/dev/null 2>&1')\n"
    "final_answer(str(rc))"
)

agent = CodeAgent(
    tools=[],
    model=FixedModel(CODE),
    max_steps=1,
    additional_authorized_imports=["os"],
)

result = agent.run("Try reading /etc/hosts")
print("SMOL_FILE_RESULT", result)

if str(result) == "0":
    raise SystemExit(2)

print("SMOL_FILE_DENY_OK")
