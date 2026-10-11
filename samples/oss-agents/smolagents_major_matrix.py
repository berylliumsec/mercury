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


def run_agent(code: str, prompt: str, imports: list[str]) -> str:
    agent = CodeAgent(
        tools=[],
        model=FixedModel(code),
        max_steps=1,
        additional_authorized_imports=imports,
    )
    return str(agent.run(prompt))


file_result = run_agent(
    "import os\n"
    "rc = os.system('cat /etc/hosts >/dev/null 2>&1')\n"
    "final_answer(str(rc))",
    "Try reading /etc/hosts",
    ["os"],
)

net_result = run_agent(
    "import socket\n"
    "try:\n"
    "    s = socket.socket()\n"
    "    s.settimeout(3)\n"
    "    s.connect(('1.1.1.1', 80))\n"
    "    final_answer('connected')\n"
    "except Exception as e:\n"
    "    final_answer(str(e))",
    "Try connecting to 1.1.1.1:80",
    ["socket"],
)

print("SMOLAGENTS_FILE_RESULT", file_result)
print("SMOLAGENTS_NET_RESULT", net_result)

file_ok = file_result != "0"
net_ok = any(token in net_result for token in ["Operation not permitted", "PermissionError", "Errno 1"])

print("SMOLAGENTS_FILE_OK", int(file_ok))
print("SMOLAGENTS_NET_OK", int(net_ok))

if not (file_ok and net_ok):
    raise SystemExit(2)
