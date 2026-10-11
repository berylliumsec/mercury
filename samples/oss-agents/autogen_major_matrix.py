import asyncio

from autogen_agentchat.agents import CodeExecutorAgent
from autogen_ext.code_executors.local import LocalCommandLineCodeExecutor


def last_non_empty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        value = line.strip()
        if value:
            return value
    return ""


async def run_task(task: str) -> str:
    agent = CodeExecutorAgent(
        "executor",
        code_executor=LocalCommandLineCodeExecutor(timeout=30),
    )
    result = await agent.run(task=task)
    if not result.messages:
        return ""
    return "\n".join(str(message.content) for message in result.messages)


async def main() -> int:
    file_output = await run_task(
        "Run this and return output only:\n"
        "```sh\n"
        "cat /etc/hosts >/dev/null 2>&1; echo $?\n"
        "```"
    )
    net_output = await run_task(
        "Run this and return output only:\n"
        "```python\n"
        "import socket\n"
        "s = socket.socket()\n"
        "s.settimeout(3)\n"
        "s.connect(('1.1.1.1', 80))\n"
        "print('connected')\n"
        "```"
    )

    print("AUTOGEN_FILE_OUTPUT", repr(file_output))
    print("AUTOGEN_NET_OUTPUT", repr(net_output))

    file_ok = last_non_empty_line(file_output) != "0"
    net_ok = any(
        token in net_output
        for token in [
            "Operation not permitted",
            "PermissionError",
            "Errno 1",
            "exit code: 1",
        ]
    )

    print("AUTOGEN_FILE_OK", int(file_ok))
    print("AUTOGEN_NET_OK", int(net_ok))

    return 0 if (file_ok and net_ok) else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
