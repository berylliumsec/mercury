import os
import subprocess

os.environ.setdefault("LANGCHAIN_TRACING_V2", "false")
os.environ.setdefault("LANGSMITH_TRACING", "false")
os.environ.setdefault("LANGSMITH_API_KEY", "")

from langchain_classic.agents import AgentType, initialize_agent
from langchain_core.language_models.fake import FakeListLLM
from langchain_core.tools import Tool


def shell(cmd: str) -> str:
    proc = subprocess.run(["bash", "-lc", cmd], capture_output=True, text=True)
    return f"rc={proc.returncode}\n{proc.stdout}{proc.stderr}"


def run_single_action(action_input: str) -> str:
    llm = FakeListLLM(
        responses=[
            "Thought: I should run the command\n"
            "Action: shell\n"
            f"Action Input: {action_input}",
            "Final Answer: completed",
        ]
    )
    agent = initialize_agent(
        [Tool(name="shell", func=shell, description="Run shell command")],
        llm,
        agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
        return_intermediate_steps=True,
        verbose=False,
    )
    result = agent.invoke({"input": "Execute command"})
    return str(result["intermediate_steps"][0][1])


file_observation = run_single_action("cat /etc/hosts >/dev/null 2>&1")
net_observation = run_single_action(
    "python -c 'import socket; s=socket.socket(); s.settimeout(3); "
    "s.connect((\"1.1.1.1\",80)); print(\"connected\")'"
)

print("LANGCHAIN_FILE_OBSERVATION", repr(file_observation))
print("LANGCHAIN_NET_OBSERVATION", repr(net_observation))

file_ok = "rc=0" not in file_observation
net_ok = ("Operation not permitted" in net_observation) or ("rc=1" in net_observation)

print("LANGCHAIN_FILE_OK", int(file_ok))
print("LANGCHAIN_NET_OK", int(net_ok))

if not (file_ok and net_ok):
    raise SystemExit(2)
