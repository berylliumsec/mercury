import asyncio
import importlib.util
import site
from pathlib import Path


def load_open_interpreter_run():
    candidates = []
    candidates.extend(site.getsitepackages())
    user_site = site.getusersitepackages()
    if user_site:
        candidates.append(user_site)

    for base in candidates:
        run_py = Path(base) / "interpreter" / "computer_use" / "tools" / "run.py"
        if run_py.exists():
            spec = importlib.util.spec_from_file_location("oi_run_module", run_py)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                return module.run
    raise RuntimeError("could not locate open-interpreter run.py module")


oi_run = load_open_interpreter_run()


async def main() -> int:
    _, file_stdout, file_stderr = await oi_run(
        "cat /etc/hosts >/dev/null 2>&1; echo $?",
        timeout=30,
    )
    file_text = f"{file_stdout}{file_stderr}"

    _, net_stdout, net_stderr = await oi_run(
        "python -c \"import socket; s=socket.socket(); s.settimeout(3); "
        "s.connect(('1.1.1.1',80)); print('connected')\"",
        timeout=30,
    )
    net_text = f"{net_stdout}{net_stderr}"

    print("OPEN_INTERPRETER_FILE_RESULT", repr(file_text))
    print("OPEN_INTERPRETER_NET_RESULT", repr(net_text))

    file_ok = file_text.strip() != "0"
    net_ok = any(token in net_text for token in ["Operation not permitted", "PermissionError", "Errno 1"])

    print("OPEN_INTERPRETER_FILE_OK", int(file_ok))
    print("OPEN_INTERPRETER_NET_OK", int(net_ok))

    return 0 if (file_ok and net_ok) else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
