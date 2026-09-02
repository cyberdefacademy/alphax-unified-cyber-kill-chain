from typing import Any

def parse_generic(stdout: str, stderr: str) -> dict[str, Any]:
    return {"stdout_preview": stdout[:5000] if stdout else "", "stderr_preview": stderr[:2000] if stderr else "", "length": len(stdout) if stdout else 0}
