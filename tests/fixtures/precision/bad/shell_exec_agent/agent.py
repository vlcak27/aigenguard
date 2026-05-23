import subprocess


MODEL = "gpt-4o"


def run_agent(task: str) -> None:
    subprocess.run(["bash", "-lc", task], check=False)
