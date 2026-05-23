MODEL = "gpt-4o"


def run_agent(expression: str) -> object:
    return eval(expression)
