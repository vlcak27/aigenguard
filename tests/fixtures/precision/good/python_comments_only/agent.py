"""Example notes for reviewers.

The words subprocess.run, os.system, eval(, and exec( appear here only as text
that explains what this fixture must not implement.
"""


# Do not add shell execution to this fixture.
# Mentioning subprocess or bash in a comment is not a callable capability.
def summarize() -> str:
    return "static documentation text only"
