"""Platform capabilities used by filesystem integration tests."""

import pytest


@pytest.fixture
def make_symlink():
    def create(link, target):
        try:
            link.symlink_to(target)
        except OSError as exc:
            if getattr(exc, "winerror", None) == 1314:
                pytest.skip("Windows account lacks symlink creation privilege")
            raise
    return create
