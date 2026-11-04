import sys

import pytest


@pytest.fixture(autouse=True)
def _linux_platform_for_fake_runners(monkeypatch):
    """Tests feed Linux `ip` output to fake runners, so they must see Linux as the host.

    Without this, code that picks its command by sys.platform runs `ifconfig` on macOS
    and fails on interface names that only exist on Linux. Tests that need another
    platform set it themselves with monkeypatch, which runs after this fixture.
    """
    monkeypatch.setattr(sys, "platform", "linux")
