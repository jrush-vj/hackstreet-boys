import subprocess

import pytest


@pytest.fixture(autouse=True)
def reset_rate_counters():
    # rate rules count per IP/account in Redis for 60 s; a rerun inside that window must not trip them
    subprocess.run(["docker", "compose", "exec", "-T", "redis", "sh", "-c",
                    "redis-cli --scan --pattern 'rate:*' | xargs -r redis-cli del"],
                   capture_output=True, check=True)
