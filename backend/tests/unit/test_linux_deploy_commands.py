"""Linux deploy commands (phase L6): only the fixed commands exist, every value is validated before it is placed in a
command, root goes through sudo without ever putting the password on the command line, and the precheck picks the
build for the host's CPU."""

from __future__ import annotations

import pytest

from app.adapters.base import Credential
from app.adapters.real.net import ssh as ssh_net
from app.adapters.real.ssh import parse_df, parse_service
from app.core.config import Settings
from app.engines.classification import eligibility
from app.engines.deployment.engine import package_compatible
from app.engines.remote import LINUX, WINDOWS, platform_for
from app.models import Package
from app.rules.book import RuleBook

UPLOAD = "/var/tmp/otprobe.Ab3dE5fG7h"
GOOD = {"path": f"{UPLOAD}/otprobe-agent-0.5.0-linux-arm64", "sha256": "0" * 64, "token": "enr_" + "x" * 30,
        "server_url": "https://10.0.0.5:8443", "ca_sha256": "", "deployment_id": "01a1afa2-3be4-706f-90a1-5ae0e71eb3a1",
        "profile": "linux-host"}


@pytest.mark.parametrize("key,value", [
    ("path", "/etc/shadow"), ("path", f"{UPLOAD}/../../etc/passwd"), ("path", f"{UPLOAD}/x; rm -rf /"),
    ("path", "/var/tmp/otprobe.short/otprobe-agent-1"), ("sha256", "abc"), ("token", "enr_'; reboot #"),
    ("server_url", "http://10.0.0.5"), ("server_url", "https://x$(id)"), ("profile", "Linux Host"),
    ("deployment_id", "1; id"),
])
def test_unsafe_values_are_refused_before_any_command_is_built(key, value):
    with pytest.raises(ValueError):
        ssh_net.deploy_command("install", {**GOOD, key: value})


def test_only_known_commands_exist():
    with pytest.raises(ValueError):
        ssh_net.deploy_command("rm -rf /")
    with pytest.raises(KeyError):
        ssh_net.deploy_command("q_server_connectivity", {"server": "10.0.0.5", "port": "8443", "x": "1"})


def test_install_checks_the_hash_on_a_root_owned_copy_before_installing():
    cmd = ssh_net.deploy_command("install", GOOD)
    copy, check, move = cmd.index("cp "), cmd.index("sha256sum"), cmd.index("mv -f")
    assert copy < check < move < cmd.index("install --config")
    assert "chmod 0600 /etc/otprobe/agent.json" in cmd and "chmod 0700 /etc/otprobe" in cmd
    assert '"enrollmentToken": "enr_' in cmd


def test_removing_an_upload_removes_its_whole_private_folder():
    assert ssh_net.deploy_command("remove_upload", {"path": GOOD["path"]}) == f"rm -rf -- {UPLOAD}"
    assert ssh_net.deploy_command("remove_uploads") == "rm -rf -- /var/tmp/otprobe.??????????"


def test_privilege():
    root = Credential("p", "root", "pw-1")
    assert ssh_net.with_privilege("id -u", root) == ("id -u", "")
    cmd, stdin = ssh_net.with_privilege("id -u", Credential("p", "otprobe", "s3cret pass"))
    assert cmd == "sudo -S -p '' sh -c 'id -u'" and stdin == "s3cret pass\n" and "s3cret" not in cmd
    assert ssh_net.with_privilege("id -u", Credential("p", "otprobe", "KEY", {"auth": "key"})) == \
        ("sudo -n sh -c 'id -u'", "")


def test_parsers():
    df = "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 61255492 12582912 45545472 22% /\n"
    assert parse_df(df) == [{"drive": "/", "size_gb": 58, "free_gb": 43.4}]
    assert parse_service("otprobe-agent active enabled\n") == {"name": "otprobe-agent", "state": "running",
                                                                "start_type": "enabled"}
    assert parse_service("otprobe-agent failed enabled")["state"] == "stopped"
    assert parse_service("") is None


def pkg(arch: str, supported: list[str]) -> Package:
    return Package(id="p", name=f"OTProbe Agent ({arch})", version="0.5.0", architecture=arch, sha256="0" * 64,
                   size_bytes=1, supported_os=supported, status="ACTIVE")


def test_package_must_match_the_os_family_and_the_cpu():
    linux_arm = pkg("linux/arm64", ["Debian", "Raspbian"])
    assert package_compatible(linux_arm, "Raspbian GNU/Linux", LINUX, "arm64")[0]
    ok, why = package_compatible(linux_arm, "Debian GNU/Linux", LINUX, "amd64")
    assert not ok and "choose the amd64 build" in why
    ok, why = package_compatible(pkg("windows/amd64", ["Debian"]), "Debian GNU/Linux", LINUX)
    assert not ok and "built for windows" in why
    assert package_compatible(pkg("x64", ["Windows 10"]), "Windows 10 Pro", WINDOWS)[0]   # simulator packages
    v7 = pkg("linux/arm", ["Raspbian"])
    v7.id = "agent-0.5.0-linux-armv7"
    ok, why = package_compatible(v7, "Raspbian GNU/Linux", LINUX, "arm", "armv6l")
    assert not ok and "linux-armv6 build" in why
    assert package_compatible(v7, "Raspbian GNU/Linux", LINUX, "arm", "armv7l")[0]


def test_platform_and_eligibility_for_linux():
    assert platform_for({"os.family": "linux"}) is LINUX and platform_for({"os.family": "windows"}) is WINDOWS
    assert LINUX.options({"ssh.host_key": "ssh-ed25519 AAAA"}) == {"host_key": "ssh-ed25519 AAAA"}
    book = RuleBook.load(Settings().rules_dir)
    host = {"os": {"family": "linux"}, "classification": {"type": "Linux Server"}}
    ssh = {"services": {"ssh": {"available": True}}}
    assert eligibility({**host, **ssh}, book)[0] == "ELIGIBLE"
    assert eligibility(host, book)[0] == "NOT_ELIGIBLE"
    assert eligibility({**host, **ssh, "asset": {"criticality": "CRITICAL"}}, book)[0] == "REVIEW_REQUIRED"
