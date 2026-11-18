"""
shell/execution.py — what the kernel answers when a file we hold is run.

Only exact answers: directory, missing exec bit, binary for the wrong CPU,
non-ELF binary. Anything that would really run (scripts, binaries for this
CPU) returns (False, None) so normal routing handles it.

Same contract as responders.py:
    -> (True,  output)  handled; this is the answer
    -> (False, None)    not ours; let the router decide
"""
from prompt.prompt_manager import _decode_echo_payload

# ELF e_machine values each persona CPU can run
_RUNNABLE_MACHINES = {
    "x86_64": {0x3E, 0x03},    # 64-bit kernels also run 32-bit x86
    "amd64": {0x3E, 0x03},
    "i386": {0x03},
    "i686": {0x03},
    "aarch64": {0xB7},
    "arm64": {0xB7},
    "armv7l": {0x28},
    "armv6l": {0x28},
    "armv5l": {0x28},
    "arm": {0x28},
    "mips": {0x08},
    "mipsel": {0x08},
    "ppc": {0x14},
    "ppc64le": {0x15},
}
_BIG_ENDIAN = {"mips", "ppc"}
_ELF_MAGIC = b"\x7fELF"

# Redirects, pipes and chains change what the attacker sees; not ours in v1
_SHELL_SYNTAX = set("<>|;&`$")


class Executor:
    """One session's exec-time kernel checks.

        executor.check("./bot.arm")
        -> (True, "-bash: ./bot.arm: cannot execute binary file: Exec format error")
    """

    def __init__(self, state: dict, fs, arch: str):
        self.state = state
        self.fs = fs
        self.arch = (arch or "").lower()

    def check(self, cmd: str):
        parts = cmd.split()
        if not parts or _SHELL_SYNTAX & set(cmd):
            return False, None
        token = parts[0]
        # A bare name is a PATH lookup, not a file we hold
        if "/" not in token:
            return False, None
        rec = self.state["files"].get(self.fs.resolve(token))
        # Cowrie holds the real bytes of its own downloads
        if rec is None or rec.get("backend") == "cowrie":
            return False, None

        perms = rec.get("perms", "")
        if not perms:
            return False, None
        if perms.startswith("d"):
            return True, f"-bash: {token}: Is a directory"
        if not _executable(perms):
            return True, f"-bash: {token}: Permission denied"

        data = _decode_echo_payload(rec.get("content", ""))
        if data.startswith(_ELF_MAGIC):
            if self._runs_here(data):
                return False, None
            return True, _exec_format_error(token)
        if _bash_sees_binary(data):
            return True, _exec_format_error(token)
        return False, None

    def _runs_here(self, elf: bytes) -> bool:
        machines = _RUNNABLE_MACHINES.get(self.arch)
        # Unknown CPU or truncated header: don't guess, let routing decide
        if machines is None or len(elf) < 20:
            return True
        big_endian = elf[5] == 2
        if big_endian != (self.arch in _BIG_ENDIAN):
            return False
        machine = int.from_bytes(elf[18:20], "big" if big_endian else "little")
        return machine in machines


def _executable(perms: str) -> bool:
    # Root still needs at least one execute bit, in any class
    return any(len(perms) > i and perms[i] in "xst" for i in (3, 6, 9))


def _bash_sees_binary(data: bytes) -> bool:
    # bash's check_binary_file(): a NUL before the first newline in 80 bytes
    for byte in data[:80]:
        if byte == 0x0A:
            return False
        if byte == 0x00:
            return True
    return False


def _exec_format_error(token: str) -> str:
    return f"-bash: {token}: cannot execute binary file: Exec format error"
