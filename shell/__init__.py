"""
shell/ — how HydraPoT's fake Linux box behaves.

Everything main.py used to hold as closures inside one 1,500-line function.
Grouped by JOB, one file per question:

    fakefs.py      where am I, what path is this, what's in that file
    software.py    what is installed, what version, what apt prints
    state.py       what changed after a command ran
    responders.py  answers computed without asking a model
    cowrie_link.py talking to the Cowrie container, and surviving it dying

main.py keeps what is genuinely dispatch: parse the command, decide who answers,
call them, log it.

PER-SESSION, NOT GLOBAL. Each SSH session owns its own SYSTEM_STATE, so these
are objects constructed per session rather than module-level functions reading a
shared dict. Two attackers must never see each other's files.

Not the same thing as agent_manager/ -- that is who ANSWERS (cowrie, on_device,
cloud). This is what the answer has to be consistent with.
"""
from shell.fakefs import FakeFS, mode_to_perms
from shell.software import Software
from shell.state import StateTracker
from shell.responders import Responders
from shell.cowrie_link import CowrieLink

__all__ = ["FakeFS", "mode_to_perms", "Software", "StateTracker",
           "Responders", "CowrieLink"]
