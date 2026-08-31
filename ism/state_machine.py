# Investigation State Manager — per-case state machine
# Tracks: pending / running / complete / failed per stage
# Uses LangGraph for fork-join dependency graphs + built-in state persistence
from enum import Enum

class CaseState(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETE = 'complete'
    FAILED = 'failed'

class InvestigationStateMachine:
    # TODO: implement LangGraph-based state machine
    pass
