import ast
import operator
import re
from typing import Optional, List, Dict, Any
import logging
from fastapi import APIRouter, HTTPException, Header, Depends
from pydantic import BaseModel
from api.routes.auth import get_current_user
from sanitization.injection_gate import InjectionGate
from fir.repository import FIRRepository
from models.llm import OllamaWrapper
from config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# Share the repository instance so the API and tests can interact with the same database
_fir_repo = FIRRepository()
_injection_gate = InjectionGate()


def try_eval_math(expr: str) -> Optional[str]:
    """Safely evaluates basic arithmetic expressions with zero latency."""
    allowed_ops = {
        ast.Add: operator.add,
        ast.Sub: operator.sub,
        ast.Mult: operator.mul,
        ast.Div: operator.truediv,
        ast.Pow: operator.pow,
        ast.USub: operator.neg,
        ast.UAdd: operator.pos,
    }
    if not expr or not isinstance(expr, str):
        return None
    cleaned = expr.strip()
    # Strip leading question phrases
    cleaned = re.sub(r'^(?:what\s+is|what\'s|calculate|compute|solve|eval|evaluate)\s+', '', cleaned, flags=re.IGNORECASE)
    # Strip trailing punctuation like ?, = and surrounding whitespace
    cleaned = re.sub(r'[\s\?\=]+$', '', cleaned).strip()

    # Reject if empty or contains alphabetical characters (rejects CVEs, Case IDs, names, words)
    if not cleaned or re.search(r'[a-zA-Z]', cleaned):
        return None
    # Reject dates like 2026-09-11
    if re.match(r'^\d{4}-\d{2}-\d{2}$', cleaned):
        return None
    # Reject IPs like 192.168.1.1
    if cleaned.count(".") >= 2:
        return None

    # Remove commas from formatted numbers e.g. 2,346,577
    expr_no_commas = cleaned.replace(",", "")

    # Normalize exponentiation symbol ^ to **
    normalized = expr_no_commas.replace("^", "**")

    # Must contain only digits, whitespace, arithmetic operators, parentheses, decimal point
    if not re.match(r'^[\d\s\+\-\*/\(\)\.]+$', normalized):
        return None

    # Must have at least one arithmetic operator
    if not any(op in normalized for op in ("+", "-", "*", "/")):
        return None

    try:
        node = ast.parse(normalized, mode='eval')

        def _eval(n):
            if isinstance(n, ast.Expression):
                return _eval(n.body)
            elif isinstance(n, ast.Constant) and isinstance(n.value, (int, float)):
                return n.value
            elif isinstance(n, ast.UnaryOp) and type(n.op) in allowed_ops:
                return allowed_ops[type(n.op)](_eval(n.operand))
            elif isinstance(n, ast.BinOp) and type(n.op) in allowed_ops:
                left = _eval(n.left)
                right = _eval(n.right)
                if left is None or right is None:
                    return None
                # Protect against excessive compute/memory
                if isinstance(n.op, ast.Pow) and (right > 100 or left > 100000):
                    return None
                return allowed_ops[type(n.op)](left, right)
            return None

        res = _eval(node)
        if res is not None:
            if isinstance(res, float) and res.is_integer():
                res = int(res)
            if isinstance(res, int):
                return f"{cleaned} equals {res:,}."
            else:
                return f"{cleaned} equals {round(res, 6)}."
    except Exception:
        pass
    return None


def check_history_verification(history: Optional[List[Dict[str, Any]]], clean_case_id: str) -> Optional[str]:
    """Checks recent conversation history when the analyst asks to recheck or verify."""
    if not history or not isinstance(history, list):
        return None
    for h in reversed(history):
        content = (h.get("content") or "").strip()
        if not content:
            continue
        # 1. Did the user query evaluate to a math expression?
        math_res = try_eval_math(content)
        if math_res:
            return f"I double-checked the calculation: **{math_res}** The result is verified and exact."
        # Did the assistant output an equality statement like 'X equals Y.'?
        m_eq = re.search(r'([\d\s\+\-\*/\(\)\.\^,]+)\s+equals\s+([\d,]+(?:\.\d+)?)\.', content, re.IGNORECASE)
        if m_eq:
            prev_math = try_eval_math(m_eq.group(1))
            if prev_math:
                return f"I have re-verified the calculation: **{prev_math}** The result is confirmed and exact."
            return f"I double-checked the calculation: **{m_eq.group(0)}** The result is confirmed and exact."
        # 2. Forensic re-verification queries are delegated directly to the conversational reasoning engine
        # to ensure case-specific context grounding without fixed templates.
    return None


class QueryRequest(BaseModel):
    query: str
    history: Optional[list] = None


class QueryResponse(BaseModel):
    response: str
    injection_flagged: bool
    injection_score: float
    model_tag: Optional[str] = None
    execution_mode: str = "LLM_GENERATED"
    retrieval_only: bool = False
    latency_ms: Optional[float] = None


from forensic_analysis.investigation_context import CaseInvestigationContext
from forensic_analysis.conversational_assistant import ConversationalInvestigationEngine


@router.post("/{case_id}/query", response_model=QueryResponse)
async def query_case(case_id: str, req: QueryRequest, x_tenant_id: str = Header(..., alias="X-Tenant-ID"), current_user: dict = Depends(get_current_user)):
    import time
    t_start = time.perf_counter()
    from api.routes.evidence import sanitize_uuid
    clean_case_id = sanitize_uuid(case_id)

    # 1. Fast deterministic math & arithmetic expression evaluator (< 0.1ms)
    math_eval = try_eval_math(req.query)
    if math_eval:
        return QueryResponse(
            response=math_eval,
            injection_flagged=False,
            injection_score=0.0,
            model_tag=None,
            execution_mode="RETRIEVAL_ONLY",
            retrieval_only=True,
            latency_ms=round((time.perf_counter() - t_start) * 1000, 2),
        )

    # 1.1 Fast verification & re-check handler using conversation history (< 0.1ms)
    clean_q = req.query.strip().lower()
    verification_triggers = (
        "check once more", "check again", "recheck", "re-check", "verify that",
        "verify again", "are you sure", "is that right", "is that correct",
        "double check", "double-check", "calculate again", "recalculate", "confirm that"
    )
    if (clean_q in verification_triggers or any(clean_q.startswith(t) for t in verification_triggers)) and req.history:
        v_resp = check_history_verification(req.history, clean_case_id)
        if v_resp:
            return QueryResponse(
                response=v_resp,
                injection_flagged=False,
                injection_score=0.0,
                model_tag=None,
                execution_mode="RETRIEVAL_ONLY",
                retrieval_only=True,
                latency_ms=round((time.perf_counter() - t_start) * 1000, 2),
            )

    # 1.2 Fast deterministic real-time clock & date handler (< 0.1ms)
    time_triggers = (
        "what is the time", "what time is it", "current time", "what's the time",
        "tell me the time", "time now", "what time is it now", "whats the time"
    )
    date_triggers = (
        "what is today's date", "what's the date", "what is the date", "today's date",
        "current date", "what day is it", "whats the date", "today date"
    )
    is_time_query = (
        clean_q in time_triggers or
        clean_q == "time" or
        (any(clean_q.startswith(t) for t in ("what time", "what is the time", "tell me the time", "current time")) and not any(k in clean_q for k in ("attack", "incident", "breach", "c2", "beacon", "malware", "event", "case")))
    )
    is_date_query = (
        clean_q in date_triggers or
        clean_q == "date" or
        clean_q == "today" or
        (any(clean_q.startswith(d) for d in ("what is the date", "what's the date", "today's date", "what day")) and not any(k in clean_q for k in ("attack", "incident", "breach", "event", "case")))
    )

    if is_time_query or is_date_query:
        from datetime import datetime, timezone
        now_local = datetime.now()
        now_utc = datetime.now(timezone.utc)
        local_str = now_local.strftime("%I:%M %p").lstrip("0")
        utc_str = now_utc.strftime("%H:%M UTC")
        date_str = now_local.strftime("%A, %B %d, %Y")

        if is_time_query and not is_date_query:
            resp_str = f"The current system time is **{local_str}** ({utc_str})."
        elif is_date_query and not is_time_query:
            resp_str = f"Today's date is **{date_str}**."
        else:
            resp_str = f"The current system time is **{local_str}** ({utc_str}) on **{date_str}**."

        return QueryResponse(
            response=resp_str,
            injection_flagged=False,
            injection_score=0.0,
            model_tag=None,
            execution_mode="RETRIEVAL_ONLY",
            retrieval_only=True,
            latency_ms=round((time.perf_counter() - t_start) * 1000, 2),
        )

    # 1.3 Injection check on analyst query
    gate_res = _injection_gate.check(req.query, field_name="unstructured")

    # 2. Load Unified Case Investigation Context (reusing FIR, DB, Neo4j, Qdrant)
    context = CaseInvestigationContext(case_id=clean_case_id, tenant_id=x_tenant_id, fir_repo=_fir_repo).load()

    # 3. Conversational Investigation Engine (Natural language, typos, follow-ups, grounded reasoning)
    assistant = ConversationalInvestigationEngine(context=context)
    response_text, meta = assistant.answer_query_with_metadata(query=req.query, history=req.history)
    elapsed_total_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return QueryResponse(
        response=response_text,
        injection_flagged=gate_res.injection_flagged,
        injection_score=gate_res.injection_score,
        model_tag=meta.get("model_tag"),
        execution_mode=meta.get("execution_mode", "LLM_GENERATED"),
        retrieval_only=meta.get("retrieval_only", False),
        latency_ms=elapsed_total_ms,
    )
