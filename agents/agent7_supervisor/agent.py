"""
Agent 7 — Supervisor + Verification + Report Generation
========================================================
Main unified entrypoint for Agent 7.
Coordinates the complete final investigation lifecycle:
  1. Input Validation: Ensures case_id, tenant_id, and inputs are valid before execution.
  2. Call 1 (Synthesis): Uses Qwen3-8B to merge upstream findings (Agents 3, 4, 5b, 6),
     resolve conflicts, and generate structured claims + Investigation Confidence Score.
  3. Call 2 (Verification): Evaluates each claim in an ISOLATED context via DeBERTa-v3-large-MNLI,
     deterministic existence checks, severity inflation checks, and divergence checks.
  4. Confidence Gate: Evaluates verification outcomes to conditionally route to
     Routine Analyst Review vs Mandatory Senior/Dual Review.
  5. Report Generation: Deterministically renders Analyst Report, Customer Report, and Executive
     Summary with legal metadata stamping.
  6. Interactive Assistant: Answers analyst queries on demand with grounded evidence.
  7. Failure Terminal Node: Handles validation/synthesis failures cleanly without generating
     an approved final report package.

Orchestrated using a compiled LangGraph StateGraph workflow with explicit conditional branches.
"""

from __future__ import annotations

import logging
from typing import Dict, Any, Optional, List
from langgraph.graph import StateGraph, START, END

from agents.base_agent import BaseAgent
from fir.repository import FIRRepository
from sanitization.gateway import SanitizationGateway
from models.llm import LLMLoader
from confidence_gate.gate import ConfidenceGate
from agents.agent7_supervisor.schemas import (
    Agent7State, SupervisorOutput, StructuredClaim,
    ClaimVerificationResult, InvestigationSynthesis, ConfidenceGateDecision
)
from agents.agent7_supervisor.call1_synthesis import SupervisorSynthesis
from agents.agent7_supervisor.call2_verification import SupervisorVerification
from agents.agent7_supervisor.report_builder import SupervisorReportBuilder
from agents.agent7_supervisor.assistant import InteractiveInvestigationAssistant

logger = logging.getLogger(__name__)


class SupervisorAgent(BaseAgent):
    """
    Agent 7 — Supervisor Agent.
    Coordinates synthesis, independent verification, confidence gate routing,
    and report generation using LangGraph.
    """

    def __init__(
        self,
        model: Optional[Any] = None,
        fir_repo: Optional[Any] = None,
        sanitization_gateway: Optional[Any] = None,
        tenant_id: str = "default",
        confidence_threshold: Optional[float] = None,
    ):
        # Mandatory Constraint: Use Qwen3-8B for Agent 7 synthesis
        model_instance = model if model is not None else LLMLoader().load_qwen3_8b()
        fir_instance = fir_repo if fir_repo is not None else FIRRepository()
        gateway_instance = sanitization_gateway if sanitization_gateway is not None else SanitizationGateway()

        super().__init__(
            model=model_instance,
            fir_repo=fir_instance,
            sanitization_gateway=gateway_instance,
            tenant_id=tenant_id
        )

        self.call1 = SupervisorSynthesis(
            model=self.model,
            fir_repo=self.fir,
            sanitization_gateway=self.gateway,
            tenant_id=self.tenant_id
        )
        self.call2 = SupervisorVerification(
            model=self.model,
            fir_repo=self.fir,
            sanitization_gateway=self.gateway,
            tenant_id=self.tenant_id
        )
        self.confidence_gate = ConfidenceGate(confidence_threshold=confidence_threshold)
        self.report_builder = SupervisorReportBuilder()
        self.interactive_assistant = InteractiveInvestigationAssistant()

        # Build and compile LangGraph StateGraph with conditional branching
        self.workflow = self._build_langgraph_workflow()

    def _build_langgraph_workflow(self):
        """
        Builds the LangGraph StateGraph representing Agent 7's execution graph:
        START -> input_validation
                 ├─ (invalid) ───────────────────────────────────► failure_terminal_node -> END
                 └─ (valid) -> synthesis
                               ├─ (error) ───────────────────────► failure_terminal_node -> END
                               └─ (success) -> verification
                                                 -> confidence_gate
                                                      ├─ (senior_dual) -> senior_dual_routing ─┐
                                                      └─ (routine)     -> routine_routing     ─┴─► report_generation -> END
        """
        builder = StateGraph(Agent7State)

        # ── Node 1: Input Validation ─────────────────────────────────
        def input_validation_node(state: Agent7State) -> Agent7State:
            case_id = state.get("case_id")
            tenant_id = state.get("tenant_id") or self.tenant_id

            if not case_id or not str(case_id).strip() or str(case_id).strip().upper() == "UNKNOWN":
                return {
                    "validation_passed": False,
                    "status": "FAILED",
                    "error": "INVALID_INPUTS: case_id is missing, empty, or UNKNOWN.",
                }

            return {
                "validation_passed": True,
                "status": "INITIALIZED",
                "error": None,
                "tenant_id": tenant_id,
            }

        # ── Node 2: Call 1 Synthesis ─────────────────────────────────
        def synthesis_node(state: Agent7State) -> Agent7State:
            case_id = state.get("case_id", "")
            tenant_id = state.get("tenant_id", self.tenant_id)
            context = dict(state.get("context", {}))
            context["tenant_id"] = tenant_id

            try:
                synthesis_data = self.call1.run(case_id, context)
                if synthesis_data.get("synthesis_status") == "FAILED" or synthesis_data.get("synthesis_error"):
                    return {
                        "status": "FAILED",
                        "error": synthesis_data.get("synthesis_error") or "SYNTHESIS_FAILED",
                        "synthesis": synthesis_data,
                        "claims": [],
                    }
                claims = synthesis_data.get("claims", [])
                return {
                    "status": "SYNTHESIS_COMPLETED",
                    "synthesis": synthesis_data,
                    "claims": claims,
                }
            except Exception as e:
                logger.error(f"Agent 7 synthesis node encountered exception: {e}", exc_info=True)
                return {
                    "status": "FAILED",
                    "error": f"SYNTHESIS_ERROR: {str(e)}",
                }

        # ── Node 3: Call 2 Independent Verification ──────────────────
        def verification_node(state: Agent7State) -> Agent7State:
            case_id = state.get("case_id", "")
            tenant_id = state.get("tenant_id", self.tenant_id)
            claims = state.get("claims", [])

            try:
                ver_output = self.call2.run(case_id, {"claims": claims, "tenant_id": tenant_id})
                results = ver_output.get("verification_results", [])
                return {
                    "status": "VERIFICATION_COMPLETED",
                    "verification_results": results,
                }
            except Exception as e:
                logger.error(f"Agent 7 verification node encountered exception: {e}", exc_info=True)
                return {
                    "status": "FAILED",
                    "error": f"VERIFICATION_ERROR: {str(e)}",
                }

        # ── Node 4: Confidence Gate Evaluation ───────────────────────
        def confidence_gate_node(state: Agent7State) -> Agent7State:
            synthesis_data = state.get("synthesis", {})
            ver_results = state.get("verification_results", [])
            gate_input = {
                "confidence_score": synthesis_data.get("confidence_score", 0.0),
                "verification_results": ver_results,
                "claims": state.get("claims", []),
            }
            gate_decision = self.confidence_gate.evaluate(gate_input)
            return {
                "confidence_gate": gate_decision,
                "status": "GATE_EVALUATED",
            }

        # ── Node 5a: Routine Review Routing ──────────────────────────
        def routine_routing_node(state: Agent7State) -> Agent7State:
            return {
                "review_level": "ROUTINE_ANALYST_REVIEW",
            }

        # ── Node 5b: Mandatory Senior/Dual Review Routing ────────────
        def senior_dual_routing_node(state: Agent7State) -> Agent7State:
            return {
                "review_level": "MANDATORY_SENIOR_DUAL_REVIEW",
            }

        # ── Node 6: Report Generation ────────────────────────────────
        def report_generation_node(state: Agent7State) -> Agent7State:
            case_id = state.get("case_id", "")
            tenant_id = state.get("tenant_id", self.tenant_id)
            synthesis_data = state.get("synthesis", {})
            ver_results = state.get("verification_results", [])
            claims = state.get("claims", [])
            gate_decision = state.get("confidence_gate", {})
            review_level = state.get("review_level", "ROUTINE_ANALYST_REVIEW")
            extra_ctx = dict(state.get("context", {}))
            extra_ctx["review_level"] = review_level

            try:
                package = self.report_builder.build_report_package(
                    case_id=case_id,
                    tenant_id=tenant_id,
                    synthesis=synthesis_data,
                    verification_results=ver_results,
                    confidence_gate=gate_decision,
                    extra_context=extra_ctx,
                )
            except Exception as rep_err:
                logger.error(f"Report generation failed: {rep_err}", exc_info=True)
                err_msg = f"REPORT_GENERATION_ERROR: {str(rep_err)}"
                final_output = {
                    "case_id": case_id,
                    "tenant_id": tenant_id,
                    "status": "FAILED",
                    "error": err_msg,
                    "review_level": review_level,
                    "synthesis": synthesis_data,
                    "verification_results": ver_results,
                    "all_claims_verified": False,
                    "unverified_claim_count": len(ver_results),
                    "confidence_gate": gate_decision,
                    "reports": {},
                    "report_metadata": {"status": "FAILED", "error": err_msg},
                }
                return {
                    "status": "FAILED",
                    "error": err_msg,
                    "final_output": final_output,
                }

            all_verified = bool(ver_results) and all(r.get("verified", False) for r in ver_results)
            unverified_count = sum(1 for r in ver_results if not r.get("verified", False))

            # Distinguish COMPLETED from NEEDS_REVIEW and FAILED
            synthesis_error = synthesis_data.get("synthesis_error") or state.get("error")
            if synthesis_data.get("synthesis_status") == "FAILED" or synthesis_error:
                terminal_status = "FAILED"
            elif not claims or not ver_results or not all_verified or review_level == "MANDATORY_SENIOR_DUAL_REVIEW":
                terminal_status = "NEEDS_REVIEW"
            else:
                terminal_status = "COMPLETED"

            final_output = {
                "case_id": case_id,
                "tenant_id": tenant_id,
                "status": terminal_status,
                "execution_status": "FAILED" if terminal_status == "FAILED" else "SUCCESS",
                "error": synthesis_error if terminal_status == "FAILED" else None,
                "review_level": review_level,
                "synthesis": synthesis_data,
                "verification_results": ver_results,
                "all_claims_verified": all_verified,
                "unverified_claim_count": unverified_count,
                "confidence_gate": gate_decision,
                "reports": package.get("rendered", {}),
                "report_metadata": package.get("metadata", {}),
            }

            return {
                "reports": package,
                "final_output": final_output,
                "status": terminal_status,
            }

        # ── Node 7: Failure Terminal Node ────────────────────────────
        def failure_terminal_node(state: Agent7State) -> Agent7State:
            err = state.get("error") or "Unknown execution error"
            case_id = state.get("case_id") or "INVALID"
            tenant_id = state.get("tenant_id") or self.tenant_id
            claims = state.get("claims", [])
            final_output = {
                "case_id": case_id,
                "tenant_id": tenant_id,
                "status": "FAILED",
                "error": err,
                "all_claims_verified": False,
                "unverified_claim_count": len(claims),
                "confidence_gate": {
                    "route": "senior_dual",
                    "requires_senior_review": True,
                    "reasons": [err],
                    "attention_items": ["Execution failed: manual investigation required"],
                },
                "reports": {},
                "report_metadata": {"status": "FAILED", "error": err},
            }
            return {
                "final_output": final_output,
                "status": "FAILED",
            }

        # Add Nodes
        builder.add_node("input_validation", input_validation_node)
        builder.add_node("synthesis", synthesis_node)
        builder.add_node("verification", verification_node)
        builder.add_node("confidence_gate", confidence_gate_node)
        builder.add_node("routine_routing", routine_routing_node)
        builder.add_node("senior_dual_routing", senior_dual_routing_node)
        builder.add_node("report_generation", report_generation_node)
        builder.add_node("failure_terminal", failure_terminal_node)

        # Conditional Edge 1: Input Validation -> (synthesis | failure_terminal)
        def check_input_valid(state: Agent7State) -> str:
            return "synthesis" if state.get("validation_passed") else "failure_terminal"

        # Conditional Edge 2: Synthesis -> (verification | failure_terminal)
        def check_synthesis_status(state: Agent7State) -> str:
            return "failure_terminal" if state.get("status") == "FAILED" else "verification"

        # Conditional Edge 3: Verification -> (confidence_gate | failure_terminal)
        def check_verification_status(state: Agent7State) -> str:
            return "failure_terminal" if state.get("status") == "FAILED" else "confidence_gate"

        # Conditional Edge 4: Confidence Gate -> (routine_routing | senior_dual_routing)
        def route_confidence_gate(state: Agent7State) -> str:
            decision = state.get("confidence_gate", {})
            if decision.get("route") == "senior_dual":
                return "senior_dual_routing"
            return "routine_routing"

        # Wire Workflow Edges
        builder.add_edge(START, "input_validation")
        builder.add_conditional_edges("input_validation", check_input_valid, {
            "synthesis": "synthesis",
            "failure_terminal": "failure_terminal",
        })
        builder.add_conditional_edges("synthesis", check_synthesis_status, {
            "verification": "verification",
            "failure_terminal": "failure_terminal",
        })
        builder.add_conditional_edges("verification", check_verification_status, {
            "confidence_gate": "confidence_gate",
            "failure_terminal": "failure_terminal",
        })
        builder.add_conditional_edges("confidence_gate", route_confidence_gate, {
            "routine_routing": "routine_routing",
            "senior_dual_routing": "senior_dual_routing",
        })
        builder.add_edge("routine_routing", "report_generation")
        builder.add_edge("senior_dual_routing", "report_generation")
        builder.add_edge("report_generation", END)
        builder.add_edge("failure_terminal", END)

        return builder.compile()

    def run(self, case_id: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Executes the full Agent 7 lifecycle using the compiled LangGraph workflow.
        """
        ctx = context or {}
        tenant_id = ctx.get("tenant_id") or self.tenant_id

        initial_state: Agent7State = {
            "case_id": case_id,
            "tenant_id": tenant_id,
            "context": ctx,
        }

        # Invoke LangGraph workflow
        final_state = self.workflow.invoke(initial_state)

        result = final_state.get("final_output") or {}
        # Sync with interactive assistant
        self.interactive_assistant.set_investigation_output(result)

        return result

    def ask(self, question: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Answers analyst queries over the current case investigation on demand.
        """
        return self.interactive_assistant.ask(question, context or self.interactive_assistant.output)
