"""Persistent room state and controller-owned pursuit records."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import secrets
import stat
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Iterable


PURSUIT_PROTOCOL_VERSION = 3
PURSUIT_HISTORY_LIMIT = 10


class VerificationKind(str, Enum):
    COMMAND = "command"
    STATE = "state"
    HUMAN = "human"


class CriterionStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    UNKNOWN = "unknown"
    UNVERIFIABLE = "unverifiable"
    HUMAN_PENDING = "human_pending"
    STALE = "stale"


class PursuitOutcome(str, Enum):
    VERIFIED_COMPLETE = "verified_complete"
    PROVISIONAL = "provisional"
    AWAITING_SIGNOFF = "awaiting_signoff"
    NEEDS_INPUT = "needs_input"
    BUDGET_CHECKPOINT = "budget_checkpoint"
    DEADLINE_REACHED = "deadline_reached"
    STOPPED = "stopped"


@dataclass
class PursuitBudget:
    max_cycles: int = 4
    max_tool_calls: int = 40
    max_input_tokens: int = 250_000
    max_elapsed_seconds: int = 3_600

    @classmethod
    def for_duration(cls, seconds: int) -> "PursuitBudget":
        try:
            duration = int(seconds)
        except (TypeError, ValueError) as error:
            raise ValueError("pursuit duration must be a positive integer") from error
        if duration <= 0:
            raise ValueError("pursuit duration must be positive")
        if duration > 8 * 60 * 60:
            raise ValueError("pursuit duration cannot exceed 8 hours")

        def scaled(hourly_rate: int) -> int:
            return (hourly_rate * duration + 60 * 60 - 1) // (60 * 60)

        return cls(
            max_cycles=scaled(4),
            max_tool_calls=scaled(40),
            max_input_tokens=scaled(250_000),
            max_elapsed_seconds=duration,
        )

    @classmethod
    def for_extent(cls, extent: int) -> "PursuitBudget":
        return {
            1: cls(4, 40, 250_000, 60 * 60),
            2: cls(12, 120, 750_000, 180 * 60),
            3: cls(32, 320, 2_000_000, 480 * 60),
        }.get(_pursuit_extent(extent), cls())

    @classmethod
    def from_dict(cls, value: Any, *, extent: int = 1) -> "PursuitBudget":
        if not isinstance(value, dict):
            return cls.for_extent(extent)
        defaults = cls.for_extent(extent)
        elapsed = min(
            8 * 60 * 60,
            _positive_int(
                value.get("max_elapsed_seconds"), defaults.max_elapsed_seconds
            ),
        )
        return cls(
            max_cycles=_positive_int(value.get("max_cycles"), defaults.max_cycles),
            max_tool_calls=_positive_int(
                value.get("max_tool_calls"), defaults.max_tool_calls
            ),
            max_input_tokens=_positive_int(
                value.get("max_input_tokens"), defaults.max_input_tokens
            ),
            max_elapsed_seconds=elapsed,
        )


@dataclass
class BudgetUsage:
    cycles: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    elapsed_seconds: int = 0

    def add(self, other: "BudgetUsage") -> None:
        self.cycles += max(0, other.cycles)
        self.tool_calls += max(0, other.tool_calls)
        self.input_tokens += max(0, other.input_tokens)
        self.elapsed_seconds += max(0, other.elapsed_seconds)

    def copy(self) -> "BudgetUsage":
        return BudgetUsage(**asdict(self))

    @classmethod
    def from_dict(cls, value: Any) -> "BudgetUsage":
        if not isinstance(value, dict):
            return cls()
        return cls(
            cycles=_nonnegative_int(value.get("cycles")),
            tool_calls=_nonnegative_int(value.get("tool_calls")),
            input_tokens=_nonnegative_int(value.get("input_tokens")),
            elapsed_seconds=_nonnegative_int(value.get("elapsed_seconds")),
        )


@dataclass
class BudgetLedger:
    limits: PursuitBudget = field(default_factory=PursuitBudget)
    usage: BudgetUsage = field(default_factory=BudgetUsage)
    total_usage: BudgetUsage = field(default_factory=BudgetUsage)
    tranche: int = 1
    started_ms: int | None = None

    def record_cycle(self, count: int = 1) -> None:
        self._record("cycles", count)

    def record_tool_call(self, count: int = 1) -> None:
        self._record("tool_calls", count)

    def record_input_tokens(self, count: int) -> None:
        self._record("input_tokens", count)

    def _record(self, field_name: str, count: int) -> None:
        amount = max(0, int(count))
        setattr(self.usage, field_name, getattr(self.usage, field_name) + amount)
        setattr(
            self.total_usage,
            field_name,
            getattr(self.total_usage, field_name) + amount,
        )

    def effective_usage(self, *, now_ms: int | None = None) -> BudgetUsage:
        result = self.usage.copy()
        if self.started_ms is not None:
            now = _now_ms() if now_ms is None else int(now_ms)
            result.elapsed_seconds += max(0, (now - self.started_ms) // 1_000)
        return result

    def exhausted_limits(self, *, now_ms: int | None = None) -> list[str]:
        usage = self.effective_usage(now_ms=now_ms)
        exhausted: list[str] = []
        if usage.cycles >= self.limits.max_cycles:
            exhausted.append("cycles")
        if usage.tool_calls >= self.limits.max_tool_calls:
            exhausted.append("tool_calls")
        if usage.input_tokens >= self.limits.max_input_tokens:
            exhausted.append("input_tokens")
        if usage.elapsed_seconds >= self.limits.max_elapsed_seconds:
            exhausted.append("elapsed_seconds")
        return exhausted

    def pause(self, *, now_ms: int | None = None) -> None:
        if self.started_ms is None:
            return
        now = _now_ms() if now_ms is None else int(now_ms)
        elapsed = max(0, (now - self.started_ms) // 1_000)
        self.usage.elapsed_seconds += elapsed
        self.total_usage.elapsed_seconds += elapsed
        self.started_ms = None

    def start(self, *, now_ms: int | None = None) -> None:
        if self.started_ms is None:
            self.started_ms = _now_ms() if now_ms is None else int(now_ms)

    def start_next_tranche(self, *, now_ms: int | None = None) -> None:
        now = _now_ms() if now_ms is None else int(now_ms)
        self.pause(now_ms=now)
        self.tranche += 1
        self.usage = BudgetUsage()
        self.started_ms = now

    @classmethod
    def from_dict(cls, value: Any, *, extent: int = 1) -> "BudgetLedger":
        if not isinstance(value, dict):
            return cls(limits=PursuitBudget.for_extent(extent))
        return cls(
            limits=PursuitBudget.from_dict(value.get("limits"), extent=extent),
            usage=BudgetUsage.from_dict(value.get("usage")),
            total_usage=BudgetUsage.from_dict(value.get("total_usage")),
            tranche=max(1, _nonnegative_int(value.get("tranche")) or 1),
            started_ms=_optional_int(value.get("started_ms")),
        )


@dataclass
class PursuitCriterion:
    id: str
    text: str
    verification_kind: VerificationKind = VerificationKind.HUMAN
    verification_spec: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.id = str(self.id).strip()
        self.text = str(self.text).strip()
        self.verification_kind = _enum(
            VerificationKind, self.verification_kind, VerificationKind.HUMAN
        )
        if not isinstance(self.verification_spec, dict):
            self.verification_spec = {}

    @classmethod
    def from_dict(cls, value: Any) -> "PursuitCriterion | None":
        if not isinstance(value, dict):
            return None
        criterion_id = str(value.get("id") or "").strip()
        text = str(value.get("text") or "").strip()
        if not criterion_id or not text:
            return None
        verification = value.get("verification")
        if isinstance(verification, dict):
            kind = verification.get("kind", value.get("verification_kind"))
            spec = {key: item for key, item in verification.items() if key != "kind"}
        else:
            kind = value.get("verification_kind")
            spec = value.get("verification_spec")
        return cls(
            criterion_id,
            text,
            _enum(VerificationKind, kind, VerificationKind.HUMAN),
            dict(spec) if isinstance(spec, dict) else {},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "text": self.text,
            "verification_kind": self.verification_kind.value,
            "verification_spec": self.verification_spec,
        }


@dataclass
class PursuitContract:
    version: int
    goal: str
    constraints: list[str]
    assumptions: list[str]
    criteria: list[PursuitCriterion]
    extent: int
    budget: PursuitBudget
    approved: bool = False
    approval_event_id: str | None = None
    approved_at_ms: int | None = None
    approval_digest: str | None = None

    @classmethod
    def draft(
        cls,
        goal: str,
        criteria: Iterable[PursuitCriterion | dict[str, Any]] = (),
        *,
        constraints: Iterable[str] = (),
        assumptions: Iterable[str] = (),
        extent: int = 1,
        version: int = 1,
        budget: PursuitBudget | None = None,
    ) -> "PursuitContract":
        parsed: list[PursuitCriterion] = []
        for item in criteria:
            criterion = (
                item if isinstance(item, PursuitCriterion) else PursuitCriterion.from_dict(item)
            )
            if criterion is not None:
                parsed.append(criterion)
        chosen_extent = _pursuit_extent(extent)
        return cls(
            version=max(1, int(version)),
            goal=str(goal).strip(),
            constraints=_string_list(list(constraints)),
            assumptions=_string_list(list(assumptions)),
            criteria=parsed,
            extent=chosen_extent,
            budget=budget or PursuitBudget.for_extent(chosen_extent),
        )

    def content_digest(self) -> str:
        payload = {
            "version": self.version,
            "goal": self.goal,
            "constraints": self.constraints,
            "assumptions": self.assumptions,
            "criteria": [item.to_dict() for item in self.criteria],
            "extent": self.extent,
            "budget": asdict(self.budget),
        }
        return _digest(payload)

    def approve(
        self,
        approval_event_id: str | None = None,
        approved_at_ms: int | None = None,
        *,
        event_id: str | None = None,
    ) -> "PursuitContract":
        self.approved = True
        self.approval_event_id = str(approval_event_id or event_id or "") or None
        self.approved_at_ms = _now_ms() if approved_at_ms is None else int(approved_at_ms)
        self.approval_digest = self.content_digest()
        return self

    def approval_is_current(self) -> bool:
        return bool(
            self.approved
            and self.approval_event_id
            and self.approved_at_ms is not None
            and self.approval_digest == self.content_digest()
        )

    def revise(self, **changes: Any) -> "PursuitContract":
        data = {
            "goal": changes.get("goal", self.goal),
            "criteria": changes.get("criteria", self.criteria),
            "constraints": changes.get("constraints", self.constraints),
            "assumptions": changes.get("assumptions", self.assumptions),
            "extent": changes.get("extent", self.extent),
            "budget": changes.get("budget", self.budget),
            "version": self.version + 1,
        }
        return PursuitContract.draft(**data)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "goal": self.goal,
            "constraints": self.constraints,
            "assumptions": self.assumptions,
            "criteria": [item.to_dict() for item in self.criteria],
            "extent": self.extent,
            "budget": asdict(self.budget),
            "approved": self.approved,
            "approval_event_id": self.approval_event_id,
            "approved_at_ms": self.approved_at_ms,
            "approval_digest": self.approval_digest,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "PursuitContract | None":
        if not isinstance(value, dict) or not str(value.get("goal") or "").strip():
            return None
        extent = _pursuit_extent(value.get("extent"))
        contract = cls.draft(
            str(value["goal"]),
            value.get("criteria") if isinstance(value.get("criteria"), list) else [],
            constraints=_string_list(value.get("constraints")),
            assumptions=_string_list(value.get("assumptions")),
            extent=extent,
            version=max(1, _nonnegative_int(value.get("version")) or 1),
            budget=PursuitBudget.from_dict(value.get("budget"), extent=extent),
        )
        contract.approved = bool(value.get("approved", False))
        contract.approval_event_id = _optional_string(value.get("approval_event_id"))
        contract.approved_at_ms = _optional_int(value.get("approved_at_ms"))
        contract.approval_digest = _optional_string(value.get("approval_digest"))
        return contract


@dataclass
class ObservationProvenance:
    observation_id: str
    attempt_id: str
    workspace_revision: int
    captured_at_ms: int
    source_ref: str
    digest: str

    @classmethod
    def from_dict(cls, value: Any) -> "ObservationProvenance | None":
        if not isinstance(value, dict):
            return None
        required = ("observation_id", "attempt_id", "source_ref", "digest")
        if any(not str(value.get(key) or "").strip() for key in required):
            return None
        return cls(
            observation_id=str(value["observation_id"]),
            attempt_id=str(value["attempt_id"]),
            workspace_revision=_nonnegative_int(value.get("workspace_revision")),
            captured_at_ms=_nonnegative_int(value.get("captured_at_ms")),
            source_ref=str(value["source_ref"]),
            digest=str(value["digest"]),
        )


@dataclass
class CheckResult:
    id: str
    criterion_id: str
    verification_kind: VerificationKind
    status: CriterionStatus
    provenance: ObservationProvenance
    contract_version: int = 1
    summary: str = ""
    raw_output: str = ""
    source: str = ""

    def __post_init__(self) -> None:
        self.verification_kind = _enum(
            VerificationKind, self.verification_kind, VerificationKind.HUMAN
        )
        self.status = _enum(CriterionStatus, self.status, CriterionStatus.UNKNOWN)
        self.contract_version = max(1, int(self.contract_version))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "criterion_id": self.criterion_id,
            "verification_kind": self.verification_kind.value,
            "status": self.status.value,
            "provenance": asdict(self.provenance),
            "contract_version": self.contract_version,
            "summary": self.summary,
            "raw_output": self.raw_output,
            "source": self.source,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "CheckResult | None":
        if not isinstance(value, dict):
            return None
        provenance = ObservationProvenance.from_dict(value.get("provenance"))
        if provenance is None:
            return None
        if not str(value.get("id") or "") or not str(value.get("criterion_id") or ""):
            return None
        return cls(
            id=str(value["id"]),
            criterion_id=str(value["criterion_id"]),
            verification_kind=_enum(
                VerificationKind,
                value.get("verification_kind"),
                VerificationKind.HUMAN,
            ),
            status=_enum(CriterionStatus, value.get("status"), CriterionStatus.UNKNOWN),
            provenance=provenance,
            contract_version=max(1, _nonnegative_int(value.get("contract_version")) or 1),
            summary=str(value.get("summary") or ""),
            raw_output=str(value.get("raw_output") or ""),
            source=str(value.get("source") or ""),
        )


@dataclass
class AttemptRecord:
    attempt_id: str
    cycle: int
    workspace_revision_before: int
    workspace_revision_after: int
    started_at_ms: int
    completed_at_ms: int | None = None
    tool_calls: int = 0
    input_tokens: int = 0
    action_trace_refs: list[str] = field(default_factory=list)
    outcome: str = ""

    @classmethod
    def from_dict(cls, value: Any) -> "AttemptRecord | None":
        if not isinstance(value, dict) or not str(value.get("attempt_id") or ""):
            return None
        return cls(
            attempt_id=str(value["attempt_id"]),
            cycle=max(1, _nonnegative_int(value.get("cycle")) or 1),
            workspace_revision_before=_nonnegative_int(
                value.get("workspace_revision_before")
            ),
            workspace_revision_after=_nonnegative_int(
                value.get("workspace_revision_after")
            ),
            started_at_ms=_nonnegative_int(value.get("started_at_ms")),
            completed_at_ms=_optional_int(value.get("completed_at_ms")),
            tool_calls=_nonnegative_int(value.get("tool_calls")),
            input_tokens=_nonnegative_int(value.get("input_tokens")),
            action_trace_refs=_string_list(value.get("action_trace_refs")),
            outcome=str(value.get("outcome") or ""),
        )


@dataclass
class PursuitArchive:
    contract: PursuitContract | None
    check_results: list[CheckResult]
    attempts: list[AttemptRecord]
    outcome: PursuitOutcome
    final_report: str
    budget: BudgetLedger
    legacy_untrusted_evidence: list[dict[str, str]] = field(default_factory=list)
    artifact_refs: list[str] = field(default_factory=list)
    unattended_authorized: bool = False
    authorization_event_id: str | None = None
    authorization_digest: str | None = None
    deadline_ms: int | None = None
    automatic_renewals: int = 0
    archived_at_ms: int = field(default_factory=lambda: _now_ms())

    def to_dict(self) -> dict[str, Any]:
        return {
            "contract": self.contract.to_dict() if self.contract else None,
            "check_results": [item.to_dict() for item in self.check_results],
            "attempts": [asdict(item) for item in self.attempts],
            "outcome": self.outcome.value,
            "final_report": self.final_report,
            "budget": asdict(self.budget),
            "legacy_untrusted_evidence": self.legacy_untrusted_evidence,
            "artifact_refs": self.artifact_refs,
            "unattended_authorized": self.unattended_authorized,
            "authorization_event_id": self.authorization_event_id,
            "authorization_digest": self.authorization_digest,
            "deadline_ms": self.deadline_ms,
            "automatic_renewals": self.automatic_renewals,
            "archived_at_ms": self.archived_at_ms,
        }

    @classmethod
    def from_dict(cls, value: Any) -> "PursuitArchive | None":
        if not isinstance(value, dict):
            return None
        checks = [
            parsed
            for item in value.get("check_results", [])
            if (parsed := CheckResult.from_dict(item)) is not None
        ] if isinstance(value.get("check_results"), list) else []
        attempts = [
            parsed
            for item in value.get("attempts", [])
            if (parsed := AttemptRecord.from_dict(item)) is not None
        ] if isinstance(value.get("attempts"), list) else []
        contract = PursuitContract.from_dict(value.get("contract"))
        extent = contract.extent if contract else 1
        return cls(
            contract=contract,
            check_results=checks,
            attempts=attempts,
            outcome=_enum(PursuitOutcome, value.get("outcome"), PursuitOutcome.STOPPED),
            final_report=str(value.get("final_report") or ""),
            budget=BudgetLedger.from_dict(value.get("budget"), extent=extent),
            legacy_untrusted_evidence=_evidence(
                value.get("legacy_untrusted_evidence")
            ),
            artifact_refs=_string_list(value.get("artifact_refs")),
            unattended_authorized=bool(value.get("unattended_authorized", False)),
            authorization_event_id=_optional_string(
                value.get("authorization_event_id")
            ),
            authorization_digest=_optional_string(value.get("authorization_digest")),
            deadline_ms=_optional_int(value.get("deadline_ms")),
            automatic_renewals=_nonnegative_int(value.get("automatic_renewals")),
            archived_at_ms=_nonnegative_int(value.get("archived_at_ms")) or _now_ms(),
        )


@dataclass
class PendingPermission:
    id: str
    title: str
    type: str
    pattern: str = ""
    created: int = 0
    session_id: str = ""
    retry_eligible: bool = True


@dataclass
class RoomSession:
    session_id: str
    directory: str
    title: str = "OpenCode session"
    in_flight_event_id: str | None = None
    prompt_started_ms: int | None = None
    pending_permissions: list[PendingPermission] = field(default_factory=list)
    yolo_permissions: bool = False
    yolo_session_id: str | None = None
    yolo_contract_digest: str | None = None
    pending_pursuit_goal: str | None = None
    pending_pursuit_reuse_session: bool = False
    pending_pursuit_yolo_confirmation: bool = False
    pending_pursuit_unattended: bool = False
    pursuit_goal: str | None = None
    pursuit_extent: int = 1
    pursuit_phase: str | None = None
    pursuit_iteration: int = 0
    pursuit_protocol_version: int = PURSUIT_PROTOCOL_VERSION
    pursuit_worker_input_tokens: int = 0
    verifier_session_id: str | None = None
    acceptance_criteria: list[dict[str, str]] = field(default_factory=list)
    pursuit_criteria_status: dict[str, str] = field(default_factory=dict)
    pursuit_assumptions: list[str] = field(default_factory=list)
    pursuit_evidence: list[dict[str, str]] = field(default_factory=list)
    pursuit_pending_question: str | None = None
    pursuit_protocol_failures: int = 0
    pursuit_retry_attempts: int = 0
    pursuit_last_worker_report: str | None = None
    pursuit_unattended: bool = False
    pursuit_authorization_event_id: str | None = None
    pursuit_authorization_digest: str | None = None
    pursuit_deadline_ms: int | None = None
    pursuit_auto_renewals: int = 0
    pursuit_termination_reason: str | None = None
    pursuit_termination_session_id: str | None = None

    # Protocol-v3 records. Models never write these fields directly.
    pursuit_contract: PursuitContract | None = None
    pursuit_check_results: list[CheckResult] = field(default_factory=list)
    pursuit_attempts: list[AttemptRecord] = field(default_factory=list)
    pursuit_budget_ledger: BudgetLedger | None = None
    pursuit_workspace_revision: int = 0
    pursuit_workspace_fingerprint: str | None = None
    pursuit_pending_observation_ids: list[str] = field(default_factory=list)
    pursuit_action_trace: list[dict[str, Any]] = field(default_factory=list)
    pursuit_outcome: PursuitOutcome | None = None
    pursuit_final_report: str | None = None
    pursuit_remaining_uncertainty: list[str] = field(default_factory=list)
    pursuit_artifact_refs: list[str] = field(default_factory=list)
    pursuit_history: list[PursuitArchive] = field(default_factory=list)

    bump_confirmation_session_id: str | None = None
    bump_confirmation_activity_ms: int | None = None
    manual_bump_pending: bool = False
    manual_bump_attempts: int = 0
    active_tools: dict[str, dict[str, Any]] = field(default_factory=dict)
    recovery_reason: str | None = None
    recovery_tool: str | None = None
    recovery_session_id: str | None = None
    watchdog_recovery_pending: bool = False
    watchdog_recovery_attempts: int = 0

    # Transient event aggregation fields are deliberately not persisted.
    text_parts: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    reasoning_parts: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    message_roles: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    part_message_ids: dict[str, str] = field(default_factory=dict, repr=False, compare=False)
    activity: str | None = field(default=None, repr=False, compare=False)
    activity_history: list[str] = field(default_factory=list, repr=False, compare=False)
    plan_items: list[tuple[str, str]] = field(default_factory=list, repr=False, compare=False)
    stop_requested: bool = field(default=False, repr=False, compare=False)
    last_activity_ms: int | None = field(default=None, repr=False, compare=False)

    def issue_observation_id(self) -> str:
        """Issue a controller nonce required by :meth:`record_check_result`."""
        observation_id = f"obs_{secrets.token_urlsafe(24)}"
        self.pursuit_pending_observation_ids.append(observation_id)
        self.pursuit_pending_observation_ids = self.pursuit_pending_observation_ids[-64:]
        return observation_id

    def record_check_result(self, result: CheckResult) -> bool:
        """Validate and record fresh controller evidence.

        Unissued/model-authored observation IDs, stale versions/revisions, malformed
        digests, and duplicates are rejected. A duplicate returns ``False`` so it
        cannot be counted as progress; malformed or forged evidence raises.
        """
        if not isinstance(result, CheckResult):
            raise TypeError("check result must be controller-owned CheckResult")
        observation_id = result.provenance.observation_id
        if observation_id not in self.pursuit_pending_observation_ids:
            raise ValueError("observation ID was not issued by the controller")
        self.pursuit_pending_observation_ids.remove(observation_id)
        if not _is_sha256(result.provenance.digest):
            raise ValueError("observation digest must be a SHA-256 hex digest")
        contract = self.pursuit_contract
        if contract is None:
            raise ValueError("cannot record a check without an active contract")
        criteria = {item.id: item for item in contract.criteria}
        criterion = criteria.get(result.criterion_id)
        if criterion is None:
            raise ValueError("check result references an unknown criterion")
        if result.contract_version != contract.version:
            raise ValueError("check result references a stale contract version")
        if result.verification_kind != criterion.verification_kind:
            raise ValueError("check result verification kind does not match contract")
        if result.provenance.workspace_revision != self.pursuit_workspace_revision:
            raise ValueError("check result references a stale workspace revision")
        if any(
            old.id == result.id
            or old.provenance.observation_id == observation_id
            or (
                old.criterion_id == result.criterion_id
                and old.contract_version == result.contract_version
                and old.provenance.workspace_revision
                == result.provenance.workspace_revision
                and old.provenance.digest == result.provenance.digest
            )
            for old in self.pursuit_check_results
        ):
            return False
        self.pursuit_check_results.append(result)
        return True

    def mark_workspace_mutated(
        self,
        action_trace_ref: str | None = None,
        *,
        workspace_fingerprint: str | None = None,
    ) -> int:
        self.pursuit_workspace_revision += 1
        if workspace_fingerprint is not None:
            self.pursuit_workspace_fingerprint = str(workspace_fingerprint)
        if action_trace_ref:
            self.pursuit_action_trace.append(
                {
                    "ref": str(action_trace_ref),
                    "workspace_revision": self.pursuit_workspace_revision,
                    "recorded_at_ms": _now_ms(),
                }
            )
        return self.pursuit_workspace_revision

    def current_check_results(self) -> dict[str, CheckResult]:
        """Return the latest fresh result for each criterion."""
        contract = self.pursuit_contract
        if contract is None:
            return {}
        current: dict[str, CheckResult] = {}
        for result in self.pursuit_check_results:
            if (
                result.contract_version == contract.version
                and result.provenance.workspace_revision
                == self.pursuit_workspace_revision
            ):
                current[result.criterion_id] = result
        return current

    def archive_pursuit(
        self,
        outcome: PursuitOutcome | str,
        final_report: str,
        *,
        artifact_refs: Iterable[str] | None = None,
        archived_at_ms: int | None = None,
    ) -> PursuitArchive:
        parsed_outcome = _enum(PursuitOutcome, outcome, PursuitOutcome.STOPPED)
        ledger = self.pursuit_budget_ledger or BudgetLedger(
            limits=(
                self.pursuit_contract.budget
                if self.pursuit_contract
                else PursuitBudget.for_extent(self.pursuit_extent)
            )
        )
        archive = PursuitArchive(
            contract=self.pursuit_contract,
            check_results=list(self.pursuit_check_results),
            attempts=list(self.pursuit_attempts),
            outcome=parsed_outcome,
            final_report=str(final_report),
            budget=ledger,
            legacy_untrusted_evidence=[
                dict(item)
                for item in self.pursuit_evidence
                if item.get("trust") == "legacy_untrusted"
            ],
            artifact_refs=list(artifact_refs or self.pursuit_artifact_refs),
            unattended_authorized=bool(
                self.pursuit_authorization_event_id
                and self.pursuit_authorization_digest
                and self.pursuit_deadline_ms is not None
            ),
            authorization_event_id=self.pursuit_authorization_event_id,
            authorization_digest=self.pursuit_authorization_digest,
            deadline_ms=self.pursuit_deadline_ms,
            automatic_renewals=self.pursuit_auto_renewals,
            archived_at_ms=_now_ms() if archived_at_ms is None else int(archived_at_ms),
        )
        self.pursuit_history.append(archive)
        self.pursuit_history = self.pursuit_history[-PURSUIT_HISTORY_LIMIT:]
        self.pursuit_outcome = parsed_outcome
        self.pursuit_final_report = str(final_report)
        return archive

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "directory": self.directory,
            "title": self.title,
            "in_flight_event_id": self.in_flight_event_id,
            "prompt_started_ms": self.prompt_started_ms,
            "pending_permissions": [asdict(value) for value in self.pending_permissions],
            "yolo_permissions": self.yolo_permissions,
            "yolo_session_id": self.yolo_session_id,
            "yolo_contract_digest": self.yolo_contract_digest,
            "pending_pursuit_goal": self.pending_pursuit_goal,
            "pending_pursuit_reuse_session": self.pending_pursuit_reuse_session,
            "pending_pursuit_yolo_confirmation": self.pending_pursuit_yolo_confirmation,
            "pending_pursuit_unattended": self.pending_pursuit_unattended,
            "pursuit_goal": self.pursuit_goal,
            "pursuit_extent": self.pursuit_extent,
            "pursuit_phase": self.pursuit_phase,
            "pursuit_iteration": self.pursuit_iteration,
            "pursuit_protocol_version": self.pursuit_protocol_version,
            "pursuit_worker_input_tokens": self.pursuit_worker_input_tokens,
            "verifier_session_id": self.verifier_session_id,
            "acceptance_criteria": self.acceptance_criteria,
            "pursuit_criteria_status": self.pursuit_criteria_status,
            "pursuit_assumptions": self.pursuit_assumptions,
            "pursuit_evidence": self.pursuit_evidence,
            "pursuit_pending_question": self.pursuit_pending_question,
            "pursuit_protocol_failures": self.pursuit_protocol_failures,
            "pursuit_retry_attempts": self.pursuit_retry_attempts,
            "pursuit_last_worker_report": self.pursuit_last_worker_report,
            "pursuit_unattended": self.pursuit_unattended,
            "pursuit_authorization_event_id": self.pursuit_authorization_event_id,
            "pursuit_authorization_digest": self.pursuit_authorization_digest,
            "pursuit_deadline_ms": self.pursuit_deadline_ms,
            "pursuit_auto_renewals": self.pursuit_auto_renewals,
            "pursuit_termination_reason": self.pursuit_termination_reason,
            "pursuit_termination_session_id": self.pursuit_termination_session_id,
            "pursuit_contract": self.pursuit_contract.to_dict() if self.pursuit_contract else None,
            "pursuit_check_results": [item.to_dict() for item in self.pursuit_check_results],
            "pursuit_attempts": [asdict(item) for item in self.pursuit_attempts],
            "pursuit_budget_ledger": asdict(self.pursuit_budget_ledger) if self.pursuit_budget_ledger else None,
            "pursuit_workspace_revision": self.pursuit_workspace_revision,
            "pursuit_workspace_fingerprint": self.pursuit_workspace_fingerprint,
            "pursuit_pending_observation_ids": self.pursuit_pending_observation_ids,
            "pursuit_action_trace": self.pursuit_action_trace,
            "pursuit_outcome": self.pursuit_outcome.value if self.pursuit_outcome else None,
            "pursuit_final_report": self.pursuit_final_report,
            "pursuit_remaining_uncertainty": self.pursuit_remaining_uncertainty,
            "pursuit_artifact_refs": self.pursuit_artifact_refs,
            "pursuit_history": [item.to_dict() for item in self.pursuit_history],
            "bump_confirmation_session_id": self.bump_confirmation_session_id,
            "bump_confirmation_activity_ms": self.bump_confirmation_activity_ms,
            "manual_bump_pending": self.manual_bump_pending,
            "manual_bump_attempts": self.manual_bump_attempts,
            "active_tools": self.active_tools,
            "recovery_reason": self.recovery_reason,
            "recovery_tool": self.recovery_tool,
            "recovery_session_id": self.recovery_session_id,
            "watchdog_recovery_pending": self.watchdog_recovery_pending,
            "watchdog_recovery_attempts": self.watchdog_recovery_attempts,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RoomSession":
        permissions = [
            PendingPermission(**item)
            for item in value.get("pending_permissions", [])
            if isinstance(item, dict) and item.get("id")
        ]
        legacy_goal = value.get("obsess_goal")
        pursuit_goal = value.get("pursuit_goal") or legacy_goal
        extent = _pursuit_extent(value.get("pursuit_extent"))
        stored_protocol = int(
            value.get("pursuit_protocol_version")
            or (1 if pursuit_goal else PURSUIT_PROTOCOL_VERSION)
        )
        legacy_worker_must_stop = bool(
            pursuit_goal
            and stored_protocol < PURSUIT_PROTOCOL_VERSION
            and value.get("in_flight_event_id")
        )
        legacy_criteria = _criteria(value.get("acceptance_criteria"))
        contract = PursuitContract.from_dict(value.get("pursuit_contract"))
        phase = _optional_string(value.get("pursuit_phase"))
        evidence = _evidence(value.get("pursuit_evidence"))
        statuses = _criterion_status_mapping(value.get("pursuit_criteria_status"))

        if pursuit_goal and stored_protocol < PURSUIT_PROTOCOL_VERSION:
            # Protocol-v1/v2 prose is not controller evidence. Preserve it only as
            # an explicitly untrusted audit record and require a fresh approval.
            contract = PursuitContract.draft(
                str(pursuit_goal),
                [
                    PursuitCriterion(item["id"], item["text"], VerificationKind.HUMAN)
                    for item in legacy_criteria
                ],
                assumptions=_string_list(value.get("pursuit_assumptions")),
                extent=extent,
            )
            phase = "awaiting_approval"
            evidence = [{**item, "trust": "legacy_untrusted"} for item in evidence]
            statuses = {item.id: CriterionStatus.UNKNOWN.value for item in contract.criteria}
            stored_protocol = PURSUIT_PROTOCOL_VERSION
        elif pursuit_goal:
            if contract is None:
                # A protocol-v3 pursuit without a contract is not safe to resume.
                # Recover its user-visible draft inputs, but require approval.
                contract = PursuitContract.draft(
                    str(pursuit_goal),
                    [
                        PursuitCriterion(
                            item["id"], item["text"], VerificationKind.HUMAN
                        )
                        for item in legacy_criteria
                    ],
                    assumptions=_string_list(value.get("pursuit_assumptions")),
                    extent=extent,
                )
                evidence = [
                    {**item, "trust": "legacy_untrusted"} for item in evidence
                ]
                statuses = {
                    item.id: CriterionStatus.UNKNOWN.value
                    for item in contract.criteria
                }
                phase = "awaiting_approval"
            elif not contract.approval_is_current():
                phase = "awaiting_approval"
            elif not phase:
                phase = "working"

            pursuit_goal = contract.goal
            extent = contract.extent

        check_results = [
            parsed
            for item in value.get("pursuit_check_results", [])
            if (parsed := CheckResult.from_dict(item)) is not None
        ] if isinstance(value.get("pursuit_check_results"), list) else []
        attempts = [
            parsed
            for item in value.get("pursuit_attempts", [])
            if (parsed := AttemptRecord.from_dict(item)) is not None
        ] if isinstance(value.get("pursuit_attempts"), list) else []
        history = [
            parsed
            for item in value.get("pursuit_history", [])
            if (parsed := PursuitArchive.from_dict(item)) is not None
        ] if isinstance(value.get("pursuit_history"), list) else []

        ledger = (
            BudgetLedger.from_dict(
                value.get("pursuit_budget_ledger"), extent=extent
            )
            if pursuit_goal or value.get("pursuit_budget_ledger")
            else None
        )
        # The approved contract is digest-bound and therefore owns the selected
        # budget.  Legacy extent remains metadata only.  Keep all accumulated
        # accounting while repairing a missing or stale ledger limit object.
        if pursuit_goal and contract is not None:
            ledger = ledger or BudgetLedger(limits=contract.budget)
            ledger.limits = contract.budget

        return cls(
            session_id=str(value["session_id"]),
            directory=str(value["directory"]),
            title=str(value.get("title") or "OpenCode session"),
            in_flight_event_id=value.get("in_flight_event_id"),
            prompt_started_ms=_optional_int(value.get("prompt_started_ms")),
            pending_permissions=permissions,
            yolo_permissions=bool(value.get("yolo_permissions", False)),
            yolo_session_id=_optional_string(value.get("yolo_session_id")),
            yolo_contract_digest=_optional_string(
                value.get("yolo_contract_digest")
            ),
            pending_pursuit_goal=_optional_string(value.get("pending_pursuit_goal")),
            pending_pursuit_reuse_session=bool(value.get("pending_pursuit_reuse_session", False)),
            pending_pursuit_yolo_confirmation=bool(value.get("pending_pursuit_yolo_confirmation", False)),
            pending_pursuit_unattended=bool(value.get("pending_pursuit_unattended", False)),
            pursuit_goal=str(pursuit_goal) if pursuit_goal else None,
            pursuit_extent=extent,
            pursuit_phase=phase,
            pursuit_iteration=int(value.get("pursuit_iteration") or value.get("obsess_iteration") or 0),
            pursuit_protocol_version=stored_protocol,
            pursuit_worker_input_tokens=_nonnegative_int(value.get("pursuit_worker_input_tokens")),
            verifier_session_id=_optional_string(value.get("verifier_session_id")),
            acceptance_criteria=legacy_criteria,
            pursuit_criteria_status=statuses,
            pursuit_assumptions=_string_list(value.get("pursuit_assumptions")),
            pursuit_evidence=evidence,
            pursuit_pending_question=_optional_string(value.get("pursuit_pending_question")),
            pursuit_protocol_failures=_nonnegative_int(value.get("pursuit_protocol_failures")),
            pursuit_retry_attempts=_nonnegative_int(value.get("pursuit_retry_attempts")),
            pursuit_last_worker_report=_optional_string(value.get("pursuit_last_worker_report")),
            pursuit_unattended=bool(value.get("pursuit_unattended", False)),
            pursuit_authorization_event_id=_optional_string(
                value.get("pursuit_authorization_event_id")
            ),
            pursuit_authorization_digest=_optional_string(
                value.get("pursuit_authorization_digest")
            ),
            pursuit_deadline_ms=_optional_int(value.get("pursuit_deadline_ms")),
            pursuit_auto_renewals=_nonnegative_int(
                value.get("pursuit_auto_renewals")
            ),
            pursuit_termination_reason=_optional_string(
                value.get("pursuit_termination_reason")
            ) or ("legacy_migration" if legacy_worker_must_stop else None),
            pursuit_termination_session_id=_optional_string(
                value.get("pursuit_termination_session_id")
            ) or (
                str(value["session_id"])
                if legacy_worker_must_stop
                else None
            ),
            pursuit_contract=contract,
            pursuit_check_results=check_results if stored_protocol >= PURSUIT_PROTOCOL_VERSION else [],
            pursuit_attempts=attempts,
            pursuit_budget_ledger=ledger,
            pursuit_workspace_revision=_nonnegative_int(value.get("pursuit_workspace_revision")),
            pursuit_workspace_fingerprint=_optional_string(
                value.get("pursuit_workspace_fingerprint")
            ),
            pursuit_pending_observation_ids=_string_list(value.get("pursuit_pending_observation_ids")),
            pursuit_action_trace=_dict_list(value.get("pursuit_action_trace")),
            pursuit_outcome=_optional_enum(PursuitOutcome, value.get("pursuit_outcome")),
            pursuit_final_report=_optional_string(value.get("pursuit_final_report")),
            pursuit_remaining_uncertainty=_string_list(value.get("pursuit_remaining_uncertainty")),
            pursuit_artifact_refs=_string_list(value.get("pursuit_artifact_refs")),
            pursuit_history=history[-PURSUIT_HISTORY_LIMIT:],
            bump_confirmation_session_id=_optional_string(value.get("bump_confirmation_session_id")),
            bump_confirmation_activity_ms=_optional_int(value.get("bump_confirmation_activity_ms")),
            manual_bump_pending=bool(value.get("manual_bump_pending", False)),
            manual_bump_attempts=_nonnegative_int(value.get("manual_bump_attempts")),
            active_tools=_active_tools(value.get("active_tools")),
            recovery_reason=_optional_string(value.get("recovery_reason")),
            recovery_tool=_optional_string(value.get("recovery_tool")),
            recovery_session_id=_optional_string(value.get("recovery_session_id")),
            watchdog_recovery_pending=bool(value.get("watchdog_recovery_pending", False)),
            watchdog_recovery_attempts=_nonnegative_int(value.get("watchdog_recovery_attempts")),
        )


class StateStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.rooms: dict[str, RoomSession] = {}
        self._lock = asyncio.Lock()

    def load(self) -> None:
        if not self.path.exists():
            return
        payload = json.loads(self.path.read_text(encoding="utf-8"))
        rooms = payload.get("rooms", {}) if isinstance(payload, dict) else {}
        if not isinstance(rooms, dict):
            raise ValueError("Invalid room mapping state")
        self.rooms = {
            str(room_id): RoomSession.from_dict(value)
            for room_id, value in rooms.items()
            if isinstance(value, dict)
        }

    async def save(self) -> None:
        async with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.parent.chmod(stat.S_IRWXU)
            temporary = self.path.with_suffix(self.path.suffix + ".tmp")
            payload = {
                "version": 3,
                "rooms": {key: value.to_dict() for key, value in self.rooms.items()},
            }
            temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            temporary.chmod(stat.S_IRUSR | stat.S_IWUSR)
            os.replace(temporary, self.path)

    async def set(self, room_id: str, state: RoomSession) -> None:
        self.rooms[room_id] = state
        await self.save()

    async def remove(self, room_id: str) -> RoomSession | None:
        value = self.rooms.pop(room_id, None)
        await self.save()
        return value


def _now_ms() -> int:
    return int(time.time() * 1_000)


def _digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(character in "0123456789abcdef" for character in value)


def _enum(enum_type: type[Enum], value: Any, default: Any) -> Any:
    if isinstance(value, enum_type):
        return value
    try:
        return enum_type(str(value))
    except (TypeError, ValueError):
        return default


def _optional_enum(enum_type: type[Enum], value: Any) -> Any | None:
    if value is None:
        return None
    try:
        return enum_type(str(value))
    except (TypeError, ValueError):
        return None


def _optional_string(value: Any) -> str | None:
    return str(value) if value is not None and str(value).strip() else None


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _nonnegative_int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _positive_int(value: Any, default: int) -> int:
    parsed = _nonnegative_int(value)
    return parsed if parsed > 0 else default


def _pursuit_extent(value: Any) -> int:
    try:
        extent = int(value or 1)
    except (TypeError, ValueError):
        return 1
    return extent if extent in {1, 2, 3} else 1


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip() for item in value if str(item).strip()]


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _criteria(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for item in value:
        criterion = PursuitCriterion.from_dict(item)
        if criterion is not None:
            result.append({"id": criterion.id, "text": criterion.text})
    return result


def _criterion_status_mapping(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    allowed = {status.value for status in CriterionStatus}
    return {
        str(key): str(status)
        for key, status in value.items()
        if str(status) in allowed
    }


def _evidence(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list):
        return []
    result: list[dict[str, str]] = []
    for item in value:
        if not isinstance(item, dict):
            continue
        fields = {
            key: item.get(key)
            for key in ("criterion_id", "claim", "source", "verification")
        }
        if all(isinstance(field, str) and field.strip() for field in fields.values()):
            parsed = {key: str(field).strip() for key, field in fields.items()}
            if item.get("trust") == "legacy_untrusted":
                parsed["trust"] = "legacy_untrusted"
            result.append(parsed)
    return result


def _active_tools(value: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for part_id, tool in value.items():
        if not isinstance(tool, dict) or not tool.get("name"):
            continue
        result[str(part_id)] = {
            "name": str(tool["name"]),
            "started_ms": int(tool.get("started_ms") or 0),
        }
    return result
