# Agent 5a Independent Red-Team Review

## Scope

Read-only adversarial review of Agent 5a threat-intelligence execution paths,
evidence provenance, tenant isolation, external adapter handling, and
persistence semantics. No production code or tests were changed as part of the
audit.

## Findings

| # | Severity | File / function | Finding |
|---|---|---|---|
| 1 | HIGH | `agents/agent5a_threat_intelligence/agent.py` — `_query_feed()` / `_match()` | Adapter results are accepted without independently proving that the returned record corresponds to the requested indicator. A contradictory adapter response can become a validated IOC/CVE/intelligence match. |
| 2 | MEDIUM | `agents/agent5a_threat_intelligence/agent.py` — `_agent2_findings()` | Agent 2 claim text is treated as an indicator source when it cites a valid FIR ID, even if the claim is not supported by the authoritative FIR finding. Fabricated indicators can inherit genuine FIR provenance. |
| 3 | MEDIUM | `agents/agent5a_threat_intelligence/agent.py` — `_valid_correlation()` | The function checks the returned record's case but not its tenant. A permissive alternate correlation repository can introduce a cross-tenant correlation reference. |
| 4 | MEDIUM | `agents/agent5a_threat_intelligence/agent.py` — `_version_matches()` | Packaging-version normalization treats exact strings such as `1.2` and `1.2.0` as equivalent. This can produce false applicability where the feed's exact-version semantics distinguish them. |
| 5 | MEDIUM | `agents/agent5a_threat_intelligence/schemas.py` — `Agent5aOutput.to_agent_output_record()` | A caller can construct an output with non-empty fabricated provenance and evidence IDs and satisfy the local `verified` predicate without authoritative repository validation. |

## Reproductions

### 1. Uncorrelated adapter result

Provide a valid current-case FIR finding and an adapter whose IOC method
always returns:

```python
{"id": "UNRELATED", "description": "arbitrary result", "confidence": 0.9}
```

for an unrelated indicator. The result is emitted in `ioc_matches` because
`_match()` validates non-empty provenance but does not deterministically
correlate the adapter record with the requested indicator.

### 2. Unsupported Agent 2 claim

Use an authoritative FIR finding whose fact says routine activity, then submit
an Agent 2 claim citing that finding and containing a fabricated CVE or domain.
`_agent2_findings()` concatenates string-valued claim fields and allows the
fabricated indicator to be queried and attributed to the cited FIR ID.

### 3. Cross-tenant correlation

Supply a `correlation_repository` whose `get_by_id()` ignores the tenant
argument and returns a record with the active case but a different tenant.
`_valid_correlation()` accepts the record because it checks only `case_id`.

### 4. Version normalization

```python
ThreatIntelligenceAgent._version_matches("1.2.0", ["1.2"])
```

returns `True` because `packaging.version.Version` normalizes both values.

### 5. Caller-constructed verified output

Construct `Agent5aOutput` directly with `SUCCESS`, non-empty fabricated
`evidence_ids`, and non-empty provenance. `to_agent_output_record()` checks
presence and shape, but does not perform repository resolution.

## Security impact

These findings can cause false intelligence matches, contaminate investigation
provenance, introduce cross-tenant correlation references, misstate CVE
applicability, or persist caller-supplied evidence as verified.

## Verification status

The live PostgreSQL tests confirmed valid, fabricated, wrong-case, and
wrong-tenant FIR evidence/correlation behavior through the normal Agent 5a
path. Real external TAXII/NVD/MITRE/CISA services and a dedicated Agent 5a
database persistence round-trip were not exercised.

## Verdict

**NOT SAFE TO INTEGRATE**

The normal PostgreSQL evidence path and tested STIX type enforcement are
hardened, but the alternate adapter, Agent 2 claim, correlation-repository,
version-semantics, and direct-persistence paths remain unresolved.
