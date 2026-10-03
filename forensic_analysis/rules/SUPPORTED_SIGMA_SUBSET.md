# Sigma Supported Subset — Argus Deterministic Forensic Layer
## Overview

Argus implements a **pure-Python Sigma rule matcher** that evaluates a deliberately
limited, explicitly documented subset of the Sigma specification against normalized
`Artifact.normalized_fields` and `Artifact.raw_fields`. This avoids external
transpilation dependencies (pySigma, Elasticsearch, Splunk) and keeps rule
evaluation fully deterministic and reproducible.

## Supported Detection Modifiers

| Modifier | Behaviour | Example |
|---|---|---|
| (none) | Exact case-insensitive equality | `process_name: powershell.exe` |
| `|contains` | Substring match (case-insensitive) | `command_line|contains: '-enc'` |
| `|endswith` | Suffix match (case-insensitive) | `process_name|endswith: '\powershell.exe'` |
| `|startswith` | Prefix match (case-insensitive) | `file_path|startswith: 'C:\Windows\Temp'` |
| `|re` | Python `re.search` regex match | `command_line|re: '(?i)invoke-\w+'` |
| `|all` | ALL values in a list must match (AND) | `command_line|contains|all: ['-enc', 'bypass']` |

## Supported Condition Syntax

| Pattern | Meaning |
|---|---|
| `selection` | Single named detection block must match |
| `selection and not filter` | Selection matches AND filter does NOT |
| `selection and filter` | Both blocks must match |
| `selection1 or selection2` | Either block matches |
| `1 of selection*` | Any block whose name starts with `selection` matches |
| `all of selection*` | All blocks whose name starts with `selection` match |

## Unsupported Features (Intentionally Excluded)

- **Aggregation conditions** (`count`, `near`, `temporal`)
- **Pipe operators** (`| count() > 5`)
- **Nested boolean logic** beyond `A and B`, `A or B`, `A and not B`
- **Field name aliases / Sigma taxonomy mapping** — Argus uses its own
  `NormalizedFields` + `raw_fields` namespace
- **Logsource backend routing** — rules are dispatched by the engine
  orchestrators based on artifact_type taxonomy, not Sigma logsource

## Rule Metadata Contract

Every Sigma YAML rule MUST include:
- `title` (str): Human-readable rule name
- `id` (str): Unique rule identifier (UUID recommended)
- `level` (str): One of `informational`, `low`, `medium`, `high`, `critical`
- `detection` (dict): At minimum one named selection block + `condition`

Optional but recommended:
- `description` (str): What the rule detects
- `tags` (list[str]): MITRE ATT&CK tags (e.g., `attack.t1059.001`)
  **NOTE**: These are treated as *rule author metadata hints*, NOT as
  authoritative MITRE mappings. Agent 5a / MITRE mapping layer may
  override or refine these downstream.
- `falsepositives` (list[str]): Known benign triggers
- `author` (str): Rule author
- `date` (str): Rule creation date

## Field Resolution Order

When matching a Sigma field name (e.g., `process_name`), the engine resolves
the value from the Artifact in this order:

1. `artifact.normalized_fields.<field_name>` (Pydantic attribute)
2. `artifact.raw_fields[<field_name>]` (dict key, case-sensitive)
3. `artifact.raw_fields[<OriginalCaseName>]` (common EVTX/Sysmon casing variants)

If the field is not found, the condition for that field evaluates to `False`
(no match), never an error.
