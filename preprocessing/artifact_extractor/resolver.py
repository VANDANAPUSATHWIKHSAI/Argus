from typing import Any, Dict, List, Optional
from preprocessing.schemas import Artifact

class ProcessRelationshipResolver:
    """
    Resolves structural parent-child process execution relationships (parent --SPAWNS--> child)
    from forensic artifacts using PIDs, PPIDs, image names, command lines, and timestamps.
    """

    def resolve_relationships(self, artifacts: List[Artifact]) -> List[Dict[str, Any]]:
        """
        Parses a batch of process artifacts, extracts metadata, correlates PIDs/PPIDs,
        and returns resolved parent-child spawn linkages.
        """
        processes: List[Dict[str, Any]] = []

        # 1. Extract process metadata from raw_fields and normalized_fields
        for art in artifacts:
            raw = art.raw_fields or {}
            norm = art.normalized_fields
            
            # Look for PID and PPID in various forensic formats
            pid = raw.get("pid") or raw.get("PID") or raw.get("process_id") or raw.get("ProcessId")
            if pid is None and norm:
                pid = norm.process_id
                
            ppid = raw.get("ppid") or raw.get("PPID") or raw.get("parent_pid") or raw.get("ParentProcessId")
            if ppid is None and norm:
                ppid = norm.parent_process_id
            
            # Look for process names and image paths
            proc_name = raw.get("process_name") or raw.get("ProcessName") or raw.get("image") or raw.get("Image")
            if not proc_name and norm:
                proc_name = norm.process_name
                
            parent_name = raw.get("parent_process_name") or raw.get("ParentProcessName") or raw.get("parent_image") or raw.get("ParentImage")
            
            # Command lines and executable paths
            cmd = raw.get("command_line") or raw.get("CommandLine") or raw.get("cmdline")
            if not cmd and norm:
                cmd = norm.process_command_line
                
            executable = raw.get("image_path") or raw.get("ImagePath") or raw.get("path")
            if not executable and norm:
                executable = norm.file_path
            
            # Timestamp
            ts = raw.get("timestamp") or raw.get("TimeCreated") or raw.get("CreateTime") or raw.get("created_at") or art.timestamp

            # Convert PID/PPID to int if possible for clean mapping
            try:
                if pid is not None:
                    pid = int(float(pid))
            except (ValueError, TypeError):
                pass
            try:
                if ppid is not None:
                    ppid = int(float(ppid))
            except (ValueError, TypeError):
                pass

            if pid is not None or proc_name is not None:
                processes.append({
                    "pid": pid,
                    "ppid": ppid,
                    "process_name": proc_name,
                    "parent_process_name": parent_name,
                    "command_line": cmd,
                    "executable": executable,
                    "timestamp": ts,
                    "artifact_id": art.artifact_id,
                    "evidence_id": art.evidence_id,
                    "source_tool": art.source_tool
                })

        resolved: List[Dict[str, Any]] = []

        # 2. Correlate parent-child links
        for child in processes:
            # Skip if we don't have a parent link (no PPID and no parent_process_name)
            if child["ppid"] is None and child["parent_process_name"] is None:
                continue

            parent_match: Optional[Dict[str, Any]] = None

            # Attempt A: Match by PID/PPID
            if child["ppid"] is not None:
                for parent in processes:
                    if parent["pid"] == child["ppid"]:
                        # Enforce temporal sanity if timestamps are available
                        parent_match = parent
                        break

            # Attempt B: Fallback to match by ParentProcessName
            if parent_match is None and child["parent_process_name"] is not None:
                for parent in processes:
                    if parent["process_name"] == child["parent_process_name"]:
                        parent_match = parent
                        break

            if parent_match is not None:
                resolved.append({
                    "parent": {
                        "pid": parent_match["pid"],
                        "process_name": parent_match["process_name"],
                        "command_line": parent_match["command_line"],
                        "executable": parent_match["executable"],
                        "timestamp": parent_match["timestamp"]
                    },
                    "child": {
                        "pid": child["pid"],
                        "process_name": child["process_name"],
                        "command_line": child["command_line"],
                        "executable": child["executable"],
                        "timestamp": child["timestamp"]
                    },
                    "relationship": "SPAWNS",
                    "provenance": {
                        "evidence_id": child["evidence_id"],
                        "parent_artifact_id": parent_match["artifact_id"],
                        "child_artifact_id": child["artifact_id"],
                        "source_tool": child["source_tool"]
                    }
                })

        return resolved


import re

class CommandLineSpanResolver:
    """
    Deterministically expands a base executable candidate to its complete command line
    using explicit syntax boundaries. Stops at sentence boundaries, attribution phrases,
    delimiters, unrelated entities, or new evidence lines.
    """

    ATTRIBUTION_PHRASES = [
        " was executed",
        " was launched",
        " was observed",
        " to dump",
        " to launch",
        " to download",
        " to establish",
        " to inject",
        " on port",
        " for user",
        " for the",
        " group attacked",
        " campaign targeting",
        " runs in",
        " runs ",
        " process",
        " shell",
        " daemon",
        " service",
        " by modifying",
        " by executing",
        " targeting ",
        " infected ",
        " using ",
        " to query",
        " process replacement",
        " via ",
        " to cause",
        " to run",
        " to execute",
        " to install",
        " to update",
        " to check",
        " to search",
        " to copy",
        " to delete",
        " to remove",
        " to clear",
        " to format",
        " to stop",
        " to start",
        " to create",
        " to add",
        " to set",
        " to get",
        " to view",
        " to read",
        " to write",
        " to send",
        " to receive",
        " to open",
        " to close",
        " to verify",
        " to publish",
        " to report",
        " to analyze",
        " to analyze ",
        " published ",
        " analyzed ",
        " reported ",
        " verified ",
        " opened ",
        " closed ",
        " sent ",
        " received ",
        " wrote ",
        " read ",
        " viewed ",
        " set ",
        " added ",
        " created ",
        " started ",
        " stopped ",
        " formatted ",
        " cleared ",
        " removed ",
        " deleted ",
        " copied ",
        " searched ",
        " checked ",
        " updated ",
        " installed ",
        " executed ",
        " run ",
        " caused ",
        " dump ",
        " launch ",
        " download ",
        " establish ",
        " inject "
    ]

    DELIMITERS = [";", "|", "&", "\n", "\r", "\t"]

    PROSE_STOPWORDS = {
        "in", "on", "at", "by", "from", "to", "for", "as", "the", "a", "an", 
        "was", "were", "is", "are", "be", "been", "has", "have", "had", 
        "observed", "detected", "executed", "launched", "used", "mentioned", 
        "reported", "states", "stated", "runs", "running", "session", "report", 
        "attacker", "system", "our", "their", "against", "about", "we", "they", 
        "he", "she", "it", "i", "you", "who", "which", "that", "this", "these", 
        "those", "and", "or", "but", "because", "according", "during", "operation",
        "investigation", "activity"
    }

    KNOWN_SUBCOMMANDS = {
        "vssadmin.exe": {"delete", "shadows", "create", "resize", "list", "shadowstorage", "providers", "writers"},
        "reg.exe": {"query", "add", "delete", "copy", "save", "restore", "load", "unload", "compare", "export", "import"},
        "schtasks.exe": {"create", "delete", "query", "change", "run", "end"},
        "sc.exe": {"create", "delete", "start", "stop", "query", "config", "control", "description"},
        "wmic.exe": {"process", "service", "bios", "computersystem", "diskdrive", "os", "path", "call", "create", "delete", "get", "set", "list"},
        "net.exe": {"user", "group", "localgroup", "use", "start", "stop", "share", "view", "accounts", "time", "session", "computer"},
        "net1.exe": {"user", "group", "localgroup", "use", "start", "stop", "share", "view", "accounts", "time", "session", "computer"}
    }

    SWITCHES_EXPECTING_VALUE = {
        "-file", "-f", "-command", "-c", "-encodedcommand", "-enc", "-e",
        "-executionpolicy", "-ep", "-windowstyle", "-w", "-style", "-stage",
        "/c", "/k", "/tr", "/tn", "/ru", "/rp", "/sc", "/mo", "/sd", "/st",
        "/v", "/t", "/d", "/r", "/s", "--stage", "--mode", "--inject"
    }

    def __init__(self, target_executables: list[str] = None):
        if target_executables is None:
            self.target_executables = [
                "powershell.exe", "cmd.exe", "vssadmin.exe", 
                "rundll32.exe", "reg.exe", "schtasks.exe"
            ]
        else:
            self.target_executables = target_executables

    def is_plausible_argument(self, token: str, prev_token: str, exec_name: str) -> bool:
        token_lower = token.lower()
        prev_lower = prev_token.lower() if prev_token else ""

        # 1. Quoted string is treated atomically (always plausible)
        if (token.startswith('"') and token.endswith('"')) or (token.startswith("'") and token.endswith("'")):
            return True

        # 2. Strict alphanumeric check: a non-quoted argument must contain at least one alphanumeric character
        # (This prevents single colons or slashes alone from keeping the parser expanding)
        if not any(c.isalnum() for c in token):
            return False

        # 3. Strong command syntax
        # A. switches
        if token.startswith(('-', '--', '/', '$')):
            return True

        # B. assignment/URL/path characters
        if '=' in token:
            return True

        # C. paths and filenames
        if '\\' in token or '/' in token or ':' in token:
            return True

        # D. standard script/executable/log extensions
        extensions = (
            '.exe', '.dll', '.ps1', '.bat', '.sh', '.py', '.pl', '.vbs', '.js', '.cmd', 
            '.bin', '.txt', '.tmp', '.log', '.xml', '.json', '.dat', '.scr', 
            '.msi', '.vbe', '.wsf', '.hta', '.cpl', '.sys', '.inf'
        )
        if any(token_lower.endswith(ext) or (ext + ",") in token_lower for ext in extensions):
            return True

        # E. numeric arguments
        if token.isdigit():
            return True

        # F. known command verbs/subcommands for specific tools
        base_exec = exec_name.split('\\')[-1].split('/')[-1].lower()
        known_verbs = self.KNOWN_SUBCOMMANDS.get(base_exec, set())
        if token_lower in known_verbs:
            return True

        # 4. Continuation token: expects value from previous token
        if prev_lower in self.SWITCHES_EXPECTING_VALUE or prev_lower.endswith(('=', ':')):
            if token_lower in self.PROSE_STOPWORDS:
                return False
            return True

        return False

    def resolve_command_line(self, text: str, start: int, end: int, value: str) -> tuple[int, int, str]:
        """
        Takes the source text and candidate boundaries. If the candidate matches a targeted
        executable pattern, it expands the span to capture the rest of the command line programmatically,
        respecting delimiters, stop boundaries, and structured command syntax.
        Returns (new_start, new_end, new_value).
        """
        exec_name = value.strip().lower()
        text_len = len(text)
        
        # Check eligibility for command-line resolution:
        # A. Matches targeted Windows executables list
        is_target = any(exec_name == target or exec_name.endswith("\\" + target) or exec_name.endswith("/" + target) 
                        for target in self.target_executables)
        
        # B. Generic matches (contains path separators, script extensions, interpreter names,
        # or is a plain word followed by a switch)
        is_generic = False
        if not is_target:
            if '\\' in value or '/' in value:
                is_generic = True
            elif any(exec_name.endswith(ext) for ext in [
                ".exe", ".dll", ".bin", ".bat", ".cmd", ".sh", ".py", ".pl", ".vbs", ".js", ".ps1"
            ]):
                is_generic = True
            elif exec_name in ["powershell", "cmd", "bash", "sh", "python3", "python", "wscript", "cscript", "regsvr32"]:
                is_generic = True
            else:
                # Check if followed immediately by a structured switch/flag token
                curr = end
                while curr < text_len and text[curr].isspace():
                    curr += 1
                if curr < text_len:
                    next_char = text[curr]
                    if next_char in ['-', '/']:
                        remaining_tok = text[curr:]
                        match = re.match(r'^[-/]+[a-zA-Z0-9]', remaining_tok)
                        if match:
                            is_generic = True
                            
        if not is_target and not is_generic:
            return start, end, value

        # Scan rightwards using token-by-token validation
        curr_idx = end
        prev_token = ""
        
        while curr_idx < text_len:
            # 1. Skip leading whitespace, but don't permanently commit the index yet
            ws_idx = curr_idx
            while ws_idx < text_len and text[ws_idx].isspace():
                ws_idx += 1
                
            if ws_idx >= text_len:
                break
                
            # If there was a newline or delimiter in the skipped whitespace, stop
            skipped_ws = text[curr_idx:ws_idx]
            if "\n" in skipped_ws or "\r" in skipped_ws or any(d in skipped_ws for d in self.DELIMITERS):
                break
                
            # 2. Check attribution phrases in the remaining text
            remaining = text[ws_idx:]
            has_attribution = False
            for phrase in self.ATTRIBUTION_PHRASES:
                phrase_stripped = phrase.lstrip()
                if remaining.lower().startswith(phrase_stripped):
                    has_attribution = True
                    break
            if has_attribution:
                break
                
            # 3. Check sentence boundaries
            if re.match(r'^[.!?](\s|$)', remaining):
                break
                
            # 4. Extract the next token using a temporary index
            token_start = ws_idx
            temp_idx = ws_idx
            char = text[ws_idx]
            
            if char in ['"', "'"]:
                quote_char = char
                temp_idx += 1 # Consume open quote
                while temp_idx < text_len and text[temp_idx] != quote_char:
                    temp_idx += 1
                if temp_idx < text_len:
                    temp_idx += 1 # Consume close quote
                token = text[token_start:temp_idx]
            else:
                # Non-quoted token: scan until whitespace or delimiter or sentence boundary
                while temp_idx < text_len and not text[temp_idx].isspace() and text[temp_idx] not in self.DELIMITERS:
                    if text[temp_idx] in ['.', '!', '?'] and (temp_idx + 1 >= text_len or text[temp_idx + 1].isspace()):
                        break
                    temp_idx += 1
                token = text[token_start:temp_idx]
                
            if not token:
                break
                
            # 5. Clean trailing punctuation typical of clause ending
            cleaned_token = token
            trailing_punctuation = ""
            match = re.search(r'([.,;:!?)]+)$', token)
            if match:
                punc = match.group(1)
                cleaned_token = token[:-len(punc)]
                trailing_punctuation = punc
                
            if not cleaned_token:
                break
                
            # 6. Validate if the token is a plausible command argument
            is_plausible = self.is_plausible_argument(cleaned_token, prev_token, value)
            if not is_plausible:
                break
                
            # Update curr_idx and prev_token only when the token is validated
            curr_idx = token_start + len(cleaned_token)
            prev_token = cleaned_token
            
            # If the token has trailing sentence-ending punctuation, we stop after it
            if any(p in trailing_punctuation for p in ('.', '!', '?')):
                break

        resolved_text = text[start:curr_idx].rstrip()
        resolved_end = start + len(resolved_text)
        
        return start, resolved_end, resolved_text

