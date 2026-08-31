"""
Layer 1 Repair #3 — Tests
==========================

Part A: Audit Log Hash Chaining (P0 repair)
  Proves that the cryptographic chain is correct, tenant-isolated,
  tamper-detectable, and backward-compatible.

Part B: Docker Sandbox Real Validation (P1 repair)
  Proves that the container command is NOT a no-op, that evidence is
  actually read and inspected, and that isolation controls remain intact.
"""

import hashlib
import json
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, call, patch


# ══════════════════════════════════════════════════════════════════════════════
# Part A — Audit Log Hash Chaining
# ══════════════════════════════════════════════════════════════════════════════

class TestAuditLogHashChaining(unittest.TestCase):
    """
    Verifies cryptographic hash chaining for audit_logger.py.
    Each test runs against an isolated temporary log directory so that tests
    are fully independent and ordering-agnostic.
    """

    def setUp(self):
        # Isolate log files in a temp directory
        self.tmp_dir = tempfile.mkdtemp()
        self.old_logs_dir = os.environ.get("ARGUS_LOGS_DIR")
        os.environ["ARGUS_LOGS_DIR"] = self.tmp_dir

        # Clear the module-level chain registry and logger registry so each
        # test gets a fresh chain starting at GENESIS.
        import infrastructure.audit_logger as al
        al._CHAIN_REGISTRY.clear()
        # Remove any existing logger handlers that would still point to old paths
        import logging
        for name in list(logging.Logger.manager.loggerDict.keys()):
            if name.startswith("audit."):
                logger = logging.getLogger(name)
                for h in list(logger.handlers):
                    logger.removeHandler(h)
                    h.close()

        self.al = al

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)
        if self.old_logs_dir:
            os.environ["ARGUS_LOGS_DIR"] = self.old_logs_dir
        else:
            os.environ.pop("ARGUS_LOGS_DIR", None)

    # ── helper ────────────────────────────────────────────────────────────────

    def _read_log(self, tenant_id: str) -> list[dict]:
        log_path = Path(self.tmp_dir) / "audit" / f"{tenant_id}.jsonl"
        entries = []
        with log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def _write_log_raw(self, tenant_id: str, lines: list[str]) -> None:
        """Write raw lines to a tenant log (for tampering simulations)."""
        log_path = Path(self.tmp_dir) / "audit" / f"{tenant_id}.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("w", encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")

    # ── Test 1: First entry uses GENESIS ─────────────────────────────────────

    def test_first_entry_uses_genesis(self):
        """First entry must carry prev_hash == 'GENESIS'."""
        logger = self.al.get_audit_logger("tenant-genesis")
        logger.info({"action": "test_event", "tenant_id": "tenant-genesis"})

        entries = self._read_log("tenant-genesis")
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["prev_hash"], "GENESIS")

    # ── Test 2: Second entry references first entry_hash ─────────────────────

    def test_second_entry_references_first_entry_hash(self):
        """Second entry's prev_hash must equal the first entry's entry_hash."""
        logger = self.al.get_audit_logger("tenant-chain")
        logger.info({"action": "event_one", "tenant_id": "tenant-chain"})
        logger.info({"action": "event_two", "tenant_id": "tenant-chain"})

        entries = self._read_log("tenant-chain")
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[1]["prev_hash"], entries[0]["entry_hash"])

    # ── Test 3: Chain verifies successfully ──────────────────────────────────

    def test_chain_verifies_successfully(self):
        """verify_chain() must return ok=True for an untampered log."""
        logger = self.al.get_audit_logger("tenant-verify")
        for i in range(5):
            logger.info({"action": f"event_{i}", "tenant_id": "tenant-verify"})

        result = self.al.verify_chain("tenant-verify")
        self.assertTrue(result["ok"])
        self.assertEqual(result["entries_verified"], 5)

    # ── Test 4: Modified entry fails verification ─────────────────────────────

    def test_modified_entry_fails_verification(self):
        """
        If an existing entry's field is changed after writing, verify_chain()
        must raise AuditChainVerificationError.
        """
        logger = self.al.get_audit_logger("tenant-modify")
        logger.info({"action": "original_event", "tenant_id": "tenant-modify"})

        entries = self._read_log("tenant-modify")
        # Tamper: change the action field of the first entry
        entries[0]["action"] = "TAMPERED_EVENT"
        tampered_lines = [
            json.dumps(e, sort_keys=True, separators=(",", ":")) for e in entries
        ]
        self._write_log_raw("tenant-modify", tampered_lines)

        with self.assertRaises(self.al.AuditChainVerificationError) as ctx:
            self.al.verify_chain("tenant-modify")
        self.assertIn("mismatch", str(ctx.exception).lower())

    # ── Test 5: Deleted entry fails verification ──────────────────────────────

    def test_deleted_entry_fails_verification(self):
        """Removing a middle entry must break the chain linkage."""
        logger = self.al.get_audit_logger("tenant-delete")
        for i in range(3):
            logger.info({"action": f"event_{i}", "tenant_id": "tenant-delete"})

        entries = self._read_log("tenant-delete")
        self.assertEqual(len(entries), 3)

        # Delete the middle entry
        remaining = [entries[0], entries[2]]
        lines = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in remaining]
        self._write_log_raw("tenant-delete", lines)

        with self.assertRaises(self.al.AuditChainVerificationError) as ctx:
            self.al.verify_chain("tenant-delete")
        self.assertIn("prev_hash", str(ctx.exception).lower())

    # ── Test 6: Inserted entry fails verification ─────────────────────────────

    def test_inserted_entry_fails_verification(self):
        """Inserting a new entry without a valid chain link must be detected."""
        logger = self.al.get_audit_logger("tenant-insert")
        logger.info({"action": "event_a", "tenant_id": "tenant-insert"})
        logger.info({"action": "event_b", "tenant_id": "tenant-insert"})

        entries = self._read_log("tenant-insert")

        # Forge an entry without recomputing hashes
        forged = {
            "action": "INJECTED_ENTRY",
            "tenant_id": "tenant-insert",
            "prev_hash": entries[0]["entry_hash"],
            "entry_hash": "deadbeef" * 8,  # wrong hash
        }
        # Insert between entry 0 and entry 1
        tampered = [entries[0], forged, entries[1]]
        lines = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in tampered]
        self._write_log_raw("tenant-insert", lines)

        with self.assertRaises(self.al.AuditChainVerificationError):
            self.al.verify_chain("tenant-insert")

    # ── Test 7: Reordered entries fail verification ───────────────────────────

    def test_reordered_entries_fail_verification(self):
        """Swapping two adjacent entries must break the chain."""
        logger = self.al.get_audit_logger("tenant-reorder")
        for i in range(3):
            logger.info({"action": f"event_{i}", "tenant_id": "tenant-reorder"})

        entries = self._read_log("tenant-reorder")
        # Swap entries 1 and 2
        reordered = [entries[0], entries[2], entries[1]]
        lines = [json.dumps(e, sort_keys=True, separators=(",", ":")) for e in reordered]
        self._write_log_raw("tenant-reorder", lines)

        with self.assertRaises(self.al.AuditChainVerificationError):
            self.al.verify_chain("tenant-reorder")

    # ── Test 8: Tenant A chain is independent from Tenant B ──────────────────

    def test_tenant_chains_are_independent(self):
        """
        Writing to Tenant A's log must not affect Tenant B's chain and vice
        versa.  Both chains must verify independently.
        """
        logger_a = self.al.get_audit_logger("tenant-A-isolated")
        logger_b = self.al.get_audit_logger("tenant-B-isolated")

        logger_a.info({"action": "a_event_1", "tenant_id": "tenant-A-isolated"})
        logger_b.info({"action": "b_event_1", "tenant_id": "tenant-B-isolated"})
        logger_a.info({"action": "a_event_2", "tenant_id": "tenant-A-isolated"})

        entries_a = self._read_log("tenant-A-isolated")
        entries_b = self._read_log("tenant-B-isolated")

        # Tenant A has 2 entries, Tenant B has 1
        self.assertEqual(len(entries_a), 2)
        self.assertEqual(len(entries_b), 1)

        # Tenant A chain starts at GENESIS independently
        self.assertEqual(entries_a[0]["prev_hash"], "GENESIS")
        # Tenant B chain also starts at GENESIS independently
        self.assertEqual(entries_b[0]["prev_hash"], "GENESIS")

        # Both chains verify cleanly
        res_a = self.al.verify_chain("tenant-A-isolated")
        res_b = self.al.verify_chain("tenant-B-isolated")
        self.assertTrue(res_a["ok"])
        self.assertTrue(res_b["ok"])
        self.assertEqual(res_a["entries_verified"], 2)
        self.assertEqual(res_b["entries_verified"], 1)

    # ── Test 9: Existing audit functionality remains compatible ───────────────

    def test_existing_audit_functionality_compatible(self):
        """
        Callers that previously used get_audit_logger() and logged plain dicts
        must still work correctly.  Fields like 'tenant_id', 'action', and
        custom payload keys must be preserved verbatim.
        """
        logger = self.al.get_audit_logger("tenant-compat")
        logger.info({
            "tenant_id": "tenant-compat",
            "action": "evidence_uploaded",
            "evidence_id": "ev-001",
            "case_id": "case-abc",
        })

        entries = self._read_log("tenant-compat")
        self.assertEqual(len(entries), 1)
        e = entries[0]

        # All caller-supplied fields must be present
        self.assertEqual(e["action"], "evidence_uploaded")
        self.assertEqual(e["evidence_id"], "ev-001")
        self.assertEqual(e["case_id"], "case-abc")

        # Chaining fields injected by the logger
        self.assertIn("prev_hash", e)
        self.assertIn("entry_hash", e)
        self.assertEqual(e["prev_hash"], "GENESIS")

        # Verify chain is still intact
        result = self.al.verify_chain("tenant-compat")
        self.assertTrue(result["ok"])

    # ── Test 10: entry_hash is deterministic ─────────────────────────────────

    def test_entry_hash_determinism(self):
        """
        Given the same prev_hash and entry contents, _compute_entry_hash must
        always produce the same result (deterministic serialisation).
        """
        entry = {"action": "ev", "tenant_id": "t1", "prev_hash": "GENESIS"}
        h1 = self.al._compute_entry_hash("GENESIS", entry)
        h2 = self.al._compute_entry_hash("GENESIS", entry)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 64)  # 256-bit hex

    # ── Test 11: Concurrent writes don't corrupt the chain ───────────────────

    def test_concurrent_writes_do_not_corrupt_chain(self):
        """
        100 concurrent writes from 10 threads must produce a valid, unbroken
        chain with exactly 100 entries.
        """
        tenant = "tenant-concurrent"
        logger = self.al.get_audit_logger(tenant)

        errors = []

        def write_entries(thread_id, count):
            try:
                for i in range(count):
                    logger.info({
                        "action": f"concurrent_event",
                        "thread": thread_id,
                        "seq": i,
                        "tenant_id": tenant,
                    })
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=write_entries, args=(tid, 10)) for tid in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertFalse(errors, f"Threads raised exceptions: {errors}")

        result = self.al.verify_chain(tenant)
        self.assertTrue(result["ok"])
        self.assertEqual(result["entries_verified"], 100)


# ══════════════════════════════════════════════════════════════════════════════
# Part B — Docker Sandbox Real Content Validation
# ══════════════════════════════════════════════════════════════════════════════

class TestSandboxRealValidation(unittest.TestCase):
    """
    Verifies the P1 sandbox repair: run_docker_sandbox() must NOT use the
    no-op command=["true"] and must actually inspect the mounted evidence.

    All Docker calls are mocked at the SDK level — Docker daemon not required.
    The tests validate the *semantics* of what is passed to Docker (command
    contents, volume mounts, isolation parameters) and the flag-parsing logic
    for real exit codes.
    """

    def setUp(self):
        import importlib
        import infrastructure.sandbox.intake_validator as iv
        self.iv = iv

    def _make_mock_client(self, exit_code: int = 0, stdout_output: bytes = b"", stderr_output: bytes = b"") -> MagicMock:
        """Returns a fully configured mock docker client."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_container.wait.return_value = {"StatusCode": exit_code}
        mock_container.logs.return_value = stdout_output + stderr_output
        return mock_client

    # ── Test 1: Command is NOT ["true"] ──────────────────────────────────────

    def test_container_command_is_not_true(self):
        """
        The command passed to client.containers.run() must NOT be ["true"]
        or any trivial no-op equivalent.
        """
        mock_client = self._make_mock_client(exit_code=0, stdout_output=b"SANDBOX_INFO: size=10 header_hex=aabbccdd")
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"forensic evidence bytes")
                tf_path = tf.name

            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        call_kwargs = mock_client.containers.run.call_args
        command = call_kwargs[1].get("command") or call_kwargs[0][1]

        # Must NOT be the trivial no-op
        self.assertNotEqual(command, ["true"], "command=['true'] no-op must be removed")
        self.assertNotIn("true", command if isinstance(command, list) else [command],
                         "command must not be just 'true'")

    # ── Test 2: Command is a real script that reads evidence ─────────────────

    def test_container_command_is_real_validation_script(self):
        """
        The command must be a shell invocation (sh -c ...) containing
        evidence-reading operations (dd, wc, od, or equivalent).
        """
        mock_client = self._make_mock_client(exit_code=0, stdout_output=b"SANDBOX_INFO: size=42 header_hex=deadbeef")
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"x" * 42)
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        call_kwargs = mock_client.containers.run.call_args[1]
        command = call_kwargs.get("command")

        # Expect sh -c <script>
        self.assertIsInstance(command, list)
        self.assertGreaterEqual(len(command), 3, "Expected ['sh', '-c', script]")
        self.assertEqual(command[0], "sh")
        self.assertEqual(command[1], "-c")

        script = command[2]
        # Script must reference the evidence path
        self.assertIn("/evidence", script)
        # Script must contain at least one byte-reading tool
        reads_bytes = any(tool in script for tool in ("dd", "wc", "od", "xxd", "hexdump", "cat"))
        self.assertTrue(reads_bytes, "Validation script must read evidence bytes")

    # ── Test 3: Valid evidence is accepted (exit_code=0 → no reject flags) ───

    def test_valid_evidence_accepted(self):
        """Exit code 0 with no error output must produce no sandbox_container_error flags."""
        mock_client = self._make_mock_client(
            exit_code=0,
            stdout_output=b"SANDBOX_INFO: size=100 header_hex=4d5a9000"
        )
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"MZ" + b"\x00" * 98)
                tf_path = tf.name
            try:
                flags = self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        error_flags = [f for f in flags if "sandbox_container_error" in f]
        self.assertEqual(error_flags, [], f"Valid evidence must not produce error flags: {flags}")

    # ── Test 4: Invalid/empty evidence is rejected (non-zero exit code) ───────

    def test_invalid_evidence_produces_error_flag(self):
        """
        A non-zero exit code from the container (empty file, unreadable, etc.)
        must produce a 'sandbox_container_error' flag.
        """
        mock_client = self._make_mock_client(
            exit_code=5,  # Exit 5 = empty file in our script
            stderr_output=b"SANDBOX_ERROR: /evidence/file is empty (0 bytes)"
        )
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf_path = tf.name  # empty file
            try:
                flags = self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        error_flags = [f for f in flags if "sandbox_container_error" in f]
        self.assertTrue(len(error_flags) > 0, f"Empty/invalid evidence must produce error flags; got: {flags}")
        self.assertIn("exit_code=5", error_flags[0])

    # ── Test 5: Evidence is mounted read-only ─────────────────────────────────

    def test_evidence_mounted_read_only(self):
        """The volume mount mode must be 'ro' (read-only)."""
        mock_client = self._make_mock_client(exit_code=0)
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"evidence content")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        kwargs = mock_client.containers.run.call_args[1]
        volumes = kwargs["volumes"]
        # There must be exactly one volume; its mode must be 'ro'
        for host_path, mount_cfg in volumes.items():
            self.assertEqual(mount_cfg["mode"], "ro",
                             f"Volume {host_path} must be read-only, got: {mount_cfg}")

    # ── Test 6: Network remains disabled ─────────────────────────────────────

    def test_network_disabled(self):
        """network_disabled must be True."""
        mock_client = self._make_mock_client(exit_code=0)
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"data")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        kwargs = mock_client.containers.run.call_args[1]
        self.assertTrue(kwargs.get("network_disabled"), "network_disabled must be True")

    # ── Test 7: Resource limits remain active ─────────────────────────────────

    def test_resource_limits_active(self):
        """mem_limit and nano_cpus must be set to non-trivially-permissive values."""
        mock_client = self._make_mock_client(exit_code=0)
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"data")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        kwargs = mock_client.containers.run.call_args[1]
        self.assertIn("mem_limit", kwargs, "mem_limit must be set")
        self.assertIn("nano_cpus", kwargs, "nano_cpus must be set")
        self.assertIsNotNone(kwargs["mem_limit"])
        self.assertIsNotNone(kwargs["nano_cpus"])

    # ── Test 8: Evidence is never executed (command safety) ───────────────────

    def test_evidence_never_executed(self):
        """
        The validation script must never exec, source, or eval the evidence file.
        Specifically it must not contain:  'exec', 'source', 'eval', or Python subprocess calls
        directed at the evidence path in a way that would run it.
        """
        mock_client = self._make_mock_client(exit_code=0)
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"data")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        kwargs = mock_client.containers.run.call_args[1]
        command = kwargs.get("command", [])
        script = " ".join(command) if isinstance(command, list) else str(command)

        # Script must not execute the evidence file
        # exec /evidence... or source /evidence... patterns are forbidden
        forbidden_patterns = [
            "exec /evidence",
            "source /evidence",
            "eval $(cat /evidence",
            "/evidence/file &&",
            "sh /evidence",
            "bash /evidence",
            "python /evidence",
            ". /evidence",  # POSIX 'source' equivalent
        ]
        for pat in forbidden_patterns:
            self.assertNotIn(pat, script,
                             f"Script must not contain execution pattern: '{pat}'")

    # ── Test 9: Container cleanup occurs after success ────────────────────────

    def test_container_cleanup_after_success(self):
        """container.remove(force=True) must be called after successful validation."""
        mock_client = self._make_mock_client(exit_code=0)
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"data")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        container = mock_client.containers.run.return_value
        container.remove.assert_called_once_with(force=True)

    # ── Test 10: Container cleanup occurs after failure ───────────────────────

    def test_container_cleanup_after_failure(self):
        """container.remove(force=True) must be called even when container exits non-zero."""
        mock_client = self._make_mock_client(exit_code=2, stderr_output=b"SANDBOX_ERROR: missing")
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"data")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        container = mock_client.containers.run.return_value
        container.remove.assert_called_once_with(force=True)

    # ── Test 11: Sandbox timeout produces a timeout flag ─────────────────────

    def test_sandbox_timeout_produces_flag(self):
        """If container.wait() raises (simulating timeout), a sandbox_timeout flag is returned."""
        mock_client = MagicMock()
        mock_container = MagicMock()
        mock_client.containers.run.return_value = mock_container
        mock_container.wait.side_effect = Exception("timeout waiting for container")

        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = RuntimeError  # won't match

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"data")
                tf_path = tf.name
            try:
                flags = self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        timeout_flags = [f for f in flags if "sandbox_timeout" in f]
        self.assertTrue(len(timeout_flags) > 0, f"Timeout must produce a sandbox_timeout flag; got: {flags}")
        # Container must still be removed even after timeout
        mock_container.remove.assert_called_once_with(force=True)

    # ── Test 12: Volume mount path contains the host evidence path ───────────

    def test_volume_mount_contains_evidence_path(self):
        """The evidence HOST path must appear as a key in the volumes dict."""
        mock_client = self._make_mock_client(exit_code=0)
        with patch("infrastructure.sandbox.intake_validator.docker") as mock_docker:
            mock_docker.from_env.return_value = mock_client
            mock_docker.errors.DockerException = Exception

            with tempfile.NamedTemporaryFile(suffix=".log", delete=False) as tf:
                tf.write(b"evidence bytes for path check")
                tf_path = tf.name
            try:
                self.iv.run_docker_sandbox(tf_path)
            finally:
                os.unlink(tf_path)

        kwargs = mock_client.containers.run.call_args[1]
        volumes = kwargs["volumes"]
        self.assertIn(tf_path, volumes,
                      f"Evidence host path {tf_path!r} must be in volumes dict keys")


# ══════════════════════════════════════════════════════════════════════════════
# Part C — Datetime Deprecation Cleanup Verification
# ══════════════════════════════════════════════════════════════════════════════

class TestDatetimeDeprecationCleanup(unittest.TestCase):
    """
    Verifies that production modules no longer use the deprecated
    datetime.utcnow() call.
    """

    def _grep_for_utcnow(self, filepath: str) -> list[int]:
        """Returns line numbers where datetime.utcnow() appears."""
        hits = []
        with open(filepath, "r", encoding="utf-8") as fh:
            for lineno, line in enumerate(fh, start=1):
                if "utcnow()" in line and not line.strip().startswith("#"):
                    hits.append(lineno)
        return hits

    def test_timestamp_service_no_utcnow(self):
        here = os.path.dirname(__file__)
        # Walk up to find the infrastructure directory
        ts_path = os.path.join(
            os.path.dirname(os.path.dirname(here)),
            "infrastructure", "integrity", "timestamp_service.py"
        )
        # Fallback: search relative to CWD
        if not os.path.exists(ts_path):
            ts_path = os.path.join("infrastructure", "integrity", "timestamp_service.py")
        if not os.path.exists(ts_path):
            self.skipTest(f"timestamp_service.py not found at {ts_path}")
        hits = self._grep_for_utcnow(ts_path)
        self.assertEqual(hits, [], f"datetime.utcnow() still used at lines {hits} in timestamp_service.py")

    def test_gateway_no_utcnow(self):
        here = os.path.dirname(__file__)
        gw_path = os.path.join(
            os.path.dirname(os.path.dirname(here)),
            "sanitization", "gateway.py"
        )
        if not os.path.exists(gw_path):
            gw_path = os.path.join("sanitization", "gateway.py")
        if not os.path.exists(gw_path):
            self.skipTest(f"gateway.py not found at {gw_path}")
        hits = self._grep_for_utcnow(gw_path)
        self.assertEqual(hits, [], f"datetime.utcnow() still used at lines {hits} in gateway.py")


if __name__ == "__main__":
    unittest.main()
