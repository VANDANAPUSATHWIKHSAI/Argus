"""
Neo4j Client Wrapper for ARGUS Layer 3 Deterministic Analysis & Graph Correlation
===================================================================================
Provides parameterized Cypher query execution, GDS operation support,
connection health verification, and resource management.
"""

import logging
from typing import Any, Optional, Dict, List
from neo4j import GraphDatabase, Driver

logger = logging.getLogger(__name__)


class Neo4jClient:
    """
    Thread-safe Neo4j driver wrapper for Layer 3 graph correlation and GDS analytics.
    Enforces Cypher parameterization to prevent injection vulnerabilities.
    """

    def __init__(self, uri: str, user: str, password: str, database: str = "neo4j") -> None:
        self._uri = uri
        self._user = user
        self._database = database
        try:
            self.driver: Driver = GraphDatabase.driver(uri, auth=(user, password))
        except Exception as exc:
            logger.error("Failed to initialize Neo4j driver for %s: %s", uri, exc)
            self.driver = None

    def query(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute a parameterized Cypher query and return a list of record dictionaries.
        """
        if not self.driver:
            raise RuntimeError("Neo4j driver is uninitialized or disconnected.")

        parameters = params or {}
        records_out: List[Dict[str, Any]] = []

        try:
            with self.driver.session(database=self._database) as session:
                result = session.run(cypher, parameters)
                for record in result:
                    records_out.append(record.data())
        except Exception as exc:
            logger.error("Neo4j Cypher query execution failed: %s | Query: %s", exc, cypher)
            raise RuntimeError(f"Neo4j Cypher execution error: {exc}") from exc

        return records_out

    def execute_write(self, cypher: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        Execute a parameterized write query within an explicit write transaction.
        """
        if not self.driver:
            raise RuntimeError("Neo4j driver is uninitialized or disconnected.")

        parameters = params or {}

        def _write_tx(tx):
            res = tx.run(cypher, parameters)
            return [rec.data() for rec in res]

        try:
            with self.driver.session(database=self._database) as session:
                return session.execute_write(_write_tx)
        except Exception as exc:
            logger.error("Neo4j write transaction failed: %s | Query: %s", exc, cypher)
            raise RuntimeError(f"Neo4j write transaction error: {exc}") from exc

    def verify_connectivity(self) -> bool:
        """Verify live connectivity to the Neo4j database instance."""
        if not self.driver:
            return False
        try:
            self.driver.verify_connectivity()
            return True
        except Exception as exc:
            logger.warning("Neo4j connectivity check failed: %s", exc)
            return False

    def close(self) -> None:
        """Close driver connection pool."""
        if self.driver:
            try:
                self.driver.close()
            except Exception as exc:
                logger.warning("Error closing Neo4j driver: %s", exc)

