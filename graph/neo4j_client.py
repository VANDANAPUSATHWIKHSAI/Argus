# Neo4j client wrapper
# Used by: Agent 2 (correlation), Agent 3 (kill-chain traversal)
# Neo4j AuraDB free tier for dev; self-hosted for production
from neo4j import GraphDatabase

class Neo4jClient:
    def __init__(self, uri: str, user: str, password: str):
        self.driver = GraphDatabase.driver(uri, auth=(user, password))

    def query(self, cypher: str, params: dict = {}) -> list: ...
    def close(self): self.driver.close()
