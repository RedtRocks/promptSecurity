"""
Gateway integration for logging and future enforcement.

Security rationale:
- Gateway acts as architectural choke point
- All LLM requests pass through gateway
- Provides logging boundary for audit
- Future enforcement point for tool permissions
- Enables centralized policy enforcement
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
import json


class GatewayClient:
    """
    Client for interacting with Trylon Gateway.
    
    Security rationale:
    - Single point for all LLM requests
    - Enables request/response logging
    - Future enforcement of tool permissions
    - Provides visibility into all LLM interactions
    """
    
    def __init__(self, gateway_url: Optional[str] = None):
        """
        Initialize gateway client.
        
        Args:
            gateway_url: Optional gateway URL (default: local gateway)
        """
        self.gateway_url = gateway_url or "http://localhost:8000"
        self.request_log: List[Dict[str, Any]] = []
    
    def log_request(
        self,
        messages: List[Dict[str, str]],
        metadata: Dict[str, Any]
    ):
        """
        Log LLM request through gateway.
        
        Security rationale:
        - Records all requests for audit
        - Includes trust metadata for analysis
        - Enables detection of attack patterns
        - Supports incident response
        
        Args:
            messages: Message list being sent to LLM
            metadata: Additional metadata (trust levels, risk classifications, etc.)
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "messages": messages,
            "metadata": metadata,
            "request_id": self._generate_request_id()
        }
        
        self.request_log.append(log_entry)
        
        # In production, would send to actual gateway
        # self._send_to_gateway(log_entry)
    
    def log_response(
        self,
        request_id: str,
        response: str,
        metadata: Dict[str, Any]
    ):
        """
        Log LLM response through gateway.
        
        Security rationale:
        - Records model outputs for audit
        - Enables detection of prompt leaks
        - Supports output validation analysis
        
        Args:
            request_id: ID of original request
            response: Model response
            metadata: Additional metadata
        """
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "request_id": request_id,
            "response": response,
            "metadata": metadata
        }
        
        self.request_log.append(log_entry)
        
        # In production, would send to actual gateway
        # self._send_to_gateway(log_entry)
    
    def _generate_request_id(self) -> str:
        """Generate unique request ID."""
        import uuid
        return str(uuid.uuid4())
    
    def _send_to_gateway(self, log_entry: Dict[str, Any]):
        """
        Send log entry to gateway.
        
        Note: Placeholder for actual gateway integration
        """
        # In production, use httpx to send to gateway
        # import httpx
        # response = httpx.post(
        #     f"{self.gateway_url}/log",
        #     json=log_entry
        # )
        pass
    
    def get_request_log(self) -> List[Dict[str, Any]]:
        """
        Get request log.
        
        Returns:
            List of logged requests/responses
        """
        return self.request_log
    
    def export_log(self, filepath: str):
        """
        Export request log to file.
        
        Security rationale:
        - Enables offline audit
        - Supports compliance requirements
        - Provides evidence for incident response
        
        Args:
            filepath: Path to export log
        """
        with open(filepath, 'w') as f:
            json.dump(self.request_log, f, indent=2)


class RequestLogger:
    """
    Request logger for PALADIN operations.
    
    Security rationale:
    - Logs all security-relevant operations
    - Tracks intake, classification, memory operations
    - Provides comprehensive audit trail
    """
    
    def __init__(self, gateway_client: Optional[GatewayClient] = None):
        """
        Initialize request logger.
        
        Args:
            gateway_client: Optional gateway client
        """
        self.gateway = gateway_client or GatewayClient()
        self.operation_log: List[Dict[str, Any]] = []
    
    def log_intake(
        self,
        raw_input: str,
        risk_classification: Dict[str, Any],
        rewritten: Optional[str] = None
    ):
        """
        Log intake pipeline operation.
        
        Args:
            raw_input: Original user input
            risk_classification: Risk classification result
            rewritten: Optional rewritten content
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": "intake",
            "raw_input": raw_input[:200],  # Truncate for log
            "risk_classification": risk_classification,
            "rewritten": rewritten[:200] if rewritten else None
        }
        
        self.operation_log.append(entry)
    
    def log_memory_write(
        self,
        content: str,
        allowed: bool,
        reason: Optional[str] = None
    ):
        """
        Log memory write attempt.
        
        Args:
            content: Content to be written
            allowed: Whether write was allowed
            reason: Optional reason for decision
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": "memory_write",
            "content_preview": content[:100],
            "allowed": allowed,
            "reason": reason
        }
        
        self.operation_log.append(entry)
    
    def log_retrieval(
        self,
        origin: str,
        document_count: int,
        avg_instruction_density: float
    ):
        """
        Log retrieval operation.
        
        Args:
            origin: Source of retrieval
            document_count: Number of documents retrieved
            avg_instruction_density: Average instruction density
        """
        entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "operation": "retrieval",
            "origin": origin,
            "document_count": document_count,
            "avg_instruction_density": avg_instruction_density
        }
        
        self.operation_log.append(entry)
    
    def get_operation_log(self) -> List[Dict[str, Any]]:
        """Get operation log."""
        return self.operation_log
    
    def export_log(self, filepath: str):
        """Export operation log to file."""
        with open(filepath, 'w') as f:
            json.dump(self.operation_log, f, indent=2)
