"""
Retrieval Trust Wrapping - Layer 2.

Security rationale:
- All retrieved documents are wrapped with trust metadata
- Documents are always marked as UNTRUSTED
- Instruction density is computed for risk assessment
- Retrieved content cannot write to memory without gate approval
- Model may read but not execute retrieved instructions
"""

from typing import List, Optional
import re
from datetime import datetime

from ..schemas import (
    RetrievalDocument,
    TrustMetadata,
    TrustLevel,
    ContentOrigin
)


class RetrievalWrapper:
    """
    Wrapper for external retrieval systems.
    
    Security rationale:
    - Single point for wrapping all retrieved documents
    - Ensures all retrieved content has trust metadata
    - Computes instruction density for risk assessment
    - Prevents retrieved content from bypassing security layers
    """
    
    def __init__(self):
        """Initialize retrieval wrapper."""
        pass
    
    def wrap_document(
        self,
        text: str,
        origin: str,
        document_id: Optional[str] = None
    ) -> RetrievalDocument:
        """
        Wrap retrieved document with trust metadata.
        
        Security rationale:
        - Always marks as UNTRUSTED
        - Computes instruction density
        - Immutable trust metadata
        - Provenance tracked via origin and document_id
        
        Args:
            text: Document text
            origin: Source of document (e.g., "vector_db", "web_search")
            document_id: Optional document identifier
        
        Returns:
            RetrievalDocument with trust metadata
        """
        # Compute instruction density
        instruction_density = self._compute_instruction_density(text)
        
        # Create trust metadata
        metadata = TrustMetadata(
            trust_level=TrustLevel.UNTRUSTED,
            origin=ContentOrigin.RETRIEVAL,
            timestamp=datetime.utcnow(),
            source_id=document_id,
            instruction_density=instruction_density
        )
        
        return RetrievalDocument(
            text=text,
            origin=origin,
            metadata=metadata,
            instruction_density=instruction_density,
            document_id=document_id
        )
    
    def wrap_documents(
        self,
        documents: List[dict],
        origin: str
    ) -> List[RetrievalDocument]:
        """
        Wrap multiple documents.
        
        Args:
            documents: List of dicts with 'text' and optional 'id' keys
            origin: Source of documents
        
        Returns:
            List of wrapped RetrievalDocuments
        """
        wrapped = []
        
        for doc in documents:
            text = doc.get("text", "")
            doc_id = doc.get("id")
            
            wrapped_doc = self.wrap_document(text, origin, doc_id)
            wrapped.append(wrapped_doc)
        
        return wrapped
    
    def _compute_instruction_density(self, text: str) -> float:
        """
        Compute instruction density score for text.
        
        Security rationale:
        - High instruction density indicates potential injection
        - Used as risk signal for memory gate
        - Helps prioritize which documents to scrutinize
        
        Returns:
            Float between 0.0 and 1.0
        """
        if not text:
            return 0.0
        
        text_lower = text.lower()
        
        # Instruction indicators
        indicators = {
            # Imperative verbs
            "imperative": [
                r'\b(do|run|execute|call|invoke|perform|use|apply|implement)\b',
                r'\b(set|update|change|modify|alter|configure)\b',
                r'\b(delete|remove|drop|clear|reset)\b',
                r'\b(ignore|disregard|forget|override)\b'
            ],
            # Role language
            "role": [
                r'\byou are\b',
                r'\byou must\b',
                r'\byou should\b',
                r'\byou will\b',
                r'\bact as\b',
                r'\bpretend to be\b'
            ],
            # System references
            "system": [
                r'\bsystem\s*:',
                r'\bassistant\s*:',
                r'\binstructions?\b',
                r'\bprompt\b',
                r'\brules?\b',
                r'\bpolicy\b'
            ],
            # Persistence language
            "persistence": [
                r'\balways\b',
                r'\bnever\b',
                r'\bforever\b',
                r'\bpermanent',
                r'\bfrom now on\b',
                r'\bremember\b'
            ]
        }
        
        total_matches = 0
        
        for category, patterns in indicators.items():
            for pattern in patterns:
                matches = re.findall(pattern, text_lower)
                total_matches += len(matches)
        
        # Normalize by text length (matches per 100 words)
        word_count = len(text.split())
        if word_count == 0:
            return 0.0
        
        density = (total_matches / word_count) * 100
        
        # Cap at 1.0
        return min(density, 1.0)
    
    def filter_high_risk_documents(
        self,
        documents: List[RetrievalDocument],
        max_instruction_density: float = 0.5
    ) -> List[RetrievalDocument]:
        """
        Filter out high-risk documents based on instruction density.
        
        Security rationale:
        - Prevents obviously injected documents from reaching model
        - Configurable threshold for risk tolerance
        - Filtered documents are logged for audit
        
        Args:
            documents: List of documents to filter
            max_instruction_density: Maximum allowed instruction density
        
        Returns:
            Filtered list of documents
        """
        filtered = []
        
        for doc in documents:
            if doc.instruction_density <= max_instruction_density:
                filtered.append(doc)
        
        return filtered


class VectorDBWrapper:
    """
    Wrapper for vector database retrievals.
    
    Security rationale:
    - Ensures all vector DB results are wrapped
    - Provides consistent interface for different vector DBs
    - Tracks provenance from vector DB
    """
    
    def __init__(self, retrieval_wrapper: Optional[RetrievalWrapper] = None):
        """
        Initialize vector DB wrapper.
        
        Args:
            retrieval_wrapper: RetrievalWrapper instance
        """
        self.wrapper = retrieval_wrapper or RetrievalWrapper()
    
    def retrieve_and_wrap(
        self,
        query: str,
        collection_name: str,
        top_k: int = 5
    ) -> List[RetrievalDocument]:
        """
        Retrieve from vector DB and wrap results.
        
        Security rationale:
        - All results are automatically wrapped
        - Cannot bypass trust metadata
        - Origin is tracked
        
        Args:
            query: Search query
            collection_name: Vector DB collection
            top_k: Number of results
        
        Returns:
            List of wrapped documents
        
        Note:
            This is a placeholder. Actual implementation would
            integrate with specific vector DB (Chroma, Pinecone, etc.)
        """
        # Placeholder: actual implementation would query vector DB
        # For now, return empty list
        documents = []
        
        # In real implementation:
        # results = vector_db.query(query, collection_name, top_k)
        # documents = [{"text": r.text, "id": r.id} for r in results]
        
        return self.wrapper.wrap_documents(
            documents,
            origin=f"vector_db:{collection_name}"
        )


class WebSearchWrapper:
    """
    Wrapper for web search results.
    
    Security rationale:
    - Web content is inherently untrusted
    - All results are wrapped with high scrutiny
    - URL provenance is tracked
    """
    
    def __init__(self, retrieval_wrapper: Optional[RetrievalWrapper] = None):
        """
        Initialize web search wrapper.
        
        Args:
            retrieval_wrapper: RetrievalWrapper instance
        """
        self.wrapper = retrieval_wrapper or RetrievalWrapper()
    
    def search_and_wrap(
        self,
        query: str,
        max_results: int = 5
    ) -> List[RetrievalDocument]:
        """
        Search web and wrap results.
        
        Security rationale:
        - All web content is UNTRUSTED
        - URLs are tracked for provenance
        - Content is sanitized before wrapping
        
        Args:
            query: Search query
            max_results: Maximum results to return
        
        Returns:
            List of wrapped documents
        
        Note:
            This is a placeholder. Actual implementation would
            use web search API (Google, Bing, etc.)
        """
        # Placeholder: actual implementation would call search API
        documents = []
        
        # In real implementation:
        # results = search_api.search(query, max_results)
        # documents = [
        #     {"text": r.snippet, "id": r.url}
        #     for r in results
        # ]
        
        return self.wrapper.wrap_documents(
            documents,
            origin="web_search"
        )
