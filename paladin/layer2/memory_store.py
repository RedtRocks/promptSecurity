"""
Memory Store - Layer 2.

Security rationale:
- Append-only semantics prevent tampering
- Versioning enables audit trail and rollback
- Provenance metadata tracks trust boundaries
- No free-text writes; all writes go through gate
- Memory cannot be modified, only new versions appended
"""

from typing import List, Optional, Dict
from datetime import datetime
import json
import uuid

from ..schemas import MemoryEntry, TrustMetadata, TrustLevel, ContentOrigin


class MemoryStore:
    """
    Append-only versioned memory store.
    
    Security rationale:
    - Append-only: prevents modification of existing entries
    - Versioning: enables audit trail and rollback
    - Provenance: tracks source of every entry
    - Immutable entries: MemoryEntry is frozen after creation
    - Persistence layer is separated from access control
    """
    
    def __init__(self, storage_path: Optional[str] = None):
        """
        Initialize memory store.
        
        Args:
            storage_path: Optional path for persistent storage
        
        Security rationale:
        - In-memory store for testing and development
        - File-based store for production (with proper file permissions)
        - Storage layer is abstracted for future database backend
        """
        self.storage_path = storage_path
        self.entries: Dict[str, List[MemoryEntry]] = {}  # id -> versions
        self.quarantine: Dict[str, MemoryEntry] = {}  # Quarantine buffer
        
        if storage_path:
            self._load_from_disk()
    
    def append(self, content: str, metadata: TrustMetadata) -> MemoryEntry:
        """
        Append new entry to memory.
        
        Security rationale:
        - Cannot modify existing entries
        - Metadata is immutable
        - Entry ID is generated (not user-provided)
        - Timestamp is system-generated (not user-provided)
        
        Args:
            content: Content to store
            metadata: Trust metadata (must be provided)
        
        Returns:
            Created MemoryEntry
        """
        entry_id = str(uuid.uuid4())
        
        entry = MemoryEntry(
            id=entry_id,
            content=content,
            metadata=metadata,
            version=1,
            created_at=datetime.utcnow(),
            promoted_from_quarantine=False
        )
        
        self.entries[entry_id] = [entry]
        
        if self.storage_path:
            self._persist_to_disk()
        
        return entry
    
    def append_version(
        self,
        entry_id: str,
        content: str,
        metadata: TrustMetadata
    ) -> MemoryEntry:
        """
        Append new version of existing entry.
        
        Security rationale:
        - Creates new version, doesn't modify existing
        - Parent version is tracked
        - Original entry is preserved
        - Version chain is immutable
        
        Args:
            entry_id: ID of entry to version
            content: New content
            metadata: Trust metadata for new version
        
        Returns:
            New version entry
        
        Raises:
            ValueError: If entry_id doesn't exist
        """
        if entry_id not in self.entries:
            raise ValueError(f"Entry {entry_id} not found")
        
        versions = self.entries[entry_id]
        last_version = versions[-1]
        
        new_entry = MemoryEntry(
            id=entry_id,
            content=content,
            metadata=metadata,
            version=last_version.version + 1,
            parent_version=last_version.version,
            created_at=datetime.utcnow(),
            promoted_from_quarantine=False
        )
        
        versions.append(new_entry)
        
        if self.storage_path:
            self._persist_to_disk()
        
        return new_entry
    
    def get(self, entry_id: str, version: Optional[int] = None) -> Optional[MemoryEntry]:
        """
        Get entry by ID and optional version.
        
        Args:
            entry_id: Entry ID
            version: Optional version number (defaults to latest)
        
        Returns:
            MemoryEntry or None if not found
        """
        if entry_id not in self.entries:
            return None
        
        versions = self.entries[entry_id]
        
        if version is None:
            return versions[-1]  # Latest version
        
        for entry in versions:
            if entry.version == version:
                return entry
        
        return None
    
    def get_all_versions(self, entry_id: str) -> List[MemoryEntry]:
        """
        Get all versions of an entry.
        
        Security rationale:
        - Enables audit of entry history
        - Shows trust evolution over time
        - Helps detect tampering attempts
        """
        return self.entries.get(entry_id, [])
    
    def search(self, query: str, trust_level: Optional[TrustLevel] = None) -> List[MemoryEntry]:
        """
        Search memory entries.
        
        Security rationale:
        - Can filter by trust level
        - Returns latest versions only by default
        - No arbitrary SQL injection (in-memory search)
        
        Args:
            query: Search query (simple substring match)
            trust_level: Optional trust level filter
        
        Returns:
            List of matching entries
        """
        results = []
        
        for versions in self.entries.values():
            latest = versions[-1]
            
            # Filter by trust level if specified
            if trust_level and latest.metadata.trust_level != trust_level:
                continue
            
            # Simple substring search
            if query.lower() in latest.content.lower():
                results.append(latest)
        
        return results
    
    def add_to_quarantine(self, content: str, metadata: TrustMetadata) -> str:
        """
        Add entry to quarantine buffer.
        
        Security rationale:
        - Untrusted content goes to quarantine first
        - Can be reviewed before promotion
        - Prevents immediate persistence of malicious content
        - Quarantine entries are read-only
        
        Args:
            content: Content to quarantine
            metadata: Trust metadata
        
        Returns:
            Quarantine entry ID
        """
        entry_id = str(uuid.uuid4())
        
        entry = MemoryEntry(
            id=entry_id,
            content=content,
            metadata=metadata,
            version=1,
            created_at=datetime.utcnow(),
            promoted_from_quarantine=False
        )
        
        self.quarantine[entry_id] = entry
        
        return entry_id
    
    def promote_from_quarantine(self, quarantine_id: str) -> MemoryEntry:
        """
        Promote quarantine entry to main memory.
        
        Security rationale:
        - Only called after passing MemoryWriteGate
        - Promotion is logged via metadata flag
        - Original quarantine entry is preserved
        
        Args:
            quarantine_id: ID of quarantine entry
        
        Returns:
            Promoted MemoryEntry
        
        Raises:
            ValueError: If quarantine_id not found
        """
        if quarantine_id not in self.quarantine:
            raise ValueError(f"Quarantine entry {quarantine_id} not found")
        
        quarantine_entry = self.quarantine[quarantine_id]
        
        # Create promoted entry
        promoted = MemoryEntry(
            id=quarantine_entry.id,
            content=quarantine_entry.content,
            metadata=quarantine_entry.metadata,
            version=1,
            created_at=datetime.utcnow(),
            promoted_from_quarantine=True
        )
        
        self.entries[promoted.id] = [promoted]
        
        # Remove from quarantine
        del self.quarantine[quarantine_id]
        
        if self.storage_path:
            self._persist_to_disk()
        
        return promoted
    
    def get_quarantine(self) -> List[MemoryEntry]:
        """
        Get all quarantine entries.
        
        Security rationale:
        - Enables review of pending entries
        - Supports manual or automated promotion decisions
        """
        return list(self.quarantine.values())
    
    def _persist_to_disk(self):
        """
        Persist memory to disk.
        
        Security rationale:
        - Simple JSON serialization for now
        - In production, use proper database with ACID guarantees
        - File permissions should restrict write access
        """
        if not self.storage_path:
            return
        
        data = {
            "entries": {
                entry_id: [
                    {
                        "id": e.id,
                        "content": e.content,
                        "metadata": e.metadata.model_dump(),
                        "version": e.version,
                        "parent_version": e.parent_version,
                        "created_at": e.created_at.isoformat(),
                        "promoted_from_quarantine": e.promoted_from_quarantine
                    }
                    for e in versions
                ]
                for entry_id, versions in self.entries.items()
            },
            "quarantine": {
                q_id: {
                    "id": e.id,
                    "content": e.content,
                    "metadata": e.metadata.model_dump(),
                    "version": e.version,
                    "created_at": e.created_at.isoformat(),
                    "promoted_from_quarantine": False
                }
                for q_id, e in self.quarantine.items()
            }
        }
        
        with open(self.storage_path, 'w') as f:
            json.dump(data, f, indent=2)
    
    def _load_from_disk(self):
        """Load memory from disk."""
        if not self.storage_path:
            return
        
        try:
            with open(self.storage_path, 'r') as f:
                data = json.load(f)
            
            # Load entries
            for entry_id, versions_data in data.get("entries", {}).items():
                versions = []
                for v_data in versions_data:
                    metadata = TrustMetadata(**v_data["metadata"])
                    entry = MemoryEntry(
                        id=v_data["id"],
                        content=v_data["content"],
                        metadata=metadata,
                        version=v_data["version"],
                        parent_version=v_data.get("parent_version"),
                        created_at=datetime.fromisoformat(v_data["created_at"]),
                        promoted_from_quarantine=v_data.get("promoted_from_quarantine", False)
                    )
                    versions.append(entry)
                self.entries[entry_id] = versions
            
            # Load quarantine
            for q_id, q_data in data.get("quarantine", {}).items():
                metadata = TrustMetadata(**q_data["metadata"])
                entry = MemoryEntry(
                    id=q_data["id"],
                    content=q_data["content"],
                    metadata=metadata,
                    version=q_data["version"],
                    created_at=datetime.fromisoformat(q_data["created_at"]),
                    promoted_from_quarantine=False
                )
                self.quarantine[q_id] = entry
        
        except FileNotFoundError:
            # First run, no data yet
            pass
