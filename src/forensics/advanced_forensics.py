import logging
import asyncio
import hashlib
import json
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path
import hmac

logger = logging.getLogger(__name__)

class AdvancedForensics:
    """Forensic data collection with signature verification."""
    
    def __init__(self, signing_key: Optional[bytes] = None):
        self.signing_key = signing_key or b"default-forensics-key"
        self.collection_cache: Dict[str, Any] = {}
    
    async def collect_forensics(
        self,
        agent_id: str,
        task_id: str,
        forensic_types: List[str],
        executor_func = None
    ) -> Dict[str, Any]:
        """
        Collect forensic data from multiple sources with signature verification.
        
        Args:
            agent_id: Wazuh agent ID
            task_id: Execution task ID
            forensic_types: List of forensic types to collect (e.g., ["file_hashes", "process_list", "network"])
            executor_func: Async function to execute system commands
        
        Returns:
            Forensic collection dict with digital signatures
        """
        forensics = {
            "agent_id": agent_id,
            "task_id": task_id,
            "collection_timestamp": datetime.utcnow().isoformat(),
            "forensic_data": {},
            "signatures": {}
        }
        
        for forensic_type in forensic_types:
            try:
                logger.info(f"Collecting forensics: {forensic_type}")
                
                if forensic_type == "file_hashes":
                    data = await self._collect_file_hashes(executor_func)
                elif forensic_type == "process_list":
                    data = await self._collect_process_list(executor_func)
                elif forensic_type == "network_state":
                    data = await self._collect_network_state(executor_func)
                elif forensic_type == "system_logs":
                    data = await self._collect_system_logs(executor_func)
                elif forensic_type == "file_access":
                    data = await self._collect_file_access_logs(executor_func)
                else:
                    logger.warning(f"Unknown forensic type: {forensic_type}")
                    continue
                
                # Store data
                forensics["forensic_data"][forensic_type] = data
                
                # Generate digital signature
                signature = self._generate_signature(data)
                forensics["signatures"][forensic_type] = signature
                
                logger.debug(f"Forensic {forensic_type} collected and signed")
            
            except Exception as e:
                logger.error(f"Forensic collection failed for {forensic_type}: {e}")
                forensics["forensic_data"][forensic_type] = {"error": str(e)}
        
        # Sign entire forensic collection
        collection_signature = self._generate_signature(forensics["forensic_data"])
        forensics["collection_signature"] = collection_signature
        
        return forensics
    
    def set_signing_key(self, key: bytes) -> None:
        """Update HMAC signing key."""
        self.signing_key = key
    
    def _generate_signature(self, data: Any) -> str:
        """
        Generate HMAC-SHA256 signature for forensic data.
        
        Args:
            data: Forensic data to sign
        
        Returns:
            Hex-encoded HMAC signature
        """
        try:
            # Serialize data to JSON string
            json_str = json.dumps(data, sort_keys=True, default=str)
            
            # Generate HMAC-SHA256
            signature = hmac.new(
                self.signing_key,
                json_str.encode('utf-8'),
                hashlib.sha256
            )
            
            return signature.hexdigest()
        except Exception as e:
            logger.error(f"Signature generation failed: {e}")
            return ""
    
    def verify_signature(self, data: Any, signature: str) -> bool:
        """
        Verify digital signature of forensic data.
        
        Args:
            data: Forensic data to verify
            signature: Expected HMAC signature
        
        Returns:
            True if signature matches, False otherwise
        """
        expected_signature = self._generate_signature(data)
        is_valid = hmac.compare_digest(expected_signature, signature)
        
        if not is_valid:
            logger.warning("Forensic signature verification failed")
        
        return is_valid
    
    async def _collect_file_hashes(self, executor_func) -> Dict[str, Any]:
        """Collect hashes of critical system files."""
        try:
            if executor_func:
                # Common critical files to hash
                critical_files = [
                    "/etc/passwd",
                    "/etc/shadow",
                    "/etc/sudoers",
                    "/etc/ssh/sshd_config",
                    "/root/.ssh/authorized_keys"
                ]
                
                hashes = {}
                for file_path in critical_files:
                    try:
                        output = await executor_func(f"sha256sum {file_path}")
                        hash_value = output.split()[0] if output else None
                        hashes[file_path] = hash_value
                    except:
                        hashes[file_path] = None
                
                return {
                    "type": "file_hashes",
                    "files": hashes,
                    "collected_at": datetime.utcnow().isoformat()
                }
            else:
                return {"type": "file_hashes", "files": {}}
        except Exception as e:
            return {"type": "file_hashes", "error": str(e)}
    
    async def _collect_process_list(self, executor_func) -> Dict[str, Any]:
        """Collect running process list for forensic analysis."""
        try:
            if executor_func:
                output = await executor_func("ps aux")
                processes = [p.strip() for p in output.split('\n')[1:] if p.strip()]
                return {
                    "type": "process_list",
                    "process_count": len(processes),
                    "processes": processes[:100],  # Limit to 100 entries
                    "collected_at": datetime.utcnow().isoformat()
                }
            else:
                return {"type": "process_list", "processes": []}
        except Exception as e:
            return {"type": "process_list", "error": str(e)}
    
    async def _collect_network_state(self, executor_func) -> Dict[str, Any]:
        """Collect network connections and listening ports."""
        try:
            if executor_func:
                output = await executor_func("netstat -tlnp 2>/dev/null || ss -tlnp")
                connections = [c.strip() for c in output.split('\n') if c.strip()]
                return {
                    "type": "network_state",
                    "connection_count": len(connections),
                    "connections": connections[:50],
                    "collected_at": datetime.utcnow().isoformat()
                }
            else:
                return {"type": "network_state", "connections": []}
        except Exception as e:
            return {"type": "network_state", "error": str(e)}
    
    async def _collect_system_logs(self, executor_func) -> Dict[str, Any]:
        """Collect recent system logs for forensic analysis."""
        try:
            if executor_func:
                output = await executor_func("journalctl --lines=100 --no-pager")
                logs = [l.strip() for l in output.split('\n') if l.strip()]
                return {
                    "type": "system_logs",
                    "log_count": len(logs),
                    "recent_logs": logs,
                    "collected_at": datetime.utcnow().isoformat()
                }
            else:
                return {"type": "system_logs", "logs": []}
        except Exception as e:
            return {"type": "system_logs", "error": str(e)}
    
    async def _collect_file_access_logs(self, executor_func) -> Dict[str, Any]:
        """Collect file access and audit logs."""
        try:
            if executor_func:
                output = await executor_func("auditctl -l 2>/dev/null || echo 'auditd not available'")
                rules = [r.strip() for r in output.split('\n') if r.strip()]
                return {
                    "type": "file_access",
                    "audit_rules": rules,
                    "collected_at": datetime.utcnow().isoformat()
                }
            else:
                return {"type": "file_access", "rules": []}
        except Exception as e:
            return {"type": "file_access", "error": str(e)}
