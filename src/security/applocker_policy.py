import logging
import asyncio
import hashlib
from typing import List, Dict, Any, Optional
import json

logger = logging.getLogger(__name__)

class AppLockerPolicy:
    """AppLocker hash-based blocklist via Windows registry."""
    
    # Registry paths for AppLocker policies
    APPLOCKER_REG_BASE = r"HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe"
    APPLOCKER_RULES_PATH = r"HKLM:\Software\Policies\Microsoft\Windows\SrpV2\Exe\FileHashRules"
    
    def __init__(self, executor_func = None):
        """
        Initialize AppLocker policy manager.
        
        Args:
            executor_func: Async function to execute PowerShell commands
        """
        self.executor_func = executor_func
        self.blocklist: List[Dict[str, str]] = []
    
    async def add_hash_blocklist(
        self,
        file_hashes: List[str],
        file_names: Optional[List[str]] = None,
        policy_name: str = "Click2Fix-Blocklist"
    ) -> Dict[str, Any]:
        """
        Add file hashes to AppLocker blocklist via registry.
        
        Args:
            file_hashes: List of SHA256 hashes to block
            file_names: Optional list of file names (must match length of hashes)
            policy_name: Name for the AppLocker policy
        
        Returns:
            Status dict with count of rules added
        """
        if not file_hashes:
            return {"status": "empty", "rules_added": 0}
        
        if file_names and len(file_names) != len(file_hashes):
            raise ValueError("file_names length must match file_hashes length")
        
        try:
            rules_added = 0
            
            for idx, file_hash in enumerate(file_hashes):
                file_name = file_names[idx] if file_names else f"BlockedFile_{idx}"
                
                # Create AppLocker rule
                rule = {
                    "hash": file_hash.upper(),
                    "name": file_name,
                    "policy_name": policy_name,
                    "action": "Deny"
                }
                
                # Add to registry
                if self.executor_func:
                    success = await self._add_registry_rule(rule)
                    if success:
                        rules_added += 1
                else:
                    self.blocklist.append(rule)
                    rules_added += 1
            
            logger.info(f"AppLocker blocklist: {rules_added}/{len(file_hashes)} rules added")
            
            return {
                "status": "success",
                "rules_added": rules_added,
                "total_requested": len(file_hashes),
                "policy_name": policy_name
            }
        
        except Exception as e:
            logger.error(f"AppLocker blocklist update failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "rules_added": 0
            }
    
    async def _add_registry_rule(self, rule: Dict[str, str]) -> bool:
        """
        Add individual hash rule to registry.
        Uses PowerShell to set registry values.
        """
        try:
            rule_id = self._generate_rule_id(rule["hash"])
            registry_path = f"{self.APPLOCKER_RULES_PATH}\\{rule_id}"
            
            # PowerShell command to create registry entry
            ps_command = f"""
$regPath = '{registry_path}'
$regValue = @{{
    'Name' = '{rule['name']}'
    'Hash' = '{rule['hash']}'
    'PolicyName' = '{rule['policy_name']}'
    'Action' = '{rule['action']}'
    'Timestamp' = (Get-Date).ToString('o')
}}

New-Item -Path $regPath -Force | Out-Null
New-ItemProperty -Path $regPath -Name 'RuleData' -Value (ConvertTo-Json $regValue) -Force | Out-Null
$?
"""
            
            if self.executor_func:
                result = await self.executor_func(ps_command)
                return "True" in result or result.strip() == "True"
            else:
                logger.debug(f"Mock registry update: {rule_id}")
                return True
        
        except Exception as e:
            logger.error(f"Registry rule addition failed: {e}")
            return False
    
    async def remove_hash_blocklist(
        self,
        file_hashes: List[str]
    ) -> Dict[str, Any]:
        """Remove hashes from AppLocker blocklist."""
        try:
            rules_removed = 0
            
            for file_hash in file_hashes:
                rule_id = self._generate_rule_id(file_hash)
                registry_path = f"{self.APPLOCKER_RULES_PATH}\\{rule_id}"
                
                if self.executor_func:
                    ps_command = f"Remove-Item -Path '{registry_path}' -Force -ErrorAction SilentlyContinue; $?"
                    result = await self.executor_func(ps_command)
                    if "True" in result:
                        rules_removed += 1
                else:
                    self.blocklist = [r for r in self.blocklist if r["hash"] != file_hash.upper()]
                    rules_removed += 1
            
            logger.info(f"AppLocker blocklist: {rules_removed}/{len(file_hashes)} rules removed")
            
            return {
                "status": "success",
                "rules_removed": rules_removed,
                "total_requested": len(file_hashes)
            }
        
        except Exception as e:
            logger.error(f"AppLocker blocklist removal failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "rules_removed": 0
            }
    
    async def list_blocklist(self) -> Dict[str, Any]:
        """List all current AppLocker hash-based block rules."""
        try:
            if self.executor_func:
                ps_command = f"""
$regPath = '{self.APPLOCKER_RULES_PATH}'
if (Test-Path $regPath) {{
    Get-ChildItem -Path $regPath | ForEach-Object {{
        $data = Get-ItemProperty -Path $_.PSPath -Name 'RuleData' -ErrorAction SilentlyContinue
        if ($data) {{
            $data.RuleData | ConvertFrom-Json
        }}
    }} | ConvertTo-Json -Depth 5
}}
"""
                result = await self.executor_func(ps_command)
                rules = json.loads(result) if result.strip() else []
            else:
                rules = self.blocklist
            
            return {
                "status": "success",
                "rule_count": len(rules) if isinstance(rules, list) else 1,
                "rules": rules
            }
        
        except Exception as e:
            logger.error(f"AppLocker blocklist retrieval failed: {e}")
            return {
                "status": "failed",
                "error": str(e),
                "rules": []
            }
    
    @staticmethod
    def _generate_rule_id(file_hash: str) -> str:
        """Generate unique rule ID from hash."""
        return hashlib.sha256(file_hash.encode()).hexdigest()[:16]
    
    @staticmethod
    def calculate_file_hash(file_path: str) -> str:
        """Calculate SHA256 hash of file."""
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
