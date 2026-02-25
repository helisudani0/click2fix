import asyncio
import logging
from typing import Optional, Dict, Any
import aiohttp
from datetime import datetime
import json

logger = logging.getLogger(__name__)

class WazuhVulnerabilityScanner:
    def __init__(
        self,
        wazuh_api_url: str,
        username: str,
        password: str,
        verify_ssl: bool = True
    ):
        self.wazuh_api_url = wazuh_api_url.rstrip("/")
        self.username = username
        self.password = password
        self.verify_ssl = verify_ssl
        self.token: Optional[str] = None
        self.token_expiry: Optional[datetime] = None
    
    async def _authenticate(self) -> str:
        """Obtain JWT token from Wazuh API."""
        auth_url = f"{self.wazuh_api_url}/security/user/authenticate"
        auth = aiohttp.BasicAuth(self.username, self.password)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    auth_url,
                    auth=auth,
                    ssl=self.verify_ssl,
                    timeout=aiohttp.ClientTimeout(total=10)
                ) as response:
                    if response.status != 200:
                        raise RuntimeError(
                            f"Wazuh authentication failed: {response.status} {await response.text()}"
                        )
                    
                    data = await response.json()
                    self.token = data.get("data", {}).get("token")
                    
                    if not self.token:
                        raise RuntimeError("No token returned from Wazuh API")
                    
                    logger.info("Successfully authenticated with Wazuh API")
                    return self.token
        except asyncio.TimeoutError:
            raise RuntimeError("Wazuh API authentication timeout")
    
    async def _get_valid_token(self) -> str:
        """Get valid token, refreshing if necessary."""
        if not self.token or (self.token_expiry and datetime.utcnow() >= self.token_expiry):
            await self._authenticate()
        return self.token
    
    async def trigger_sca_rescan(
        self,
        agent_id: str,
        policy_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Trigger SCA (Security Configuration Assessment) rescan on specific agent.
        
        Args:
            agent_id: Wazuh agent ID (e.g., "001", "manager")
            policy_id: Optional specific policy to rescan
        
        Returns:
            Dict with status and scan details
        """
        token = await self._get_valid_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # Endpoint: POST /syscheck/{agent_id}/run
        rescan_url = f"{self.wazuh_api_url}/syscheck/{agent_id}/run"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    rescan_url,
                    headers=headers,
                    ssl=self.verify_ssl,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    data = await response.json()
                    
                    if response.status not in [200, 202]:
                        logger.error(f"SCA rescan failed: {response.status} {data}")
                        return {
                            "status": "failed",
                            "agent_id": agent_id,
                            "error": data.get("detail", "Unknown error"),
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    
                    logger.info(f"SCA rescan initiated for agent {agent_id}")
                    return {
                        "status": "rescan_initiated",
                        "agent_id": agent_id,
                        "scan_type": "syscheck",
                        "timestamp": datetime.utcnow().isoformat(),
                        "response": data.get("data", {})
                    }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "agent_id": agent_id,
                "error": "Wazuh API request timeout",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def trigger_vulnerability_scan(
        self,
        agent_id: str
    ) -> Dict[str, Any]:
        """
        Trigger vulnerability detection scan on specific agent.
        
        Args:
            agent_id: Wazuh agent ID
        
        Returns:
            Dict with status and scan details
        """
        token = await self._get_valid_token()
        
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        
        # Endpoint: POST /vulnerability/{agent_id}/run
        vuln_url = f"{self.wazuh_api_url}/vulnerability/{agent_id}/run"
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    vuln_url,
                    headers=headers,
                    json={},
                    ssl=self.verify_ssl,
                    timeout=aiohttp.ClientTimeout(total=15)
                ) as response:
                    data = await response.json()
                    
                    if response.status not in [200, 202]:
                        logger.error(f"Vulnerability scan failed: {response.status} {data}")
                        return {
                            "status": "failed",
                            "agent_id": agent_id,
                            "scan_type": "vulnerability",
                            "error": data.get("detail", "Unknown error"),
                            "timestamp": datetime.utcnow().isoformat()
                        }
                    
                    logger.info(f"Vulnerability scan initiated for agent {agent_id}")
                    return {
                        "status": "scan_initiated",
                        "agent_id": agent_id,
                        "scan_type": "vulnerability",
                        "timestamp": datetime.utcnow().isoformat(),
                        "response": data.get("data", {})
                    }
        except asyncio.TimeoutError:
            return {
                "status": "timeout",
                "agent_id": agent_id,
                "scan_type": "vulnerability",
                "error": "Wazuh API request timeout",
                "timestamp": datetime.utcnow().isoformat()
            }
    
    async def on_task_completion(
        self,
        agent_id: str,
        task_type: str,
        task_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Callback triggered upon task completion to initiate rescans.
        
        Args:
            agent_id: Wazuh agent ID
            task_type: Type of remediation task completed
            task_result: Execution result from standardized_output schema
        
        Returns:
            Combined rescan initiation status
        """
        if task_result.get("status") != "success":
            logger.info(f"Skipping rescan for failed task: {task_type}")
            return {"status": "skipped", "reason": "task_failed"}
        
        rescan_results = {}
        
        # Trigger SCA rescan for most remediation tasks
        if task_type in ["firewall_rule", "selinux_enforce", "package_update", "service_config"]:
            rescan_results["sca"] = await self.trigger_sca_rescan(agent_id)
        
        # Trigger vulnerability scan for package-related tasks
        if task_type in ["package_update", "patch_install"]:
            rescan_results["vulnerability"] = await self.trigger_vulnerability_scan(agent_id)
        
        logger.info(f"Rescan initiated post-task completion: {rescan_results}")
        return {
            "status": "rescans_initiated",
            "agent_id": agent_id,
            "task_type": task_type,
            "scans": rescan_results,
            "timestamp": datetime.utcnow().isoformat()
        }
