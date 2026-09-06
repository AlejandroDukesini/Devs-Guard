import httpx
import asyncio
from typing import List, Dict, Any

OSV_API_URL = "https://api.osv.dev/v1/query"

async def check_vulnerability(client: httpx.AsyncClient, dep: Dict[str, str]) -> Dict[str, Any]:
    """Consulta la API de OSV.dev para una dependencia especifica."""
    payload = {
        "version": dep["version"],
        "package": {
            "name": dep["name"],
            "ecosystem": dep["ecosystem"]
        }
    }
    
    try:
        response = await client.post(OSV_API_URL, json=payload, timeout=10.0)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            return {
                "name": dep["name"],
                "version": dep["version"],
                "ecosystem": dep["ecosystem"],
                "vulnerabilities": vulns
            }
    except Exception as e:
        pass

    return {
        "name": dep["name"],
        "version": dep["version"],
        "ecosystem": dep["ecosystem"],
        "vulnerabilities": []
    }

async def scan_dependencies(dependencies: List[Dict[str, str]]) -> List[Dict[str, Any]]:
    """Analiza múltiples dependencias en paralelo usando httpx asíncrono."""
    async with httpx.AsyncClient() as client:
        tasks = [check_vulnerability(client, dep) for dep in dependencies]
        results = await asyncio.gather(*tasks)
        return results