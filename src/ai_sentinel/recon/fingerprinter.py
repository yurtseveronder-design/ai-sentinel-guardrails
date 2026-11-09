"""
Attack Surface Fingerprinting module for AI-Sentinel Guardrails.
Performs rapid concurrent reconnaissance, security header analysis, technology stack detection,
and sensitive endpoint discovery.
"""

import urllib.request
import urllib.error
import ssl
import concurrent.futures
from typing import Dict, Any, List

class AttackSurfaceFingerprinter:
    SENSITIVE_PATHS = [
        "/admin",
        "/swagger.json",
        "/openapi.json",
        "/.env",
        "/.git/config",
        "/metrics",
        "/health",
        "/api/docs",
        "/graphql"
    ]

    @classmethod
    def _probe_path(cls, base_url: str, path: str) -> Dict[str, Any]:
        test_url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(
                test_url,
                headers={"User-Agent": "AISentinel-Fingerprinter/2.0"}
            )
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(req, context=context, timeout=3) as resp:
                if resp.status == 200:
                    risk_level = "High" if path in ["/.env", "/.git/config"] else "Medium"
                    return {
                        "path": path,
                        "status_code": resp.status,
                        "risk": risk_level
                    }
        except Exception:
            pass
        return None

    @classmethod
    def fingerprint(cls, target_url: str) -> Dict[str, Any]:
        results = {
            "target": target_url,
            "headers": {},
            "security_score": 100,
            "vulnerabilities": [],
            "discovered_endpoints": [],
            "technologies": []
        }

        # 1. Analyze Headers and Base Response
        try:
            req = urllib.request.Request(
                target_url,
                headers={"User-Agent": "AISentinel-Fingerprinter/2.0"}
            )
            context = ssl._create_unverified_context()
            with urllib.request.urlopen(req, context=context, timeout=5) as response:
                headers = dict(response.headers)
                results["headers"] = headers
                results["status_code"] = response.status

                server = headers.get("Server", "")
                if server:
                    results["technologies"].append(server)
                
                powered_by = headers.get("X-Powered-By", "")
                if powered_by:
                    results["technologies"].append(powered_by)

                security_headers = [
                    "Strict-Transport-Security",
                    "Content-Security-Policy",
                    "X-Frame-Options",
                    "X-Content-Type-Options"
                ]
                for h in security_headers:
                    if h not in headers:
                        results["security_score"] -= 15
                        results["vulnerabilities"].append(f"Missing security header: {h}")

        except urllib.error.HTTPError as e:
            results["status_code"] = e.code
        except Exception as e:
            results["error"] = str(e)
            return results

        # 2. Concurrent Probing of Sensitive Endpoints
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {
                executor.submit(cls._probe_path, target_url, path): path 
                for path in cls.SENSITIVE_PATHS
            }
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results["discovered_endpoints"].append(res)
                    if res["risk"] == "High":
                        results["security_score"] -= 25

        # Clamp security score between 0 and 100
        results["security_score"] = max(0, results["security_score"])
        return results