import requests
from config import ABUSEIPDB_API_KEY

BASE_URL = "https://api.abuseipdb.com/api/v2/check"

def abuse_check(ip: str) -> dict:
    try:
        headers = {
            "Key": ABUSEIPDB_API_KEY,
            "Accept": "application/json"
        }

        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90
        }

        response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)

        if response.status_code != 200:
            return {"error": f"HTTP {response.status_code}", "raw": response.text}

        data = response.json().get("data", {})

        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports"),
            "last_reported": data.get("lastReportedAt"),
        }

    except Exception as e:
        return {"error": str(e)}
