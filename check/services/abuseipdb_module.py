from __future__ import annotations
from datetime import datetime
import tomllib
from aiohttp import ClientSession
from check.utils import format_iso_date
from check.services.service_module import ServiceHandler


class AbuseIPDBData:
    """Class for storing data received from AbuseIPDB"""

    def __init__(
        self,
        is_whitelisted,
        abuse_confidence_score,
        usage_type,
        domain,
        hostnames,
        is_tor,
        total_reports,
        reports,
        last_reported_at,
    ) -> None:
        self._is_whitelisted = is_whitelisted
        self._abuse_confidence_score = abuse_confidence_score
        self._usage_type = usage_type
        self._domain = domain
        self._hostnames = hostnames
        self._is_tor = is_tor
        self._total_reports = total_reports
        self._reports = reports
        self._last_reported_at = last_reported_at

    @classmethod
    def from_json(cls, json_data: dict) -> AbuseIPDBData:
        """Creates a class instance based on json data received via API"""
        return cls(
            is_whitelisted=json_data.get("isWhitelisted", False),
            abuse_confidence_score=json_data.get("abuseConfidenceScore"),
            usage_type=json_data.get("usageType"),
            domain=json_data.get("domain"),
            hostnames=json_data.get("hostnames"),
            is_tor=json_data.get("isTor"),
            total_reports=json_data.get("totalReports"),
            reports=json_data.get("reports"),
            last_reported_at=json_data.get("lastReportedAt", ""),
        )

    @property
    def is_whitelisted(self) -> bool:
        """Describes whether the address is present in the AbuseIPDB whitelist"""
        return self._is_whitelisted

    @property
    def abuse_confidence_score(self) -> int:
        """Contains 'Confidence of Abuse' of the address"""
        return self._abuse_confidence_score

    @property
    def usage_type(self) -> str:
        """Contains usage type of the address, like 'Content Delivery Network'"""
        return self._usage_type

    @property
    def domain(self) -> str:
        """Contains the domain to which the address refers to"""
        return self._domain

    @property
    def hostnames(self) -> str:
        """Contains hostnames of the address"""
        return self._hostnames

    @property
    def is_tor(self) -> bool:
        """Describes whether the address belongs to the TOR network"""
        return self._is_tor

    @property
    def total_reports(self) -> int:
        """Contains total amount of reports to the address"""
        return self._total_reports

    @property
    def last_reported_at(self) -> str:
        """Contains the date of the last report to the address"""
        return format_iso_date(self._last_reported_at)

    @property
    def top_categories(self) -> list[str]:
        """Contains top categories from the reports for IP"""
        categories_count = {}
        for report in self._reports:
            for category in report.get("categories"):
                key = category
                categories_count[key] = categories_count.get(key, 0) + 1

        sorted_categories = [
            item[0]
            for item in sorted(
                categories_count.items(), key=lambda x: x[1], reverse=True
            )
        ]
        if len(sorted_categories) > 5:
            sorted_categories = sorted_categories[:5]

        with open("check/abuse_categories.toml", "rb") as file:
            abuseipdb_categories = tomllib.load(file)

        top_categories = []

        for category_id in sorted_categories:
            top_categories.append(
                abuseipdb_categories.get("categories")
                .get(str(category_id))
                .get("title")
            )

        return top_categories

    @property
    def reports_data(self) -> dict:
        """Contains report data for IP in the form of columns data|category|count"""
        temp_reports_data = []

        for report in self._reports:
            for category in report.get("categories"):
                temp_reports_data.append(
                    {
                        "date": datetime.strptime(
                            report.get("reportedAt")[:10], "%Y-%m-%d"
                        ),
                        "category": category,
                    }
                )

        reports_data = {"date": [], "category": [], "count": []}

        count_dict = {}
        for report in temp_reports_data:
            key = (report.get("date"), report.get("category"))
            count_dict[key] = count_dict.get(key, 0) + 1

        with open("check/abuse_categories.toml", "rb") as file:
            abuseipdb_categories = tomllib.load(file)

        for (date, category), count in count_dict.items():
            reports_data.get("date").append(date)
            reports_data.get("category").append(
                abuseipdb_categories.get("categories").get(str(category)).get("title")
            )
            reports_data.get("count").append(count)

        return reports_data


class AbuseIPDBHandler(ServiceHandler):
    """Handler for interactions with AbuseIPDB"""

    async def get_ip_data(self, address) -> AbuseIPDBData:
        """Get data for indicator from AbuseIPDB"""

        headers = {"accept": "application/json", "key": self._key}
        querystring = {
            "ipAddress": address.as_a_string,
            "verbose": "True",
            "maxAgeInDays": 365,
        }

        async with ClientSession(
            base_url="https://api.abuseipdb.com", headers=headers
        ) as session:
            response = await self._fetch(session, "/api/v2/check", params=querystring)

        data = AbuseIPDBData.from_json(response.get("data"))

        return data
