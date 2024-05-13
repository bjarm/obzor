from __future__ import annotations
import enum


class IPIndicatorCategory(enum.Enum):
    HOSTING = 3
    TOR = 2
    SCANNER = 1


class AnalysisModule:
    """Class for analyzing data from external services"""

    @staticmethod
    def analyze_ip(
        vt_result=None, alienvault_otx_result=None, abuseipdb_result=None, keywords=None
    ):
        total_score = 0
        categories = []

        # AbuseIPDB
        if abuseipdb_result:
            # Check 'Confidence of Abuse'
            abuse_score = abuseipdb_result.abuse_confidence_score
            if 50 > abuse_score >= 10:
                total_score += 1
            elif 75 > abuse_score >= 50:
                total_score += 3
            elif abuse_score >= 75:
                total_score += 5

            # Check if TOR
            if abuseipdb_result.is_tor:
                categories.append(IPIndicatorCategory.TOR.name)
                total_score += 3

            # Check if whitelisted
            if abuseipdb_result.is_whitelisted:
                total_score -= 5

            # Check if seen as scanner
            if (
                "Port Scan" in abuseipdb_result.top_categories
                and abuseipdb_result.total_reports >= 100
            ):
                categories.append(IPIndicatorCategory.SCANNER.name)

        # VirusTotal
        if vt_result:
            # Check VT score
            vt_score = vt_result.engine_malicious
            if 10 > vt_score >= 3:
                total_score += 1
            elif 20 > vt_score >= 10:
                total_score += 3
            elif vt_score >= 20:
                total_score += 5

            # Check VT community reputation
            vt_community_score = vt_result.reputation
            if vt_community_score >= 100:
                total_score -= 3
            elif vt_community_score <= -25:
                total_score += 3

        # AlienVault OTX
        if alienvault_otx_result:
            # Check if related to any adversaries or malware families
            if (
                alienvault_otx_result.adversaries
                or alienvault_otx_result.malware_families
            ):
                total_score += 5

        # AbuseIPDB + AlienVault OTX
        if abuseipdb_result and alienvault_otx_result:
            # Check if hosting/CDN
            if (
                abuseipdb_result.usage_type
                in ["Data Center/Web Hosting/Transit", "Content Delivery Network"]
                or alienvault_otx_result.passive_dns_count > 100
            ):
                categories.append(IPIndicatorCategory.HOSTING.name)

        # Check keywords
        keyword_entry = []

        if keywords:
            for keyword in keywords:
                if vt_result:
                    if keyword in " ".join(vt_result.tags):
                        keyword_entry.append({"keyword": keyword, "service": "VT"})

                if alienvault_otx_result:
                    if (
                        keyword in " ".join(alienvault_otx_result.tags)
                        or keyword in " ".join(alienvault_otx_result.adversaries)
                        or keyword in " ".join(alienvault_otx_result.malware_families)
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "AV_OTX"})
                    else:
                        for record in alienvault_otx_result.passive_dns:
                            if keyword in record.get("hostname"):
                                keyword_entry.append(
                                    {"keyword": keyword, "servic    e": "AV_OTX"}
                                )

                if abuseipdb_result:
                    if keyword in abuseipdb_result.domain or keyword in " ".join(
                        abuseipdb_result.hostnames
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "AIPDB"})

        result = {
            "total_score": total_score,
            "categories": categories,
            "keywords_result": keyword_entry,
        }

        return result

    @staticmethod
    def analyze_domain(vt_result=None, alienvault_otx_result=None, keywords=None):
        total_score = 0
        categories = []

        # Check VT score
        if vt_result:
            vt_score = vt_result.engine_malicious
            if 10 > vt_score >= 3:
                total_score += 1
            elif 20 > vt_score >= 10:
                total_score += 3
            elif vt_score >= 20:
                total_score += 5

            # Check VT community reputation
            vt_community_score = vt_result.reputation
            if vt_community_score >= 100:
                total_score -= 3
            elif vt_community_score <= -25:
                total_score += 3

        # AlienVault OTX
        if alienvault_otx_result:
            # Check if related to any adversaries or malware families
            if (
                alienvault_otx_result.adversaries
                or alienvault_otx_result.malware_families
            ):
                total_score += 5

        # Check keywords
        keyword_entry = []

        if keywords:
            for keyword in keywords:
                if vt_result:
                    if (
                        keyword in " ".join(vt_result.tags)
                        or keyword in vt_result.registrar
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "VT"})

                if alienvault_otx_result:
                    if (
                        keyword in " ".join(alienvault_otx_result.tags)
                        or keyword in " ".join(alienvault_otx_result.adversaries)
                        or keyword in " ".join(alienvault_otx_result.malware_families)
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "AV_OTX"})
                    else:
                        for record in alienvault_otx_result.passive_dns:
                            if keyword in record.get("hostname"):
                                keyword_entry.append(
                                    {"keyword": keyword, "service": "AV_OTX"}
                                )

        result = {
            "total_score": total_score,
            "categories": categories,
            "keywords_result": keyword_entry,
        }

        return result

    @staticmethod
    def analyze_hostname(vt_result=None, alienvault_otx_result=None, keywords=None):
        total_score = 0
        categories = []

        # Check VT score
        if vt_result:
            vt_score = vt_result.engine_malicious
            if 10 > vt_score >= 3:
                total_score += 1
            elif 20 > vt_score >= 10:
                total_score += 3
            elif vt_score >= 20:
                total_score += 5

            # Check VT community reputation
            vt_community_score = vt_result.reputation
            if vt_community_score >= 100:
                total_score -= 3
            elif vt_community_score <= -25:
                total_score += 3

        # AlienVault OTX
        if alienvault_otx_result:
            # Check if related to any adversaries or malware families
            if (
                alienvault_otx_result.adversaries
                or alienvault_otx_result.malware_families
            ):
                total_score += 5

        # Check keywords
        keyword_entry = []

        if keywords:
            for keyword in keywords:
                if vt_result:
                    if (
                        keyword in " ".join(vt_result.tags)
                        or keyword in vt_result.registrar
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "VT"})

                if alienvault_otx_result:
                    if (
                        keyword in " ".join(alienvault_otx_result.tags)
                        or keyword in " ".join(alienvault_otx_result.adversaries)
                        or keyword in " ".join(alienvault_otx_result.malware_families)
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "AV_OTX"})
                    else:
                        for record in alienvault_otx_result.passive_dns:
                            if keyword in record.get("hostname"):
                                keyword_entry.append(
                                    {"keyword": keyword, "service": "AV_OTX"}
                                )

        result = {
            "total_score": total_score,
            "categories": categories,
            "keywords_result": keyword_entry,
        }

        return result

    @staticmethod
    def analyze_file(vt_result=None, alienvault_otx_result=None, keywords=None):
        total_score = 0
        categories = []
        kaspersky_result = ""

        # Check VT score
        if vt_result:
            vt_score = vt_result.engine_malicious
            if 10 > vt_score >= 3:
                total_score += 1
            elif 20 > vt_score >= 10:
                total_score += 3
            elif vt_score >= 20:
                total_score += 5

            # Check VT community reputation
            vt_community_score = vt_result.reputation
            if vt_community_score >= 100:
                total_score -= 3
            elif vt_community_score <= -25:
                total_score += 3

            # Check Kaspersky result
            kaspersky_result = vt_result.kaspersky.get("result").split(":")[1]

        # AlienVault OTX
        if alienvault_otx_result:
            # Check if related to any adversaries or malware families
            if (
                alienvault_otx_result.adversaries
                or alienvault_otx_result.malware_families
            ):
                total_score += 5

        # Check keywords
        keyword_entry = []

        if keywords:
            for keyword in keywords:
                if vt_result:
                    if (
                        keyword in " ".join(vt_result.tags)
                        or keyword in " ".join(vt_result.names)
                        or keyword in vt_result.meaningful_name
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "VT"})

                if alienvault_otx_result:
                    if (
                        keyword in " ".join(alienvault_otx_result.tags)
                        or keyword in " ".join(alienvault_otx_result.adversaries)
                        or keyword in " ".join(alienvault_otx_result.malware_families)
                        or keyword in " ".join(alienvault_otx_result.metaextract_urls)
                    ):
                        keyword_entry.append({"keyword": keyword, "service": "AV_OTX"})

        result = {
            "total_score": total_score,
            "categories": categories,
            "kaspersky_result": kaspersky_result,
            "keywords_result": keyword_entry,
        }

        return result
