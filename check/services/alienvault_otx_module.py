from __future__ import annotations
from abc import ABC, abstractmethod
from aiohttp import ClientSession
import requests
from check.utils import format_iso_date
from check.services.service_module import ServiceHandler


class AlienVaultOTXData(ABC):
    """Class for storing data received from AlienVault OTX"""

    def __init__(self, tags, adversaries, malware_families, industries) -> None:
        self._tags = tags
        self._adversaries = adversaries
        self._malware_families = malware_families
        self._industries = industries

    @classmethod
    @abstractmethod
    def from_json(cls, json_data: dict) -> AlienVaultOTXData:
        """Creates a class instance based on json data received via API"""

    @property
    def tags(self) -> list[str]:
        """Contains list of tags associated with the indicator"""
        return self._tags

    @property
    def adversaries(self) -> list[str]:
        """Contains list of the adversaries associated with the indicator"""
        return self._adversaries

    @property
    def malware_families(self) -> list[str]:
        """Contains list of malware families associated with the indicator"""
        return self._malware_families

    @property
    def industries(self) -> list[str]:
        """Contains list of industries associated with the indicator"""
        return self._industries


class AlienVaultOTXIPData(AlienVaultOTXData):
    """Class for storing IP data received from AlienVault OTX"""

    def __init__(
        self,
        tags,
        adversaries,
        malware_families,
        industries,
        passive_dns,
        passive_dns_count,
    ) -> None:
        super().__init__(tags, adversaries, malware_families, industries)
        self._passive_dns = passive_dns
        self._passive_dns_count = passive_dns_count

    @classmethod
    def from_json(
        cls, general_json_data: dict, passive_dns_json_data: dict
    ) -> AlienVaultOTXIPData:
        """Creates a class instance based on json data received via API"""

        tags = []
        adversaries = []
        malware_families = []
        industries = []

        pulse_info = general_json_data.get("pulse_info")

        if pulse_info:
            # Get pulses from response
            pulses = pulse_info.get("pulses")

            if pulses:
                # Collecting unique tags from pulses that have more than 1000 subscribers
                for pulse in pulses:
                    for tag in pulse.get("tags", []):
                        if tag not in tags and pulse.get("subscriber_count", 0) >= 1000:
                            tags.append(tag)

                alienvault_related = pulse_info.get("related").get("alienvault")
                other_related = pulse_info.get("related").get("other")

                # Collecting unique adversaries
                for adversary in alienvault_related.get(
                    "adversary"
                ) + other_related.get("adversary"):
                    if adversary not in adversaries:
                        adversaries.append(adversary)
                # Collecting unique malware_families
                for malware_family in alienvault_related.get(
                    "malware_families"
                ) + other_related.get("malware_families"):
                    if malware_family not in malware_families:
                        malware_families.append(malware_family)
                # Collecting unique industries
                for industry in alienvault_related.get(
                    "industries"
                ) + other_related.get("industries"):
                    if industry not in industries:
                        industries.append(industry)

        passive_dns = passive_dns_json_data.get("passive_dns", [])
        for record in passive_dns:
            record.update({"first": format_iso_date(record.get("first"))})
            record.update({"last": format_iso_date(record.get("last"))})

        return cls(
            tags=tags,
            adversaries=adversaries,
            malware_families=malware_families,
            industries=industries,
            passive_dns=passive_dns,
            passive_dns_count=passive_dns_json_data.get("count", 0),
        )

    @property
    def passive_dns(self) -> list[str]:
        """Contains list of passive dns record history"""
        return self._passive_dns

    @property
    def passive_dns_count(self) -> int:
        """Contains passive dns record count"""
        return self._passive_dns_count


class AlienVaultOTXHostnameData(AlienVaultOTXData):
    """Class for storing hostname data received from AlienVault OTX"""

    def __init__(
        self,
        tags,
        adversaries,
        malware_families,
        industries,
        passive_dns,
        passive_dns_count,
    ) -> None:
        super().__init__(tags, adversaries, malware_families, industries)
        self._passive_dns = passive_dns
        self._passive_dns_count = passive_dns_count

    @classmethod
    def from_json(
        cls, general_json_data: dict, passive_dns_json_data: dict
    ) -> AlienVaultOTXHostnameData:
        """Creates a class instance based on json data received via API"""

        tags = []
        adversaries = []
        malware_families = []
        industries = []

        pulse_info = general_json_data.get("pulse_info")

        if pulse_info:
            # Get pulses from response
            pulses = pulse_info.get("pulses")

            if pulses:
                # Collecting unique tags from pulses that have more than 1000 subscribers
                for pulse in pulses:
                    for tag in pulse.get("tags", []):
                        if tag not in tags and pulse.get("subscriber_count", 0) >= 1000:
                            tags.append(tag)

                alienvault_related = pulse_info.get("related").get("alienvault")
                other_related = pulse_info.get("related").get("other")

                # Collecting unique adversaries
                for adversary in alienvault_related.get(
                    "adversary"
                ) + other_related.get("adversary"):
                    if adversary not in adversaries:
                        adversaries.append(adversary)
                # Collecting unique malware_families
                for malware_family in alienvault_related.get(
                    "malware_families"
                ) + other_related.get("malware_families"):
                    if malware_family not in malware_families:
                        malware_families.append(malware_family)
                # Collecting unique industries
                for industry in alienvault_related.get(
                    "industries"
                ) + other_related.get("industries"):
                    if industry not in industries:
                        industries.append(industry)

        passive_dns = passive_dns_json_data.get("passive_dns", [])
        for record in passive_dns:
            record.update({"first": format_iso_date(record.get("first"))})
            record.update({"last": format_iso_date(record.get("last"))})

        return cls(
            tags=tags,
            adversaries=adversaries,
            malware_families=malware_families,
            industries=industries,
            passive_dns=passive_dns,
            passive_dns_count=passive_dns_json_data.get("count", 0),
        )

    @property
    def passive_dns(self) -> list[str]:
        """Contains list of passive dns record history"""
        return self._passive_dns

    @property
    def passive_dns_count(self) -> int:
        """Contains passive dns record count"""
        return self._passive_dns_count


class AlienVaultOTXDomainData(AlienVaultOTXData):
    """Class for storing domain data received from AlienVault OTX"""

    def __init__(
        self,
        tags,
        adversaries,
        malware_families,
        industries,
        passive_dns,
        passive_dns_count,
    ) -> None:
        super().__init__(tags, adversaries, malware_families, industries)
        self._passive_dns = passive_dns
        self._passive_dns_count = passive_dns_count

    @classmethod
    def from_json(
        cls, general_json_data: dict, passive_dns_json_data: dict
    ) -> AlienVaultOTXDomainData:
        """Creates a class instance based on json data received via API"""

        tags = []
        adversaries = []
        malware_families = []
        industries = []

        pulse_info = general_json_data.get("pulse_info")

        if pulse_info:
            # Get pulses from response
            pulses = pulse_info.get("pulses")

            if pulses:
                # Collecting unique tags from pulses that have more than 1000 subscribers
                for pulse in pulses:
                    for tag in pulse.get("tags", []):
                        if tag not in tags and pulse.get("subscriber_count", 0) >= 1000:
                            tags.append(tag)

                alienvault_related = pulse_info.get("related").get("alienvault")
                other_related = pulse_info.get("related").get("other")

                # Collecting unique adversaries
                for adversary in alienvault_related.get(
                    "adversary"
                ) + other_related.get("adversary"):
                    if adversary not in adversaries:
                        adversaries.append(adversary)
                # Collecting unique malware_families
                for malware_family in alienvault_related.get(
                    "malware_families"
                ) + other_related.get("malware_families"):
                    if malware_family not in malware_families:
                        malware_families.append(malware_family)
                # Collecting unique industries
                for industry in alienvault_related.get(
                    "industries"
                ) + other_related.get("industries"):
                    if industry not in industries:
                        industries.append(industry)

        passive_dns = passive_dns_json_data.get("passive_dns", [])
        for record in passive_dns:
            record.update({"first": format_iso_date(record.get("first"))})
            record.update({"last": format_iso_date(record.get("last"))})

        return cls(
            tags=tags,
            adversaries=adversaries,
            malware_families=malware_families,
            industries=industries,
            passive_dns=passive_dns,
            passive_dns_count=passive_dns_json_data.get("count", 0),
        )

    @property
    def passive_dns(self) -> list[str]:
        """Contains list of passive dns record history"""
        return self._passive_dns

    @property
    def passive_dns_count(self) -> int:
        """Contains passive dns record count"""
        return self._passive_dns_count


class AlienVaultOTXFileData(AlienVaultOTXData):
    """Class for storing file data received from AlienVault OTX"""

    def __init__(
        self,
        tags,
        adversaries,
        malware_families,
        industries,
        md5,
        sha1,
        sha256,
        filesize,
        file_type,
        metaextract_urls,
        metaextract_ips,
    ) -> None:
        super().__init__(tags, adversaries, malware_families, industries)
        self._md5 = md5
        self._sha1 = sha1
        self._sha256 = sha256
        self._filesize = filesize
        self._file_type = file_type
        self._metaextract_urls = metaextract_urls
        self._metaextract_ips = metaextract_ips

    @classmethod
    def from_json(
        cls, general_json_data: dict, analysis_json_data: dict
    ) -> AlienVaultOTXFileData:
        """Creates a class instance based on json data received via API"""

        tags = []
        adversaries = []
        malware_families = []
        industries = []

        pulse_info = general_json_data.get("pulse_info")

        if pulse_info:
            # Get pulses from response
            pulses = pulse_info.get("pulses")

            if pulses:
                # Collecting unique tags from pulses that have more than 1000 subscribers
                for pulse in pulses:
                    for tag in pulse.get("tags", []):
                        if tag not in tags and pulse.get("subscriber_count", 0) >= 1000:
                            tags.append(tag)

                alienvault_related = pulse_info.get("related").get("alienvault")
                other_related = pulse_info.get("related").get("other")

                # Collecting unique adversaries
                for adversary in alienvault_related.get(
                    "adversary"
                ) + other_related.get("adversary"):
                    if adversary not in adversaries:
                        adversaries.append(adversary)
                # Collecting unique malware_families
                for malware_family in alienvault_related.get(
                    "malware_families"
                ) + other_related.get("malware_families"):
                    if malware_family not in malware_families:
                        malware_families.append(malware_family)
                # Collecting unique industries
                for industry in alienvault_related.get(
                    "industries"
                ) + other_related.get("industries"):
                    if industry not in industries:
                        industries.append(industry)

        analysis = analysis_json_data.get("analysis", {})
        analysis_info_results = analysis.get("info", {}).get("results", {})
        analysis_info_plugins_metaextract_results = (
            analysis_json_data.get("analysis", {})
            .get("plugins", {})
            .get("metaextract", {})
            .get("results", {})
        )

        return cls(
            tags=tags,
            adversaries=adversaries,
            malware_families=malware_families,
            industries=industries,
            md5=analysis_info_results.get("md5"),
            sha1=analysis_info_results.get("sha1"),
            sha256=analysis_info_results.get("sha256"),
            filesize=analysis_info_results.get("filesize"),
            file_type=analysis_info_results.get("file_type"),
            metaextract_urls=analysis_info_plugins_metaextract_results.get("urls"),
            metaextract_ips=analysis_info_plugins_metaextract_results.get("ips"),
        )

    @property
    def md5(self) -> str:
        """Contains the file's MD5 hash"""
        return self._md5

    @property
    def sha1(self) -> str:
        """Contains the file's SHA1 hash"""
        return self._sha1

    @property
    def sha256(self) -> str:
        """Contains the file's SHA256 hash"""
        return self._sha256

    @property
    def filesize(self) -> int:
        """Contains file size in bytes"""
        return self._filesize

    @property
    def file_type(self) -> str:
        """Contains the file type"""
        return self._file_type

    @property
    def metaextract_urls(self) -> int:
        """Contains the list of URLs related to the file (information received from metaextract)"""
        return self._metaextract_urls

    @property
    def metaextract_ips(self) -> list[str]:
        """Contains the list of IPs related to the file (information received from metaextract)"""
        return self._metaextract_urls

    def __bool__(self):
        return not self.is_empty()

    def is_empty(self):
        return all(value is None or value == [] for value in vars(self).values())


class AlienVaultOTXHandler(ServiceHandler):
    """Handler for interactions with AlienVault OTX"""

    def get_ip_data(self, address) -> AlienVaultOTXIPData:
        """Get IP data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}
        general_url = (
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{address}/general/"
        )
        pdns_url = (
            f"https://otx.alienvault.com/api/v1/indicators/IPv4/{address}/passive_dns/"
        )

        with requests.Session() as session:
            general_response = session.get(url=general_url, headers=headers)
            pdns_response = session.get(url=pdns_url, headers=headers)

        data = AlienVaultOTXIPData.from_json(
            general_response.json(), pdns_response.json()
        )
        print(data)

        return data

    def get_hostname_data(self, hostname) -> AlienVaultOTXHostnameData:
        """Get hostname data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}
        general_url = (
            f"https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/general/"
        )
        pdns_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{hostname}/passive_dns/"

        with requests.Session() as session:
            general_response = session.get(url=general_url, headers=headers)
            pdns_response = session.get(url=pdns_url, headers=headers)

        data = AlienVaultOTXIPData.from_json(
            general_response.json(), pdns_response.json()
        )

        return data

    def get_domain_data(self, domain) -> AlienVaultOTXDomainData:
        """Get domain data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}
        general_url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general/"
        )
        pdns_url = (
            f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns/"
        )

        with requests.Session() as session:
            general_response = session.get(url=general_url, headers=headers)
            pdns_response = session.get(url=pdns_url, headers=headers)

        data = AlienVaultOTXIPData.from_json(
            general_response.json(), pdns_response.json()
        )

        return data

    def get_file_data(self, file) -> AlienVaultOTXFileData:
        """Get file data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}
        general_url = (
            f"https://otx.alienvault.com/api/v1/indicators/file/{file}/general/"
        )
        analysis_url = (
            f"https://otx.alienvault.com/api/v1/indicators/file/{file}/analysis/"
        )

        with requests.Session() as session:
            general_response = session.get(url=general_url, headers=headers)
            analysis_response = session.get(url=analysis_url, headers=headers)

        data = AlienVaultOTXFileData.from_json(
            general_response.json(), analysis_response.json()
        )

        return data

    async def get_ip_data_async(self, address) -> AlienVaultOTXIPData:
        """Get IP data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}

        async with ClientSession(
            base_url="https://otx.alienvault.com", headers=headers
        ) as session:
            general_response = await self._fetch(
                session, f"/api/v1/indicators/IPv4/{address}/general/"
            )
            passive_dns_response = await self._fetch(
                session, f"/api/v1/indicators/IPv4/{address}/passive_dns/"
            )

        data = AlienVaultOTXIPData.from_json(general_response, passive_dns_response)

        return data

    async def get_hostname_data_async(self, hostname) -> AlienVaultOTXHostnameData:
        """Get hostname data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}

        async with ClientSession(
            base_url="https://otx.alienvault.com", headers=headers
        ) as session:
            general_response = await self._fetch(
                session, f"/api/v1/indicators/hostname/{hostname}/general/"
            )
            passive_dns_response = await self._fetch(
                session,
                f"/api/v1/indicators/hostname/{hostname}/passive_dns/",
            )

        data = AlienVaultOTXHostnameData.from_json(
            general_response, passive_dns_response
        )

        return data

    async def get_domain_data_async(self, domain) -> AlienVaultOTXDomainData:
        """Get domain data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}

        async with ClientSession(
            base_url="https://otx.alienvault.com", headers=headers
        ) as session:
            general_response = await self._fetch(
                session, f"/api/v1/indicators/domain/{domain}/general/"
            )
            passive_dns_response = await self._fetch(
                session, f"/api/v1/indicators/domain/{domain}/passive_dns/"
            )

        data = AlienVaultOTXDomainData.from_json(general_response, passive_dns_response)

        return data

    async def get_file_data_async(self, file) -> AlienVaultOTXFileData:
        """Get file data for indicator from AlienVault OTX"""

        headers = {"accept": "application/json", "x-otx-api-key": self._key}

        async with ClientSession(
            base_url="https://otx.alienvault.com", headers=headers
        ) as session:
            general_response = await self._fetch(
                session, f"/api/v1/indicators/file/{file}/general/"
            )
            analysis_response = await self._fetch(
                session, f"/api/v1/indicators/file/{file}/analysis/"
            )

        data = AlienVaultOTXFileData.from_json(general_response, analysis_response)

        return data
