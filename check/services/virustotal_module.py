from __future__ import annotations
from abc import ABC, abstractmethod
from aiohttp import ClientSession
import requests
from check.utils import format_timestamp
from check.services.service_module import ServiceHandler


class VirusTotalData(ABC):
    """Class for storing data received from VirusTotal"""

    def __init__(
        self,
        last_analysis_date,
        engine_malicious,
        engine_count,
        reputation,
        tags,
        last_modification_date,
    ) -> None:
        self._last_analysis_date = last_analysis_date
        self._engine_malicious = engine_malicious
        self._engine_count = engine_count
        self._reputation = reputation
        self._tags = tags
        self._last_modification_date = last_modification_date

    @classmethod
    @abstractmethod
    def from_json(cls, json_data: dict) -> VirusTotalData:
        """Creates a class instance based on json data received via API"""

    @property
    def last_analysis_date(self) -> str:
        """Contains the date representing last time the indicator was scanned"""
        return self._last_analysis_date

    @property
    def engine_malicious(self) -> str:
        """Contains the number of av engines that consider the indicator to be malicious"""
        return self._engine_malicious

    @property
    def engine_count(self) -> int:
        """Contains the total number of av engines used for analysis"""
        return self._engine_count

    @property
    def reputation(self) -> int:
        """Contains indicator's score calculated from the votes of the VirusTotal's community"""
        return self._reputation

    @property
    def tags(self) -> list[str]:
        """Contains the list of identificative attributes"""
        return self._tags

    @property
    def last_modification_date(self) -> str:
        """Contains the date when any of the indicator information was last updated"""
        return self._last_modification_date


class VirusTotalIPData(VirusTotalData):
    """Class for storing IP data received from VirusTotal"""

    @classmethod
    def from_json(cls, json_data: dict) -> VirusTotalIPData:
        """Creates a class instance based on json data received via API"""

        attributes = json_data.get("attributes")

        return cls(
            last_analysis_date=format_timestamp(
                attributes.get("last_analysis_date", "")
            ),
            engine_malicious=attributes.get("last_analysis_stats").get("malicious"),
            engine_count=sum(attributes.get("last_analysis_stats").values()),
            reputation=attributes.get("reputation"),
            tags=attributes.get("tags"),
            last_modification_date=format_timestamp(
                attributes.get("last_modification_date")
            ),
        )


class VirusTotalDomainData(VirusTotalData):
    """Class for storing domain/hostname data received from VirusTotal"""

    def __init__(
        self,
        last_analysis_date,
        engine_malicious,
        engine_count,
        reputation,
        tags,
        last_modification_date,
        registrar,
    ) -> None:
        super().__init__(
            last_analysis_date,
            engine_malicious,
            engine_count,
            reputation,
            tags,
            last_modification_date,
        )
        self._registrar = registrar

    @classmethod
    def from_json(cls, json_data: dict) -> VirusTotalDomainData:
        """Creates a class instance based on json data received via API"""

        attributes = json_data.get("attributes")

        return cls(
            last_analysis_date=attributes.get("last_analysis_date", ""),
            engine_malicious=attributes.get("last_analysis_stats").get("malicious"),
            engine_count=sum(attributes.get("last_analysis_stats").values()),
            reputation=attributes.get("reputation"),
            tags=attributes.get("tags"),
            last_modification_date=format_timestamp(
                attributes.get("last_modification_date")
            ),
            registrar=attributes.get("registrar"),
        )

    @property
    def registrar(self) -> str:
        """Contains the company that registered the domain"""
        return self._registrar


class VirusTotalFileData(VirusTotalData):
    """Class for storing file data received from VirusTotal"""

    def __init__(
        self,
        last_analysis_date,
        engine_malicious,
        engine_count,
        reputation,
        tags,
        last_modification_date,
        type_extension,
        type_description,
        type_tags,
        magic,
        names,
        meaningful_name,
        size,
        sha256,
        sha1,
        md5,
        kaspersky,
    ) -> None:
        super().__init__(
            last_analysis_date,
            engine_malicious,
            engine_count,
            reputation,
            tags,
            last_modification_date,
        )
        self._type_extension = type_extension
        self._type_description = type_description
        self._type_tags = type_tags
        self._magic = magic
        self._names = names
        self._meaningful_name = meaningful_name
        self._size = size
        self._sha256 = sha256
        self._sha1 = sha1
        self._md5 = md5
        self._kasperky = kaspersky

    @classmethod
    def from_json(cls, json_data: dict) -> VirusTotalFileData:
        """Creates a class instance based on json data received via API"""

        attributes = json_data.get("attributes")

        return cls(
            last_analysis_date=attributes.get("last_analysis_date", ""),
            engine_malicious=attributes.get("last_analysis_stats").get("malicious"),
            engine_count=sum(attributes.get("last_analysis_stats").values()),
            reputation=attributes.get("reputation"),
            tags=attributes.get("tags"),
            last_modification_date=format_timestamp(
                attributes.get("last_modification_date")
            ),
            type_extension=attributes.get("type_extension"),
            type_description=attributes.get("type_description"),
            type_tags=attributes.get("type_tags"),
            magic=attributes.get("magic"),
            names=attributes.get("names"),
            meaningful_name=attributes.get("meaningful_name"),
            size=attributes.get("size"),
            sha256=attributes.get("sha256"),
            sha1=attributes.get("sha1"),
            md5=attributes.get("md5"),
            kaspersky=attributes.get("last_analysis_results").get("Kaspersky"),
        )

    @property
    def type_extension(self) -> str:
        """Contains file extension"""
        return self._type_extension

    @property
    def type_description(self) -> str:
        """Describes the file type"""
        return self._type_description

    @property
    def type_tags(self) -> list[str]:
        """Contains broader tags related to the specific file type"""
        return self._type_tags

    @property
    def magic(self) -> str:
        """Contains a guess of the file type, based on a popular parsing tool from unix"""
        return self._magic

    @property
    def names(self) -> list[str]:
        """Contains all file names associated with the file"""
        return self._names

    @property
    def meaningful_name(self) -> str:
        """Contains the most interesting name out of all file's names"""
        return self._meaningful_name

    @property
    def size(self) -> int:
        """Contains file size in bytes"""
        return self._size

    @property
    def sha256(self) -> str:
        """Contains the file's SHA256 hash"""
        return self._sha256

    @property
    def sha1(self) -> str:
        """Contains the file's SHA1 hash"""
        return self._sha1

    @property
    def md5(self) -> str:
        """Contains the file's MD5 hash"""
        return self._md5

    @property
    def kaspersky(self) -> dict:
        """Contains the result of Kaspersky AV analysis"""
        return self._kasperky


class VirusTotalHandler(ServiceHandler):
    """Handler for interactions with VirusTotal"""

    def get_ip_data(self, address) -> VirusTotalIPData | None:
        """Get IP data for indicator from VirusTotal"""

        headers = {"accept": "application/json", "x-apikey": self._key}
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{address}"

        try:
            response = requests.get(url=url, headers=headers, timeout=5)
        except requests.exceptions.ReadTimeout:
            return None

        data = VirusTotalIPData.from_json(response.json().get("data"))

        return data

    def get_domain_data(self, domain) -> VirusTotalDomainData | None:
        """Get domain/hostname data for indicator from VirusTotal"""

        headers = {"accept": "application/json", "x-apikey": self._key}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"

        try:
            response = requests.get(url=url, headers=headers, timeout=5)
        except requests.exceptions.ReadTimeout:
            return None

        data = VirusTotalDomainData.from_json(response.json().get("data"))

        return data

    def get_file_data(self, file) -> VirusTotalFileData | None:
        """Get file data for indicator from VirusTotal"""

        headers = {"accept": "application/json", "x-apikey": self._key}
        url = f"https://www.virustotal.com/api/v3/files/{file}"

        try:
            response = requests.get(url=url, headers=headers, timeout=5)
        except requests.exceptions.ReadTimeout:
            return None

        data = VirusTotalFileData.from_json(response.json().get("data"))

        return data

    async def get_ip_data_async(self, address) -> VirusTotalIPData:
        """Get IP data for indicator from VirusTotal"""

        headers = {"accept": "application/json", "x-apikey": self._key}

        async with ClientSession(
            base_url="https://www.virustotal.com", headers=headers
        ) as session:
            response = await self._fetch(session, f"/api/v3/ip_addresses/{address}")

        data = VirusTotalIPData.from_json(response.get("data"))

        return data

    async def get_domain_data_async(self, domain) -> VirusTotalDomainData:
        """Get domain/hostname data for indicator from VirusTotal"""

        headers = {"accept": "application/json", "x-apikey": self._key}

        async with ClientSession(
            base_url="https://www.virustotal.com", headers=headers
        ) as session:
            response = await self._fetch(session, f"/api/v3/domains/{domain}")

        data = VirusTotalDomainData.from_json(response.get("data"))

        return data

    async def get_file_data_async(self, file) -> VirusTotalFileData:
        """Get file data for indicator from VirusTotal"""

        headers = {"accept": "application/json", "x-apikey": self._key}

        async with ClientSession(
            base_url="https://www.virustotal.com", headers=headers
        ) as session:
            response = await self._fetch(session, f"/api/v3/files/{file}")

        data = VirusTotalFileData.from_json(response.get("data"))

        return data
