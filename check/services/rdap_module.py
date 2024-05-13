from __future__ import annotations
import json
from check.utils import format_iso_date
from ipwhois import ipwhois
from check.services.service_module import ServiceHandler


class RDAPData:
    """Class for storing data received via RDAP"""

    def __init__(
        self,
        asn,
        asn_description,
        asn_country_code,
        asn_cidr,
        network_name,
        network_start_address,
        network_end_address,
        last_changed,
        registration,
        raw,
    ) -> None:
        self._asn = asn
        self._asn_description = asn_description
        self._asn_country_code = asn_country_code
        self._asn_cidr = asn_cidr
        self._network_name = network_name
        self._network_start_address = network_start_address
        self._network_end_address = network_end_address
        self._last_changed = last_changed
        self._registration = registration
        self._raw = raw

    @classmethod
    def from_json(cls, json_data: dict) -> RDAPData:
        """Creates a class instance based on json data received via RDAP"""

        asn_description = "N/A"
        if json_data.get("asn", "N/A") not in json_data.get("asn_description", ""):
            asn_description = json_data.get("asn_description", "")

        network = json_data.get("network")

        events = network.get("events")
        last_changed = "N/A"
        registration = "N/A"
        if events:
            for event in events:
                if event.get("action") == "last changed":
                    last_changed = format_iso_date(event.get("timestamp"))
                elif event.get("action") == "registration":
                    registration = format_iso_date(event.get("timestamp"))

        return cls(
            asn=json_data.get("asn", "N/A"),
            asn_description=asn_description,
            asn_country_code=json_data.get("asn_country_code", "N/A"),
            asn_cidr=json_data.get("asn_cidr", "N/A"),
            network_name=network.get("name", "N/A"),
            network_start_address=network.get("start_address", "N/A"),
            network_end_address=network.get("end_address", "N/A"),
            last_changed=last_changed,
            registration=registration,
            raw=json.dumps(json_data.get("raw", "N/A"), indent=4),
        )

    @property
    def asn(self) -> str:
        """Contains ASN to which address belongs"""
        return self._asn

    @property
    def asn_description(self) -> str:
        """Contains description of ASN"""
        return self._asn_description

    @property
    def asn_country_code(self) -> str:
        """Contains country code of ASN"""
        return self._asn_country_code

    @property
    def asn_cidr(self) -> str:
        """Contains ASN CIDR"""
        return self._asn_cidr

    @property
    def network_name(self) -> str:
        """Contains name of network to which address belongs"""
        return self._network_name

    @property
    def network_start_address(self) -> bool:
        """Contains first address of network"""
        return self._network_start_address

    @property
    def network_end_address(self) -> int:
        """Contains last address of network"""
        return self._network_end_address

    @property
    def last_changed(self) -> str:
        """Contains the date when the information was last modified"""
        return self._last_changed

    @property
    def registration(self) -> str:
        """Contains the date when registration record was created"""
        return self._registration

    @property
    def raw(self) -> str:
        """Contains raw RDAP data"""
        return self._raw


class RDAPHandler(ServiceHandler):
    """Handler for interactions via RDAP"""

    def get_ip_data(self, address) -> RDAPData | None:
        """Get data for indicator via RDAP"""

        lookup_result = ipwhois.IPWhois(address).lookup_rdap(inc_raw=True)

        data = RDAPData.from_json(lookup_result)

        return data
