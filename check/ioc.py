import ipaddress
import enum
import re
import tldextract


class Indicator:
    def __init__(self, indicator):
        self.as_a_string = indicator
        self.type = typify(indicator)


class IndicatorType(enum.Enum):
    IP = 5
    HOSTNAME = 4
    DOMAIN = 3
    HASH = 2
    NOT_IOC = 1


def typify(indicator):
    if is_valid_ip(indicator):
        return IndicatorType.IP
    if is_valid_hostname(indicator):
        return IndicatorType.HOSTNAME
    if is_valid_domain(indicator):
        return IndicatorType.DOMAIN
    if is_valid_hash(indicator):
        return IndicatorType.HASH
    return IndicatorType.NOT_IOC


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    else:
        return ipaddress.ip_address(ip_str).is_global


def is_valid_domain(domain_str):
    extracted_domain = tldextract.extract(domain_str)
    return bool(
        extracted_domain.domain
        and extracted_domain.suffix
        and extracted_domain.fqdn == domain_str
        and not extracted_domain.subdomain
    )


def is_valid_hostname(hostname_str):
    extracted_hostname = tldextract.extract(hostname_str)
    return bool(
        extracted_hostname.domain
        and extracted_hostname.suffix
        and extracted_hostname.fqdn == hostname_str
        and extracted_hostname.subdomain
    )


def is_valid_hash(hash_str):
    # Регулярные выражения для MD5, SHA-1 и SHA-256 хешей
    md5_pattern = re.compile(r"^[a-fA-F0-9]{32}$")
    sha1_pattern = re.compile(r"^[a-fA-F0-9]{40}$")
    sha256_pattern = re.compile(r"^[a-fA-F0-9]{64}$")

    # Проверка совпадения строки с шаблонами
    return bool(
        md5_pattern.match(hash_str)
        or sha1_pattern.match(hash_str)
        or sha256_pattern.match(hash_str)
    )
