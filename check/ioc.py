import ipaddress
import enum
import tldextract
import re


class Indicator:
    def __init__(self, indicator):
        self.as_a_string = indicator
        self.type = typify(indicator)


class IndicatorType(enum.Enum):
    ip = 4
    domain = 3
    hash = 2
    not_ioc = 1


def typify(indicator):
    if is_valid_ip(indicator):
        return IndicatorType.ip
    elif is_valid_domain(indicator):
        return IndicatorType.domain
    elif is_valid_hash(indicator):
        return IndicatorType.hash
    else:
        return IndicatorType.not_ioc


def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False


def is_valid_domain(domain_str):
    extracted_domain = tldextract.extract(domain_str)
    return bool(extracted_domain.domain and extracted_domain.suffix and extracted_domain.fqdn == domain_str)


def is_valid_hash(hash_str):
    # Регулярные выражения для MD5, SHA-1 и SHA-256 хешей
    md5_pattern = re.compile(r'^[a-fA-F0-9]{32}$')
    sha1_pattern = re.compile(r'^[a-fA-F0-9]{40}$')
    sha256_pattern = re.compile(r'^[a-fA-F0-9]{64}$')

    # Проверка совпадения строки с шаблонами
    return bool(md5_pattern.match(hash_str) or sha1_pattern.match(hash_str) or sha256_pattern.match(hash_str))
