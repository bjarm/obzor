import ipaddress
import re
import tldextract
from django.db import models
from users.models import User


class IndicatorType(models.Model):
    name = models.CharField(max_length=255)

    class Meta:
        verbose_name_plural = "Indicator Types"

    def __str__(self):
        return str(self.name)

    @staticmethod
    def typify(indicator):

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

        if is_valid_ip(indicator):
            return IndicatorType.objects.get(name="IPv4")
        elif is_valid_hostname(indicator):
            return IndicatorType.objects.get(name="Hostname")
        elif is_valid_domain(indicator):
            return IndicatorType.objects.get(name="Domain")
        elif is_valid_hash(indicator):
            return IndicatorType.objects.get(name="Hash")


class Indicator(models.Model):
    value = models.CharField(max_length=255)
    type = models.ForeignKey(IndicatorType, on_delete=models.PROTECT)

    def __str__(self):
        return f"{str(self.type)} | {str(self.value)}"


class Check(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    indicator = models.ForeignKey(Indicator, on_delete=models.CASCADE)
    created_timestamp = models.DateTimeField(auto_now_add=True)
