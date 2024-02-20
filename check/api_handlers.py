import requests
import json
import tomllib
from datetime import datetime, timezone
from check.ioc import Indicator, IndicatorType
from django.conf import settings


def virustotal_handle(indicator):

    HEADERS = {
        "accept": "application/json",
        "x-apikey": settings.VT_API_KEY
    }

    url = ""

    if indicator.type == IndicatorType.ip:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{
            indicator.as_a_string}"
    elif indicator.type == IndicatorType.domain:
        url = f"https://www.virustotal.com/api/v3/domains/{
            indicator.as_a_string}"
    elif indicator.type == IndicatorType.hash:
        url = f"https://www.virustotal.com/api/v3/files/{
            indicator.as_a_string}"

    response = requests.get(url, headers=HEADERS)
    response_decoded = json.loads(response.text)
    attributes = response_decoded.get('data').get('attributes')

    result = {
        'last_analysis_date': datetime.utcfromtimestamp(attributes.get('last_analysis_date')).replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        'engine_malicious': attributes.get('last_analysis_stats').get('malicious'),
        'engine_count': attributes.get('last_analysis_stats').get('malicious') +
        attributes.get('last_analysis_stats').get('suspicious') +
        attributes.get('last_analysis_stats').get('undetected') +
        attributes.get('last_analysis_stats').get('harmless') +
        attributes.get('last_analysis_stats').get('timeout'),
        'reputation': attributes.get('reputation'),
        'tags': attributes.get('tags'),
        'last_modification_date': datetime.utcfromtimestamp(attributes.get('last_modification_date')).replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    }

    if indicator.type == IndicatorType.ip:
        pass
    elif indicator.type == IndicatorType.domain:
        result.update({
            'registrar': attributes.get('registrar')
        })
    elif indicator.type == IndicatorType.hash:
        result.update({
            'type_extension': attributes.get('type_extension'),
            'type_description': attributes.get('type_description'),
            'type_tags': attributes.get('type_tags'),
            'magic': attributes.get('magic'),
            'names': attributes.get('names'),
            'meaningful_name': attributes.get('meaningful_name'),
            'size': attributes.get('size'),
            'sha256': attributes.get('sha256'),
            'sha1': attributes.get('sha1'),
            'md5': attributes.get('md5')
        })
        popular_threat_classification = attributes.get(
            'popular_threat_classification')
        if popular_threat_classification:
            result.update({
                'popular_threat_category': popular_threat_classification.get('popular_threat_category'),
                'popular_threat_name': popular_threat_classification.get('popular_threat_name'),
                'suggested_threat_label': popular_threat_classification.get('suggested_threat_label')
            })

    return result


def abuseipdb_handle(indicator):
    
    url = 'https://api.abuseipdb.com/api/v2/check'

    querystring = {
        'ipAddress': indicator.as_a_string,
        'verbose': True
    }

    headers = {
        'accept': 'application/json',
        'key': settings.ABUSEIPDB_API_KEY
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)
    response_decoded = json.loads(response.text)
    data = response_decoded.get('data')

    # Get reports from response
    reports = data.get('reports')
    # List for unique category IDs 
    categories_id = []
    # Collecting unique IDs
    if reports:
        for report in data.get('reports'):
            for category_id in report.get('categories', []):
                if category_id not in categories_id:
                    categories_id.append(category_id)
    # Access the file with the table of categories (ID, title, description)
    with open(str(settings.BASE_DIR) + '\\check\\abuse_categories.toml', 'rb') as file:
        abuseipdb_categories = tomllib.load(file)
    # List for unique categories
    categories = []
    # Collecting information about the categories of IDs we have previously received 
    for category_id in categories_id:
        categories.append(abuseipdb_categories.get('categories').get(str(category_id)).get('title'))

    result = {
        'is_whitelisted': data.get('isWhitelisted'),
        'abuse_confidence_score': data.get('abuseConfidenceScore'),
        'usage_type': data.get('usageType'),
        'isp': data.get('isp'),
        'domain': data.get('domain'),
        'hostnames': data.get('hostnames'),
        'country_name': data.get('countryName'),
        'is_tor': data.get('isTor'),
        'total_reports': data.get('totalReports'),
        'last_reported_at': datetime.fromisoformat(data.get('lastReportedAt')).replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        'categories': categories
    }

    return result


def alienvault_handle(indicator):
    
    HEADERS = {
        "accept": "application/json",
        "x-otx-api-key": settings.OTX_API_KEY
    }

    general_url = ""
    
    if indicator.type == IndicatorType.ip:
        general_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.domain:
        general_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.hash:
        general_url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator.as_a_string}/general/"

    general_response = requests.get(general_url, headers=HEADERS)
    general_response_decoded = json.loads(general_response.text)

    # Collecting pulses data
    pulse_info = general_response_decoded.get('pulse_info')

    # Get pulses from response
    pulses = pulse_info.get('pulses')

    tags = []
    adversaries = []
    malware_families = []
    industries = []

    if pulses:
        # Collecting unique tags from pulses that have more than 1000 subscribers (criterion of relevancy idk)
        for pulse in pulses:
            for tag in pulse.get('tags', []):
                if tag not in tags and pulse.get('subscriber_count', 0) >= 1000:
                    tags.append(tag)
        
        alienvault_related = pulse_info.get('related').get('alienvault')
        other_related = pulse_info.get('related').get('other')

        # Collecting unique adversaries
        for adversary in alienvault_related.get('adversary') + other_related.get('adversary'):
            if adversary not in adversaries:
                adversaries.append(adversary)
        # Collecting unique malware_families
        for malware_family in alienvault_related.get('malware_families') + other_related.get('malware_families'):
            if malware_family not in malware_families:
                malware_families.append(malware_family)
        # Collecting unique industries
        for industry in alienvault_related.get('industries') + other_related.get('industries'):
            if industry not in industries:
                industries.append(industry)

    result = {
        'tags': tags,
        'adversaries': adversaries,
        'malware_families': malware_families,
        'industries': industries
    }


    if indicator.type in [IndicatorType.ip, IndicatorType.domain]:
        passive_dns_url = ''

        if indicator.type == IndicatorType.ip:
            passive_dns_url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{indicator.as_a_string}/passive_dns/"
        elif indicator.type == IndicatorType.domain:
            passive_dns_url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{indicator.as_a_string}/passive_dns/"

        passive_dns_response = requests.get(passive_dns_url, headers=HEADERS)
        passive_dns_response_decoded = json.loads(passive_dns_response.text)

        last_passive_dns = []
        
        if indicator.type == IndicatorType.ip:
            for passive_dns in passive_dns_response_decoded.get('passive_dns')[:5]:
                last_passive_dns.append(passive_dns.get('hostname'))
            
            result.update({
                'asn': general_response_decoded.get('asn'),
                'country_name': general_response_decoded.get('country_name'),
                'city': general_response_decoded.get('city'),
                'passive_dns_count': passive_dns_response_decoded.get('count'),
                'last_passive_dns': last_passive_dns
            })
        elif indicator.type == IndicatorType.domain:
            for passive_dns in passive_dns_response_decoded.get('passive_dns')[:5]:
                last_passive_dns.append({
                    'address': passive_dns.get('address'),
                    'record_type': passive_dns.get('record_type')
                })
            
            result.update({
                'domain': general_response_decoded.get('domain'),
                'passive_dns_count': passive_dns_response_decoded.get('count'),
                'last_passive_dns': last_passive_dns
            })
    elif indicator.type == IndicatorType.hash:
        analysis_url = f"https://otx.alienvault.com/api/v1/indicators/file/{indicator.as_a_string}/analysis/"
        
        analysis_response = requests.get(analysis_url, headers=HEADERS)
        analysis_response_decoded = json.loads(analysis_response.text)

        analysis_info_results = analysis_response_decoded.get('analysis').get('info').get('results')
        analysis_info_plugins_metaextract_results = analysis_response_decoded.get('analysis').get('plugins').get('metaextract').get('results')

        result.update({
            'md5': analysis_info_results.get('md5'),
            'sha1': analysis_info_results.get('sha1'),
            'sha256': analysis_info_results.get('sha256'),
            'filesize': analysis_info_results.get('filesize'),
            'file_type': analysis_info_results.get('file_type'),
            'metaextract_urls': analysis_info_plugins_metaextract_results.get('urls'),
            'metaextract_ips': analysis_info_plugins_metaextract_results.get('ips')
        })

    return result
