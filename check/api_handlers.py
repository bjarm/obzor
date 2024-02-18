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