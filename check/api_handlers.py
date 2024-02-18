import requests
import json
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
