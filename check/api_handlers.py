import tomllib
from aiohttp import ClientSession
from datetime import datetime, timezone
from check.ioc import Indicator, IndicatorType
from django.conf import settings


async def fetch(session, url, params=None):
    async with session.get(url, params=params) as response:
        return await response.json()


async def vt_handle(indicator):

    if indicator.type == IndicatorType.ip:
        url = f"/api/v3/ip_addresses/{indicator.as_a_string}"
    elif indicator.type == IndicatorType.domain or indicator.type == IndicatorType.hostname:
        url = f"/api/v3/domains/{indicator.as_a_string}"
    elif indicator.type == IndicatorType.hash:
        url = f"/api/v3/files/{indicator.as_a_string}"

    headers = {
        "accept": "application/json",
        "x-apikey": settings.VT_API_KEY
    }

    async with ClientSession(base_url="https://www.virustotal.com", headers=headers) as session:
        response = await fetch(session, url)

    data = response.get('data')
    result = {}

    if data:
        attributes = data.get('attributes')

        result.update({
            'last_analysis_date': datetime.utcfromtimestamp(attributes.get('last_analysis_date')).replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
            'engine_malicious': attributes.get('last_analysis_stats').get('malicious'),
            'engine_count': sum(attributes.get('last_analysis_stats').values()),
            'reputation': attributes.get('reputation'),
            'tags': attributes.get('tags'),
            'last_modification_date': datetime.utcfromtimestamp(attributes.get('last_modification_date')).replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
        })

        if indicator.type == IndicatorType.domain or indicator.type == IndicatorType.hostname:
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


async def abuseipdb_handle(indicator):
    
    headers = {
        'accept': 'application/json',
        'key': settings.ABUSEIPDB_API_KEY
    }
    querystring = {
        'ipAddress': indicator.as_a_string,
        'verbose': 'True'
    }
    
    async with ClientSession(base_url="https://api.abuseipdb.com", headers=headers) as session:
        response = await fetch(session, '/api/v2/check', params=querystring)

    data = response.get('data')
    result = {}

    if data:
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

        result.update({
            'is_whitelisted': data.get('isWhitelisted'),
            'abuse_confidence_score': data.get('abuseConfidenceScore'),
            'usage_type': data.get('usageType'),
            'isp': data.get('isp'),
            'domain': data.get('domain'),
            'hostnames': data.get('hostnames'),
            'country_name': data.get('countryName'),
            'is_tor': data.get('isTor'),
            'total_reports': data.get('totalReports'),
            'categories': categories
        })

        if data.get('lastReportedAt'):
            result.update({
                'last_reported_at': datetime.fromisoformat(data.get('lastReportedAt')).replace(tzinfo=timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
            })

    return result


async def alienvault_handle(indicator):
    
    if indicator.type == IndicatorType.ip:
        general_url = f"/api/v1/indicators/IPv4/{indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.hostname:
        general_url = f"/api/v1/indicators/hostname/{indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.domain:
        general_url = f"/api/v1/indicators/domain/{indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.hash:
        general_url = f"/api/v1/indicators/file/{indicator.as_a_string}/general/"

    headers = {
        "accept": "application/json",
        "x-otx-api-key": settings.OTX_API_KEY
    }

    session = ClientSession(base_url="https://otx.alienvault.com", headers=headers)
    general_response = await fetch(session, general_url)

    # Collecting pulses data
    pulse_info = general_response.get('pulse_info')
    result = {}
    
    if pulse_info:
        # Get pulses from response
        pulses = pulse_info.get('pulses')

        if pulses:
            tags = []
            adversaries = []
            malware_families = []
            industries = []

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

            if tags:
                result.update({'tags': tags})
            if adversaries:
                result.update({'adversaries': adversaries})
            if malware_families:
                result.update({'malware_families': malware_families})
            if industries:
                result.update({'industries': industries})


    if indicator.type in [IndicatorType.ip, IndicatorType.hostname, IndicatorType.domain]:
        
        if indicator.type == IndicatorType.ip:
            passive_dns_url = f"/api/v1/indicators/IPv4/{indicator.as_a_string}/passive_dns/"
        elif indicator.type == IndicatorType.hostname:
            passive_dns_url = f"/api/v1/indicators/hostname/{indicator.as_a_string}/passive_dns/"
        elif indicator.type == IndicatorType.domain:
            passive_dns_url = f"/api/v1/indicators/domain/{indicator.as_a_string}/passive_dns/"

        passive_dns_response = await fetch(session, passive_dns_url)

        last_passive_dns = []
        
        if indicator.type == IndicatorType.ip:
            for passive_dns in passive_dns_response.get('passive_dns')[:5]:
                last_passive_dns.append(passive_dns.get('hostname'))
            
            result.update({
                'asn': general_response.get('asn'),
                'country_name': general_response.get('country_name'),
                'city': general_response.get('city'),
                'passive_dns_count': passive_dns_response.get('count'),
                'last_passive_dns': last_passive_dns
            })
        elif indicator.type == IndicatorType.hostname:
            for passive_dns in passive_dns_response.get('passive_dns')[:5]:
                last_passive_dns.append({
                    'address': passive_dns.get('address'),
                    'record_type': passive_dns.get('record_type')
                })
            
            result.update({
                'domain': general_response.get('domain'),
                'passive_dns_count': passive_dns_response.get('count'),
                'last_passive_dns': last_passive_dns
            })
        elif indicator.type == IndicatorType.domain:
            for passive_dns in passive_dns_response.get('passive_dns')[:5]:
                last_passive_dns.append({
                    'hostname': passive_dns.get('hostname'),
                    'address': passive_dns.get('address'),
                    'record_type': passive_dns.get('record_type')
                })
            
            result.update({
                'domain': general_response.get('domain'),
                'passive_dns_count': passive_dns_response.get('count'),
                'last_passive_dns': last_passive_dns
            })
    elif indicator.type == IndicatorType.hash:
        analysis_url = f"/api/v1/indicators/file/{indicator.as_a_string}/analysis/"
        
        analysis_response = await fetch(session, analysis_url)

        analysis = analysis_response.get('analysis')

        if analysis:
            analysis_info_results = analysis.get('info').get('results')
            analysis_info_plugins_metaextract_results = analysis_response.get('analysis').get('plugins').get('metaextract').get('results')

            result.update({
                'md5': analysis_info_results.get('md5'),
                'sha1': analysis_info_results.get('sha1'),
                'sha256': analysis_info_results.get('sha256'),
                'filesize': analysis_info_results.get('filesize'),
                'file_type': analysis_info_results.get('file_type'),
                'metaextract_urls': analysis_info_plugins_metaextract_results.get('urls'),
                'metaextract_ips': analysis_info_plugins_metaextract_results.get('ips')
        })

    await session.close()
    
    return result
