import tomllib
from datetime import datetime, timezone
import json
from aiohttp import ClientSession
from django.conf import settings
from ipwhois import ipwhois
from check.ioc import IndicatorType


async def fetch(session, url, params=None):
    async with session.get(url, params=params) as response:
        return await response.json()

def format_timestamp(timestamp):
    date = datetime.fromtimestamp(timestamp, timezone.utc)
    formatted_date = date.strftime("%Y-%m-%d %H:%M:%S %Z")
    return formatted_date

def format_iso_date(iso_date):
    date = datetime.fromisoformat(iso_date)
    utcfied_date = date.replace(tzinfo=timezone.utc)
    formatted_date = utcfied_date.strftime("%Y-%m-%d %H:%M:%S %Z")
    return formatted_date

async def vt_handle(indicator):

    if indicator.type == IndicatorType.IP:
        url = f"/api/v3/ip_addresses/{indicator.as_a_string}"
    elif indicator.type == IndicatorType.DOMAIN or indicator.type == IndicatorType.HOSTNAME:
        url = f"/api/v3/domains/{indicator.as_a_string}"
    elif indicator.type == IndicatorType.HASH:
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

        if attributes.get('last_analysis_date'):
            last_analysis_date = format_timestamp(attributes.get('last_analysis_date'))

        result.update({
            'last_analysis_date': last_analysis_date,
            'engine_malicious': attributes.get('last_analysis_stats').get('malicious'),
            'engine_count': sum(attributes.get('last_analysis_stats').values()),
            'reputation': attributes.get('reputation'),
            'tags': attributes.get('tags'),
            'last_modification_date': format_timestamp(attributes.get('last_modification_date'))
        })

        if indicator.type == IndicatorType.DOMAIN or indicator.type == IndicatorType.HOSTNAME:
            result.update({
                'registrar': attributes.get('registrar')
            })
        elif indicator.type == IndicatorType.HASH:
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
        'verbose': 'True',
        'maxAgeInDays': 365
    }

    async with ClientSession(base_url="https://api.abuseipdb.com", headers=headers) as session:
        response = await fetch(session, '/api/v2/check', params=querystring)

    data = response.get('data')
    result = {}

    if data:
        reports = data.get('reports')
        categories_count = {}
        reports_data = {}
        if reports:
            for report in reports:
                for category in report.get('categories'):
                    key = category
                    categories_count[key] = categories_count.get(key, 0) + 1
            reports_data = reports_to_stat_data(reports)

        sorted_categories = [item[0] for item in sorted(
            categories_count.items(), key=lambda x: x[1], reverse=True)]
        if len(sorted_categories) > 5:
            sorted_categories = sorted_categories[:5]

        with open(str(settings.BASE_DIR) + '/check/abuse_categories.toml', 'rb') as file:
            abuseipdb_categories = tomllib.load(file)

        top_categories = []

        for category_id in sorted_categories:
            top_categories.append(abuseipdb_categories.get(
                'categories').get(str(category_id)).get('title'))

        result.update({
            'is_whitelisted': data.get('isWhitelisted'),
            'abuse_confidence_score': data.get('abuseConfidenceScore'),
            'usage_type': data.get('usageType'),
            'domain': data.get('domain'),
            'hostnames': data.get('hostnames'),
            'is_tor': data.get('isTor'),
            'total_reports': data.get('totalReports'),
            'top_categories': top_categories,
            'reports_data': reports_data
        })

        if data.get('lastReportedAt'):
            result.update({
                'last_reported_at': format_iso_date(data.get('lastReportedAt'))
            })

    return result


def reports_to_stat_data(reports):

    temp_reports_data = []

    for report in reports:
        for category in report.get('categories'):
            temp_reports_data.append({
                'date': datetime.strptime(report.get('reportedAt')[:10], '%Y-%m-%d'),
                'category': category,
            })

    reports_data = {
        'date': [],
        'category': [],
        'count': []
    }

    count_dict = {}
    for report in temp_reports_data:
        key = (report.get('date'), report.get('category'))
        count_dict[key] = count_dict.get(key, 0) + 1

    with open(str(settings.BASE_DIR) + '/check/abuse_categories.toml', 'rb') as file:
        abuseipdb_categories = tomllib.load(file)

    for (date, category), count in count_dict.items():
        reports_data.get('date').append(date)
        reports_data.get('category').append(abuseipdb_categories.get(
            'categories').get(str(category)).get('title'))
        reports_data.get('count').append(count)

    return reports_data


async def alienvault_handle(indicator):

    if indicator.type == IndicatorType.IP:
        general_url = f"/api/v1/indicators/IPv4/{
            indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.HOSTNAME:
        general_url = f"/api/v1/indicators/hostname/{
            indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.DOMAIN:
        general_url = f"/api/v1/indicators/domain/{
            indicator.as_a_string}/general/"
    elif indicator.type == IndicatorType.HASH:
        general_url = f"/api/v1/indicators/file/{
            indicator.as_a_string}/general/"

    headers = {
        "accept": "application/json",
        "x-otx-api-key": settings.OTX_API_KEY
    }

    session = ClientSession(
        base_url="https://otx.alienvault.com", headers=headers)
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

            # Collecting unique tags from pulses that have more than 1000 subscribers
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

    if indicator.type in [IndicatorType.IP, IndicatorType.HOSTNAME, IndicatorType.DOMAIN]:

        if indicator.type == IndicatorType.IP:
            passive_dns_url = f"/api/v1/indicators/IPv4/{
                indicator.as_a_string}/passive_dns/"
        elif indicator.type == IndicatorType.HOSTNAME:
            passive_dns_url = f"/api/v1/indicators/hostname/{
                indicator.as_a_string}/passive_dns/"
        elif indicator.type == IndicatorType.DOMAIN:
            passive_dns_url = f"/api/v1/indicators/domain/{
                indicator.as_a_string}/passive_dns/"

        passive_dns_response = await fetch(session, passive_dns_url)

        passive_dns = passive_dns_response.get('passive_dns')
        for record in passive_dns:
            record.update({'first': format_iso_date(record.get('first'))})
            record.update({'last': format_iso_date(record.get('last'))})

        result.update({
            'passive_dns_count': passive_dns_response.get('count'),
            'passive_dns': passive_dns
        })

    elif indicator.type == IndicatorType.HASH:
        analysis_url = f"/api/v1/indicators/file/{
            indicator.as_a_string}/analysis/"

        analysis_response = await fetch(session, analysis_url)

        analysis = analysis_response.get('analysis')

        if analysis:
            analysis_info_results = analysis.get('info').get('results')
            analysis_info_plugins_metaextract_results = analysis_response.get(
                'analysis').get('plugins').get('metaextract').get('results')

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


def rdap_ip_handle(ip):
    lookup_result = ipwhois.IPWhois(ip.as_a_string).lookup_rdap(inc_raw=True)

    processed_result = {
        'asn': 'N/A',
        'asn_description': '',
        'asn_country_code': 'N/A',
        'asn_cidr': 'N/A',
        'network_name': 'N/A',
        'network_start_address': 'N/A',
        'network_end_address': 'N/A',
        'last_changed': 'N/A',
        'registration': 'N/A',
        'raw': 'N/A'
    }

    if lookup_result:
        processed_result.update({
            'asn': lookup_result.get('asn', 'N/A'),
            'asn_country_code': lookup_result.get('asn_country_code', 'N/A'),
            'asn_cidr': lookup_result.get('asn_cidr', 'N/A'),
            'raw': json.dumps(lookup_result.get('raw', 'N/A'), indent=4)
        })

        if processed_result['asn'] not in lookup_result.get('asn_description', ''):
            processed_result.update({
                'asn_description': lookup_result.get('asn_description', ''),
            })

        network = lookup_result.get('network')
        processed_result.update({
            'network_name': network.get('name', 'N/A'),
            'network_start_address': network.get('start_address', 'N/A'),
            'network_end_address': network.get('end_address', 'N/A')
        })

        events = network.get('events')
        if events:
            for event in events:
                if event.get('action') == 'last changed':
                    event_time = format_iso_date(event.get('timestamp'))
                    processed_result.update({
                        'last_changed': event_time
                    })
                elif event.get('action') == 'registration':
                    event_time = format_iso_date(event.get('timestamp'))
                    processed_result.update({
                        'registration': event_time
                    })

    return processed_result
