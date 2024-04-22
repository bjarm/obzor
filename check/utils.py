from datetime import datetime, timezone


def format_timestamp(timestamp):
    """Converts the timestamp to a date string (UTC)"""
    date = datetime.fromtimestamp(timestamp, timezone.utc)
    formatted_date = date.strftime("%Y-%m-%d %H:%M:%S %Z")
    return formatted_date


def format_iso_date(iso_date):
    """Converts the ISO date to a date string (UTC)"""
    date = datetime.fromisoformat(iso_date)
    utcfied_date = date.replace(tzinfo=timezone.utc)
    formatted_date = utcfied_date.strftime("%Y-%m-%d %H:%M:%S %Z")
    return formatted_date
