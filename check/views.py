from django.shortcuts import render, HttpResponse
from check.api_handlers import virustotal_handle, abuseipdb_handle, alienvault_handle
from check.ioc import IndicatorType, Indicator


def index(request):
    return render(request, 'check/index.html')


def search(request):
    indicator_input = request.POST.get("ioc_input")

    indicator = Indicator(indicator_input)

    result = {
        'indicator': indicator.as_a_string,
        'indicator_type': indicator.type.name
    }

    if indicator.type != IndicatorType.not_ioc:
        vt_result = virustotal_handle(indicator)
        alienvault_result = alienvault_handle(indicator)

        result.update({
            'vt_result': vt_result,
            'alienvault_result': alienvault_result
        })

        if indicator.type == IndicatorType.ip:
            abuseipdb_result = abuseipdb_handle(indicator)
            result.update({
                'abuseipdb_result': abuseipdb_result
            })

    return render(request, 'check/result.html', result)
