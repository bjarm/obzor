from django.shortcuts import render, HttpResponse
from check.api_handlers import vt_handle, abuseipdb_handle, alienvault_handle
from check.ioc import IndicatorType, Indicator
import asyncio


def index(request):
    return render(request, 'check/index.html')


async def search(request):
    indicator_input = request.POST.get("ioc_input")

    indicator = Indicator(indicator_input)

    result = {
        'indicator': indicator.as_a_string,
        'indicator_type': indicator.type.name
    }

    if indicator.type != IndicatorType.not_ioc:
        if indicator.type == IndicatorType.ip:
            vt_result, alienvault_result, abuseipdb_result = await asyncio.gather(vt_handle(indicator), alienvault_handle(indicator), abuseipdb_handle(indicator))
            result.update({
                'abuseipdb_result': abuseipdb_result,
                'vt_result': vt_result,
                'alienvault_result': alienvault_result
            })
        else:
            vt_result, alienvault_result = await asyncio.gather(vt_handle(indicator), alienvault_handle(indicator))
            result.update({
                'vt_result': vt_result,
                'alienvault_result': alienvault_result
            })

    return render(request, 'check/result.html', result)
