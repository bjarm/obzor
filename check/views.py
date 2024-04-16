import asyncio
from django.shortcuts import render
from django.core.cache import cache
from plotly import express as px
import pandas as pd
from check.api_handlers import (
    vt_handle,
    abuseipdb_handle,
    alienvault_handle,
    rdap_ip_handle,
)
from check.ioc import IndicatorType, Indicator


def index(request):
    return render(request, "check/index.html")


async def search(request):
    indicator_input = request.POST.get("ioc_input")
    cached_result = cache.get(indicator_input)

    if cached_result:
        return render(request, "check/result.html", cached_result)
    else:
        indicator = Indicator(indicator_input)

        result = {
            "indicator": indicator.as_a_string,
            "indicator_type": indicator.type.name,
        }

        if indicator.type != IndicatorType.NOT_IOC:
            if indicator.type == IndicatorType.IP:
                rdap_result = rdap_ip_handle(indicator)

                vt_result, alienvault_result, abuseipdb_result = await asyncio.gather(
                    vt_handle(indicator),
                    alienvault_handle(indicator),
                    abuseipdb_handle(indicator),
                )

                if abuseipdb_result.get("reports_data"):
                    abuseipdb_result.update(
                        {
                            "figure": create_abuseipdb_chart(
                                abuseipdb_result.get("reports_data")
                            )
                        }
                    )

                result.update(
                    {
                        "rdap_result": rdap_result,
                        "abuseipdb_result": abuseipdb_result,
                        "vt_result": vt_result,
                        "alienvault_result": alienvault_result,
                    }
                )
            else:
                vt_result, alienvault_result = await asyncio.gather(
                    vt_handle(indicator), alienvault_handle(indicator)
                )
                result.update(
                    {"vt_result": vt_result, "alienvault_result": alienvault_result}
                )
            cache.set(indicator_input, result, timeout=3600)

        return render(request, "check/result.html", result)


def create_abuseipdb_chart(data):
    df = pd.DataFrame(data)
    fig = px.bar(
        df,
        x="date",
        y="count",
        color="category",
        text_auto=True,
        template="plotly_dark",
        title="Статистика жалоб на IP",
        labels={"date": "Дата", "count": "Количество жалоб", "category": "Категория"},
    )
    fig.update_layout(plot_bgcolor="rgb(33,37,41)", paper_bgcolor="rgb(33,37,41)")
    return fig.to_html(
        full_html=False, include_plotlyjs="/static/js/plotly-2.30.0.min.js"
    )
