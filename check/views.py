import asyncio
from django.shortcuts import render
from django.core.cache import cache
from django.conf import settings
from plotly import express as px
import pandas as pd
from check.api_handlers import rdap_ip_handle
from check.ioc import IndicatorType, Indicator
from check.services.abuseipdb_module import AbuseIPDBHandler
from check.services.virustotal_module import VirusTotalHandler
from check.services.alienvault_otx_module import AlienVaultOTXHandler
from check.services.analysis_module import AnalysisModule


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

        match indicator.type:
            case IndicatorType.NOT_IOC:
                pass

            case (
                IndicatorType.IP
                | IndicatorType.DOMAIN
                | IndicatorType.HOSTNAME
                | IndicatorType.HASH
            ):
                virustotal_handler = VirusTotalHandler(settings.VT_API_KEY)
                alienvault_otx_handler = AlienVaultOTXHandler(settings.OTX_API_KEY)

                match indicator.type:
                    case IndicatorType.IP:
                        rdap_result = rdap_ip_handle(indicator)
                        abuseipdb_handler = AbuseIPDBHandler(settings.ABUSEIPDB_API_KEY)

                        vt_result, alienvault_result, abuseipdb_result = (
                            await asyncio.gather(
                                virustotal_handler.get_ip_data(indicator),
                                alienvault_otx_handler.get_ip_data(indicator),
                                abuseipdb_handler.get_ip_data(indicator),
                            )
                        )

                        if (
                            abuseipdb_result.reports_data
                            and abuseipdb_result.total_reports > 0
                        ):
                            result.update(
                                {
                                    "abuseipdb_figure": create_abuseipdb_chart(
                                        abuseipdb_result.reports_data
                                    )
                                }
                            )

                        result.update(
                            {
                                "rdap_result": rdap_result,
                                "abuseipdb_result": abuseipdb_result,
                                "vt_result": vt_result,
                                "alienvault_result": alienvault_result,
                                "analysis_result": AnalysisModule.analyze_ip(
                                    vt_result, alienvault_result, abuseipdb_result
                                ),
                            }
                        )

                    case IndicatorType.DOMAIN:
                        vt_result, alienvault_result = await asyncio.gather(
                            virustotal_handler.get_domain_data(indicator),
                            alienvault_otx_handler.get_domain_data(indicator),
                        )

                        result.update(
                            {
                                "vt_result": vt_result,
                                "alienvault_result": alienvault_result,
                                "analysis_result": AnalysisModule.analyze_domain(
                                    vt_result, alienvault_result
                                ),
                            }
                        )

                    case IndicatorType.HOSTNAME:
                        vt_result, alienvault_result = await asyncio.gather(
                            virustotal_handler.get_domain_data(indicator),
                            alienvault_otx_handler.get_hostname_data(indicator),
                        )

                        result.update(
                            {
                                "vt_result": vt_result,
                                "alienvault_result": alienvault_result,
                                "analysis_result": AnalysisModule.analyze_hostname(
                                    vt_result, alienvault_result
                                ),
                            }
                        )

                    case IndicatorType.HASH:
                        vt_result, alienvault_result = await asyncio.gather(
                            virustotal_handler.get_file_data(indicator),
                            alienvault_otx_handler.get_file_data(indicator),
                        )

                        result.update(
                            {
                                "vt_result": vt_result,
                                "alienvault_result": alienvault_result,
                                "analysis_result": AnalysisModule.analyze_file(
                                    vt_result, alienvault_result
                                ),
                            }
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
