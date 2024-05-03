from django.shortcuts import render
from django.core.cache import cache
from django.conf import settings
from django.views.generic.base import TemplateView
from django.views.generic.edit import FormView
from django.views.decorators.http import require_GET
from plotly import express as px
import pandas as pd
from check.api_handlers import rdap_ip_handle
from check.services.abuseipdb_module import AbuseIPDBHandler
from check.services.virustotal_module import VirusTotalHandler
from check.services.alienvault_otx_module import AlienVaultOTXHandler
from check.services.analysis_module import AnalysisModule
from check.models import Indicator
from check.forms import IndicatorForm


class IndexView(TemplateView):
    """View for index page"""

    template_name = "check/index.html"


class SearchView(FormView):
    form_class = IndicatorForm

    def get(self, request):
        form = self.form_class
        return render(request, "check/check-block.html", {"form": form})

    def post(self, request):
        form = self.form_class(request.POST)
        if form.is_valid():
            existing_indicator = Indicator.objects.filter(
                value=form.cleaned_data.get("value")
            ).first()

            if existing_indicator:
                return render(
                    request,
                    "check/result.html",
                    {"form": form, "indicator": existing_indicator},
                )
            else:
                indicator = form.save()
                return render(
                    request,
                    "check/result.html",
                    {"form": form, "indicator": indicator},
                )
        return render(request, "check/index.html", {"form": form})


@require_GET
def get_virustotal_data(request):
    indicator_value = request.GET.get("indicator")
    indicator = Indicator.objects.filter(value=indicator_value).first()
    cached_result = cache.get(f"{indicator.value}_VT")

    if cached_result:
        return render(request, "check/virustotal-block.html", cached_result)

    virustotal_handler = VirusTotalHandler(settings.VT_API_KEY)

    match indicator.type.name:
        case "IPv4":
            data = virustotal_handler.get_ip_data(indicator.value)
        case "Domain":
            data = virustotal_handler.get_domain_data(indicator.value)
        case "Hostname":
            data = virustotal_handler.get_domain_data(indicator.value)
        case "Hash":
            data = virustotal_handler.get_file_data(indicator.value)

    result = {"vt_result": data, "indicator_type": indicator.type.name}

    cache.set(f"{indicator.value}_VT", result, timeout=3600)

    return render(request, "check/virustotal-block.html", result)


@require_GET
def get_alienvault_otx_data(request):
    indicator_value = request.GET.get("indicator")
    indicator = Indicator.objects.filter(value=indicator_value).first()
    cached_result = cache.get(f"{indicator.value}_AVOTX")

    if cached_result:
        return render(request, "check/alienvault-otx-block.html", cached_result)

    alienvault_otx_handler = AlienVaultOTXHandler(settings.OTX_API_KEY)

    match indicator.type.name:
        case "IPv4":
            data = alienvault_otx_handler.get_ip_data(indicator.value)
        case "Domain":
            data = alienvault_otx_handler.get_domain_data(indicator.value)
        case "Hostname":
            data = alienvault_otx_handler.get_hostname_data(indicator.value)
        case "Hash":
            data = alienvault_otx_handler.get_file_data(indicator.value)

    result = {"alienvault_result": data, "indicator_type": indicator.type.name}

    cache.set(f"{indicator.value}_AVOTX", result, timeout=3600)

    return render(request, "check/alienvault-otx-block.html", result)


@require_GET
def get_abuseipdb_data(request):
    def create_abuseipdb_chart(data):
        """Function for creating chart of abuseipdb data"""
        df = pd.DataFrame(data)
        fig = px.bar(
            df,
            x="date",
            y="count",
            color="category",
            text_auto=True,
            template="plotly_dark",
            title="Статистика жалоб на IP",
            labels={
                "date": "Дата",
                "count": "Количество жалоб",
                "category": "Категория",
            },
        )
        fig.update_layout(plot_bgcolor="rgb(33,37,41)", paper_bgcolor="rgb(33,37,41)")
        return fig.to_html(
            full_html=False, include_plotlyjs="/static/js/plotly-2.30.0.min.js"
        )

    indicator_value = request.GET.get("indicator")
    indicator = Indicator.objects.filter(value=indicator_value).first()
    cached_result = cache.get(f"{indicator.value}_AIPDB")

    if cached_result:
        return render(request, "check/abuseipdb-block.html", cached_result)

    abuseipdb_handler = AbuseIPDBHandler(settings.ABUSEIPDB_API_KEY)
    data = abuseipdb_handler.get_ip_data(indicator.value)
    result = {
        "abuseipdb_result": data,
        "abuseipdb_figure": (
            create_abuseipdb_chart(data.reports_data)
            if data.total_reports > 0
            else None
        ),
    }

    cache.set(f"{indicator.value}_AIPDB", result, timeout=3600)

    return render(request, "check/abuseipdb-block.html", result)


@require_GET
def get_rdap_data(request):
    indicator_value = request.GET.get("indicator")
    indicator = Indicator.objects.filter(value=indicator_value).first()
    cached_result = cache.get(f"{indicator.value}_RDAP")

    if cached_result:
        return render(request, "check/rdap-block.html", cached_result)

    data = rdap_ip_handle(indicator.value)
    result = {"rdap_result": data}

    cache.set(f"{indicator.value}_RDAP", result, timeout=3600)

    return render(request, "check/rdap-block.html", result)


@require_GET
def get_analysis_data(request):
    indicator_value = request.GET.get("indicator")
    indicator = Indicator.objects.filter(value=indicator_value).first()
    cached_result = cache.get(f"{indicator.value}_A")

    if cached_result:
        return render(request, "check/analysis-block.html", cached_result)

    match indicator.type.name:
        case "IPv4":
            vt_result_cached = cache.get(f"{indicator.value}_VT")
            alienvault_result_cached = cache.get(f"{indicator.value}_AVOTX")
            abuseipdb_result_cached = cache.get(f"{indicator.value}_AIPDB")
            data = AnalysisModule.analyze_ip(
                vt_result=vt_result_cached.get("vt_result"),
                alienvault_otx_result=alienvault_result_cached.get("alienvault_result"),
                abuseipdb_result=abuseipdb_result_cached.get("abuseipdb_result"),
            )

        case "Domain":
            vt_result_cached = cache.get(f"{indicator.value}_VT")
            alienvault_result_cached = cache.get(f"{indicator.value}_AVOTX")
            data = AnalysisModule.analyze_domain(
                vt_result=vt_result_cached.get("vt_result"),
                alienvault_otx_result=alienvault_result_cached.get("alienvault_result"),
            )

        case "Hostname":
            vt_result_cached = cache.get(f"{indicator.value}_VT")
            alienvault_result_cached = cache.get(f"{indicator.value}_AVOTX")
            data = AnalysisModule.analyze_hostname(
                vt_result=vt_result_cached.get("vt_result"),
                alienvault_otx_result=alienvault_result_cached.get("alienvault_result"),
            )

        case "Hash":
            vt_result_cached = cache.get(f"{indicator.value}_VT")
            alienvault_result_cached = cache.get(f"{indicator.value}_AVOTX")
            data = AnalysisModule.analyze_file(
                vt_result=vt_result_cached.get("vt_result"),
                alienvault_otx_result=alienvault_result_cached.get("alienvault_result"),
            )

    result = {"analysis_result": data, "indicator_type": indicator.type.name}

    cache.set(f"{indicator.value}_A", result, timeout=3600)

    return render(request, "check/analysis-block.html", result)
