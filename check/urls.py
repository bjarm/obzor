from django.urls import path

from check.views import (
    get_abuseipdb_data,
    get_virustotal_data,
    get_alienvault_otx_data,
    get_rdap_data,
    get_analysis_data,
)

app_name = "check"

urlpatterns = [
    path("get-abuse/", get_abuseipdb_data, name="get-abuse"),
    path("get-vt/", get_virustotal_data, name="get-vt"),
    path("get-av-otx/", get_alienvault_otx_data, name="get-av-otx"),
    path("get-rdap/", get_rdap_data, name="get-rdap"),
    path("get-analysis/", get_analysis_data, name="get-analysis"),
]
