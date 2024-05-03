from django.contrib import admin
from check.models import Indicator, IndicatorType, Check


admin.site.register(Indicator)
admin.site.register(IndicatorType)
admin.site.register(Check)
