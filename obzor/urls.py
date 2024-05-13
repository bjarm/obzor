"""
URL configuration for obzor project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""

from django.contrib import admin
from django.urls import path, include

from check.views import SearchView, IndexView, CheckView, EditKeywordsView

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", IndexView.as_view(), name="index"),
    path("check", CheckView.as_view(), name="check"),
    path("keywords/", EditKeywordsView.as_view(), name="keywords"),
    path("search/", SearchView.as_view(), name="search"),
    path("", include("users.urls", namespace="users")),
    path("check/", include("check.urls", namespace="check")),
]
