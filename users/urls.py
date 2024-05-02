from django.urls import path

from users.views import (
    UserSignInView,
    UserSignUpView,
    UserProfileView,
    UserSignOutView,
)

app_name = "users"

urlpatterns = [
    path("sign-in/", UserSignInView.as_view(), name="sign-in"),
    path("sign-up/", UserSignUpView.as_view(), name="sign-up"),
    path("profile/", UserProfileView.as_view(), name="profile"),
    path("logout/", UserSignOutView.as_view(), name="logout"),
]
