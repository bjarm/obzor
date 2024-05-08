from django.views.generic.edit import CreateView, UpdateView
from django.contrib.auth.views import LoginView, LogoutView
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.messages.views import SuccessMessageMixin
from django.urls import reverse_lazy
from django.shortcuts import redirect

from users.forms import UserSignInForm, UserSignUpForm, UserProfileForm
from users.models import User
from check.models import Check


class LoginForbiddenMixin(UserPassesTestMixin):
    """Mixin to prevent authentication pages from being requested by authenticated users"""

    login_url = "index"

    def test_func(self):
        return self.request.user.is_anonymous

    def handle_no_permission(self):
        return redirect(self.login_url)


class UserSignInView(LoginForbiddenMixin, LoginView):
    """View for user authentication process"""

    form_class = UserSignInForm
    template_name = "users/sign-in.html"


class UserSignUpView(LoginForbiddenMixin, SuccessMessageMixin, CreateView):
    """View for user registration process"""

    model = User
    form_class = UserSignUpForm
    template_name = "users/sign-up.html"
    success_url = reverse_lazy("users:sign-in")
    success_message = "Регистрация завершена успешно."


class UserProfileView(LoginRequiredMixin, SuccessMessageMixin, UpdateView):
    """View for displaying/changing user profile"""

    model = User
    form_class = UserProfileForm
    template_name = "users/profile.html"
    success_url = reverse_lazy("users:profile")
    success_message = "Профиль успешно обновлён."

    def get_object(self, queryset=None):
        return self.request.user

    def get_context_data(self, **kwargs):
        context = super(UserProfileView, self).get_context_data()
        context["checks"] = Check.objects.filter(user=self.request.user)
        return context


class UserSignOutView(LoginRequiredMixin, LogoutView):
    """View for user logout process"""
