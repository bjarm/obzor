from django.contrib.auth.forms import (
    AuthenticationForm,
    UserCreationForm,
    UserChangeForm,
)
from django import forms
from users.models import User


class UserSignInForm(AuthenticationForm):
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "",
                "required": "",
            }
        )
    )
    password = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "",
                "required": "",
            }
        )
    )

    class Meta:
        model = User
        fields = ("username", "password")


class UserSignUpForm(UserCreationForm):
    first_name = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "",
                "required": "",
            }
        )
    )
    last_name = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "",
                "required": "",
            }
        )
    )
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "Username",
                "required": "",
            }
        )
    )
    email = forms.CharField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "you@example.com",
                "required": "",
            }
        )
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "",
                "required": "",
            }
        )
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(
            attrs={
                "class": "form-control text-bg-dark",
                "placeholder": "",
                "required": "",
            }
        )
    )

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "username",
            "email",
            "password1",
            "password2",
        )


class UserProfileForm(UserChangeForm):
    first_name = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
            }
        )
    )
    last_name = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
            }
        )
    )
    username = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark",
            }
        )
    )
    email = forms.CharField(
        widget=forms.EmailInput(
            attrs={
                "class": "form-control text-bg-dark",
            }
        )
    )

    class Meta:
        model = User
        fields = (
            "first_name",
            "last_name",
            "username",
            "email",
        )
