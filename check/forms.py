from django.forms import ModelForm
from django import forms
from check.models import Indicator, IndicatorType


class IndicatorForm(ModelForm):
    value = forms.CharField(
        widget=forms.TextInput(
            attrs={
                "class": "form-control text-bg-dark border border-2 border-top-0 border-bottom-0 border-secondary",
                "placeholder": "",
                "required": "",
                "type": "search",
            }
        )
    )

    class Meta:
        model = Indicator
        fields = ["value"]

    def clean_value(self):
        value = self.cleaned_data["value"]
        type = IndicatorType.typify(value)
        if type is None:
            raise forms.ValidationError("Не удалось определить тип индикатора.")
        return value

    def save(self, commit=True):
        instance = super().save(commit=False)
        instance.type = IndicatorType.typify(instance.value)
        if commit:
            instance.save()
        return instance


class KeywordForm(forms.Form):
    keywords = forms.CharField(
        widget=forms.Textarea(
            attrs={"class": "form-control text-bg-dark", "placeholder": ""}
        ),
        required=False,
    )
