import re
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.contrib.auth.hashers import check_password
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone

from .models import PasswordRecord


al = _('at least')
p = _('piece')
e1 = _("At least in uppercase, lowercase, numbers, special symbols")
e2 = _("kind of characters")
psk = _("Password should contain")
ght = _('Password cannot be the same as the most recent')
ght_p = _('repeated passwords used')
islp = _('The interval since the last password change must be at least')
d = _('days')


class ComplexityValidator:
    def __init__(self, **kwargs):
        self.min_char_categories = kwargs.pop('min_char_categories', 4)
        self.min_chars_of_each_type = [
            ('min_numeric_chars', r'[0-9]', _('number')),
            ('min_uppercase_chars', r'[A-Z]', _('uppercase letters')),
            ('min_lowercase_chars', r'[a-z]', _('lowercase letters')),
            ('min_special_chars', r'[^0-9A-Za-z]', _('special symbols')),
        ]
        for attr, _regex, _name in self.min_chars_of_each_type:
            setattr(
                self, attr,
                kwargs.get(attr, 1)
            )

    def validate(self, password, user=None):
        password_valid = True
        errors = []
        char_types_contained = 0
        for attr, regex, name in self.min_chars_of_each_type:
            find = re.findall(regex, password)
            required = getattr(self, attr)
            if len(find) < required:
                password_valid = False
                errors.append(str(f"{al} {required} {p} {name}"))
            if find:
                char_types_contained += 1

        if char_types_contained < self.min_char_categories:
            password_valid = False
            errors.append(f"{e1} {self.min_char_categories} {e2}")
        if not password_valid:
            errs = ', '.join(errors)
            raise ValidationError(
                _(f"{psk} {errs}"),
                code='password_lacks_numeric_or_symbols',
            )

    def get_help_text(self):
        requirements = []
        for attr, regex, name in self.min_chars_of_each_type:
            required = getattr(self, attr)
            if required:
                requirements.append(f"{al} {required} {p} {name}")
        if self.min_char_categories:
            requirements.append(
                f"{e1} {self.min_char_categories} {e2}"
            )
        reqs = ', '.join(requirements)
        return f"{psk} {reqs}."


class ReusedPasswordValidator:
    # https://docs.djangoproject.com/en/4.1/topics/auth/passwords/#writing-your-own-validator

    def __init__(self, record_length=3):
        if record_length <= 0:
            raise ValueError(_('record_length must be larger than 0.'))
        self.record_length = record_length

    def validate(self, password, user=None):
        # In case there is no user, this validator is not applicable.
        if user is None:
            return None

        stored_password_records = (
            PasswordRecord.objects.filter(user=user.id)
        )
        if not stored_password_records:
            return None
        for record in stored_password_records[:self.record_length]:
            if check_password(password, record.password):
                raise ValidationError(
                    self.get_help_text(),
                    code='password_repeated',
                )

    def get_help_text(self):
        return f"{ght} {self.record_length} {ght_p}"


class MinimumChangeIntervalValidator:

    def __init__(self, min_interval_days=1):
        self.min_interval = timedelta(days=min_interval_days)

    def validate(self, password, user=None):
        # In case there is no user, this validator is not applicable.
        if user is None:
            return None
        try:
            latest_password_record = (
                PasswordRecord.objects.filter(user=user.id).latest()
            )
        except PasswordRecord.DoesNotExist:
            return None
        if (timezone.now() - latest_password_record.date) \
                < self.min_interval:
            raise ValidationError(
                f"{islp} {self.min_interval.days} {d}.",
                code='password_reset_interval',
            )

    def get_help_text(self):
        return f"{islp} {self.min_interval.days} {d}."
