# Generated by Django 4.1.4 on 2022-12-19 19:54

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('password_policies', '0002_auto_20221215_1203'),
    ]

    operations = [
        migrations.AlterField(
            model_name='passwordrecord',
            name='user',
            field=models.ForeignKey(editable=False, on_delete=django.db.models.deletion.CASCADE, related_name='password_records', to=settings.AUTH_USER_MODEL),
        ),
    ]