# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-11-26 07:40
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dockerManager', '0003_containers_restartpolicy'),
    ]

    operations = [
        migrations.AddField(
            model_name='containers',
            name='startOnReboot',
            field=models.IntegerField(default=0),
        ),
    ]
