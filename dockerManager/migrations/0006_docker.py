# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-11-29 08:20
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dockerManager', '0005_remove_containers_restartpolicy'),
    ]

    operations = [
        migrations.CreateModel(
            name='Docker',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('allowedPorts', models.TextField()),
            ],
        ),
    ]