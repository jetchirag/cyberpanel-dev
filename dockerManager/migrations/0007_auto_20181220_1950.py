# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-12-20 19:50
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dockerManager', '0006_docker'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Docker',
        ),
        migrations.AlterField(
            model_name='containers',
            name='image',
            field=models.CharField(default='unknown', max_length=50),
        ),
        migrations.AlterField(
            model_name='containers',
            name='memory',
            field=models.IntegerField(default=0),
        ),
        migrations.AlterField(
            model_name='containers',
            name='ports',
            field=models.TextField(default='{}'),
        ),
        migrations.AlterField(
            model_name='containers',
            name='tag',
            field=models.CharField(default='unknown', max_length=50),
        ),
    ]