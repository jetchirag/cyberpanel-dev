# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-11-11 09:05
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('loginSystem', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='Comments',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain_id', models.IntegerField()),
                ('name', models.CharField(max_length=255)),
                ('type', models.CharField(max_length=10)),
                ('modified_at', models.IntegerField()),
                ('account', models.CharField(max_length=40)),
                ('comment', models.CharField(max_length=64000)),
            ],
            options={
                'db_table': 'comments',
            },
        ),
        migrations.CreateModel(
            name='Cryptokeys',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain_id', models.IntegerField()),
                ('flags', models.IntegerField()),
                ('active', models.IntegerField(blank=True, null=True)),
                ('content', models.TextField(blank=True, null=True)),
            ],
            options={
                'db_table': 'cryptokeys',
            },
        ),
        migrations.CreateModel(
            name='Domainmetadata',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('domain_id', models.IntegerField()),
                ('kind', models.CharField(blank=True, max_length=32, null=True)),
                ('content', models.TextField(blank=True, null=True)),
            ],
            options={
                'db_table': 'domainmetadata',
            },
        ),
        migrations.CreateModel(
            name='Domains',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=255, unique=True)),
                ('master', models.CharField(blank=True, max_length=128, null=True)),
                ('last_check', models.IntegerField(blank=True, null=True)),
                ('type', models.CharField(max_length=6)),
                ('notified_serial', models.IntegerField(blank=True, null=True)),
                ('account', models.CharField(blank=True, max_length=40, null=True)),
                ('admin', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='loginSystem.Administrator')),
            ],
            options={
                'db_table': 'domains',
            },
        ),
        migrations.CreateModel(
            name='Records',
            fields=[
                ('id', models.BigAutoField(primary_key=True, serialize=False)),
                ('domain_id', models.IntegerField(blank=True, null=True)),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('type', models.CharField(blank=True, max_length=10, null=True)),
                ('content', models.CharField(blank=True, max_length=64000, null=True)),
                ('ttl', models.IntegerField(blank=True, null=True)),
                ('prio', models.IntegerField(blank=True, null=True)),
                ('change_date', models.IntegerField(blank=True, null=True)),
                ('disabled', models.IntegerField(blank=True, null=True)),
                ('ordername', models.CharField(blank=True, max_length=255, null=True)),
                ('auth', models.IntegerField(blank=True, null=True)),
                ('domainOwner', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, to='dns.Domains')),
            ],
            options={
                'db_table': 'records',
            },
        ),
        migrations.CreateModel(
            name='Supermasters',
            fields=[
                ('ip', models.CharField(max_length=64, primary_key=True, serialize=False)),
                ('nameserver', models.CharField(max_length=255)),
                ('account', models.CharField(max_length=40)),
            ],
            options={
                'db_table': 'supermasters',
            },
        ),
        migrations.CreateModel(
            name='Tsigkeys',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(blank=True, max_length=255, null=True)),
                ('algorithm', models.CharField(blank=True, max_length=50, null=True)),
                ('secret', models.CharField(blank=True, max_length=255, null=True)),
            ],
            options={
                'db_table': 'tsigkeys',
            },
        ),
        migrations.AlterUniqueTogether(
            name='tsigkeys',
            unique_together=set([('name', 'algorithm')]),
        ),
        migrations.AlterUniqueTogether(
            name='supermasters',
            unique_together=set([('ip', 'nameserver')]),
        ),
    ]
