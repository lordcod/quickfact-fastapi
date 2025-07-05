from __future__ import annotations
from tortoise import fields
from tortoise.models import Model
from tortoise.fields.relational import ReverseRelation


class Fact(Model):
    id = fields.IntField(pk=True)
    category = fields.CharField(max_length=50)
    localizations: ReverseRelation[FactLocalization]


class FactLocalization(Model):
    id = fields.IntField(pk=True)
    fact = fields.ForeignKeyField(
        "models.Fact", related_name="localizations", on_delete=fields.CASCADE
    )
    lang = fields.CharField(max_length=5)
    text = fields.TextField()
    category = fields.CharField(max_length=50)
