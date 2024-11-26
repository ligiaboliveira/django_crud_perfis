from django.db import models
from django.contrib.auth.models import User


class Departamento(models.Model):
    nome = models.CharField(max_length=255)
    descricao = models.TextField()

    def __str__(self):
        return self.nome


class Perfil(models.Model):
    nome = models.CharField(max_length=255)
    descricao = models.TextField()

    def __str__(self):
        return self.nome


User.add_to_class('departamento', models.ForeignKey(Departamento, on_delete=models.CASCADE, null=True, blank=True))
User.add_to_class('perfil', models.ForeignKey(Perfil, on_delete=models.CASCADE, null=True, blank=True))
