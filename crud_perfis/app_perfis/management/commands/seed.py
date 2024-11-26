from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from django.contrib.auth.hashers import make_password
from app_perfis.models import Departamento, Perfil  # Ajuste conforme o nome real do app

class Command(BaseCommand):
    help = "Popula o banco de dados com dados iniciais (departamentos, perfis e usuário super)."

    def handle(self, *args, **kwargs):
        # Criando Departamentos
        departamentos = [
            {'nome': 'TI', 'descricao': 'Departamento de Tecnologia da Informação'},
            {'nome': 'Financeiro', 'descricao': 'Departamento Financeiro'},
            {'nome': 'Comercial', 'descricao': 'Departamento Comercial'},
        ]
        for dep in departamentos:
            Departamento.objects.get_or_create(nome=dep['nome'], defaults={'descricao': dep['descricao']})

        # Criando Perfis
        perfis = [
            {'nome': 'super', 'descricao': 'Usuário com privilégios administrativos totais'},
            {'nome': 'gestor', 'descricao': 'Usuário com privilégios para gerenciar seu departamento'},
            {'nome': 'funcionario', 'descricao': 'Usuário padrão, limitado ao seu perfil e tarefas'},
        ]
        for perfil in perfis:
            Perfil.objects.get_or_create(nome=perfil['nome'], defaults={'descricao': perfil['descricao']})

        # Criando Usuário Super
        try:
            if not User.objects.filter(username='ligia').exists():
                departamento_ti = Departamento.objects.get(nome='TI')
                perfil_super = Perfil.objects.get(nome='super')
                User.objects.create(
                    username='ligia@example.com',
                    first_name='Ligia',
                    last_name='Oliveira',
                    email='ligia@example.com',
                    password=make_password('1234'),  # Hash da senha
                    departamento=departamento_ti,
                    perfil=perfil_super,
                    is_superuser=True,
                    is_staff=True
                )
                self.stdout.write(self.style.SUCCESS("Usuário 'ligia' criado com sucesso!"))
            else:
                self.stdout.write("Usuário 'ligia' já existe.")
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Erro ao criar o usuário super: {e}"))
