## Instalação e Configuração

**1. Clone o repositório:**
```bash
git clone https://github.com/ligiaboliveira/django_crud_perfis.git
```

**Navegue até o diretório do projeto:**
```bash
cd django_crud_perfis
```

**Crie um ambiente virtual (opcional, mas recomendado):**
```bash
python3 -m venv .venv
```

**Ative o ambiente virtual:**
```bash
# No Linux ou MacOS
source .venv/bin/activate
```

**Instale as dependências do projeto:**
```bash
pip install -r requirements.txt
```

**Adicione as migrations (se estiver usando Flask-Migrate):**
```bash
python manage.py makemigrations
python manage.py migrate
```

**Inicie o servidor de desenvolvimento:**
```bash
python manage.py runserver
```

**Rodar a seed:**
```bash
python manage.py seed
```

**Usuário super:**
```bash
email e senha: ligia@example.com | 1234
```

**Acesse a aplicação em seu navegador web:**
> http://127.0.0.1:8000/
