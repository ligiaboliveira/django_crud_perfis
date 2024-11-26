import jwt
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.response import Response
from django.contrib.auth.models import User
from rest_framework import status
from rest_framework.serializers import Serializer, CharField
from django.contrib.auth import authenticate
from django.shortcuts import render, redirect, get_object_or_404
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import logout
from django.http import HttpResponseForbidden
from django.http import JsonResponse
import json
from .models import Perfil, Departamento

class CustomTokenObtainPairView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        user = User.objects.filter(username=username).first()
        if user and user.check_password(password):
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            return Response({
                'access': str(access_token),
                'refresh': str(refresh),
            })
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_400_BAD_REQUEST)

class UserRegistrationView(APIView):
    permission_classes = [AllowAny]
    def post(self, request):
        serializer = UserRegistrationSerializer(data=request.data)

        if serializer.is_valid():
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            
            user = User.objects.create_user(username=username, password=password)
            return Response({"message": "Usuário criado com sucesso!"}, status=status.HTTP_201_CREATED)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    
class UserRegistrationSerializer(Serializer):
    username = CharField(max_length=150)
    password = CharField(max_length=128)
    password2 = CharField(max_length=128)

    def validate(self, data):
        if data['password'] != data['password2']:
            raise serializers.ValidationError("As senhas não coincidem.")
        return data
    
def is_valid_jwt(token):
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
    return payload

def validate_token(request):
    body = json.loads(request.body)
    token = body.get('access_token')
    print('token:', token)

    if token:
        payload = is_valid_jwt(token)
        if payload is None:
            return JsonResponse({'message': 'Token inválido ou expirado'}, status=403)
        return JsonResponse({'message': 'Token válido'}, status=200)
    
    return JsonResponse({'message': 'Token não fornecido'}, status=400)
    
def home_view(request, access_token=None):
    return render(request, 'home.html')
    
def login_view(request):
    if request.method == 'GET':
        
        return render(request, 'login.html')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
            request.session['access_token'] = str(access_token)
            return JsonResponse({
                'access_token': str(access_token),
                'refresh_token': str(refresh)
            }, status=200)

        return JsonResponse({'error': 'Credenciais inválidas'}, status=400)

class ProtectedView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        return Response({"message": "Dados protegidos acessados com sucesso!"})

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        
        logout(request)

        
        return Response({"message": "Logout realizado com sucesso!"}, status=status.HTTP_200_OK)


def perfil_view(request):
    if request.method == 'GET':
        perfis = Perfil.objects.all()  
        return render(request, 'perfil.html', {'perfis': perfis})


def departamento_view(request):
    if request.method == 'GET':
        departamentos = Departamento.objects.all()  
        return render(request, 'departamento.html', {'departamentos': departamentos})


def check_user_permission(user):
    
    perfis = Perfil.objects.filter(user=user)
    return [perfil.nome for perfil in perfis]

def funcionarios_view(request):
    if request.method == 'GET':
        token = request.session.get('access_token')
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        user_id = payload['user_id']
        user = User.objects.get(id=user_id)
        perfil = user.perfil  
        departamento_usuario = user.departamento  
        if perfil is None:
            return JsonResponse({'message': 'Usuário sem perfil atribuído'}, status=400)

        if perfil.nome == "super":
            
            funcionarios = User.objects.all()  
        elif perfil.nome == "gestor":
            
            funcionarios = User.objects.filter(departamento=departamento_usuario)
        elif perfil.nome == "funcionario":
            
            return render(request, 'error.html', {'message': 'Você não tem permissão para ver essa tela.'})
        print('funcionarios',funcionarios)
        return render(request, 'funcionarios.html', {'funcionarios': funcionarios}) 
    
def criar_usuario(request):
    if request.method == 'GET':
        
        perfis = Perfil.objects.all()
        departamentos = Departamento.objects.all()
        
        
        return render(request, 'criar_usuario.html', {'perfis': perfis, 'departamentos': departamentos,})

    elif request.method == 'POST':
        
        data = json.loads(request.body)
        
        try:
            perfil = Perfil.objects.get(id=data['perfil'])
            departamento = Departamento.objects.get(id=data['departamento'])
            
            
            user = User.objects.create_user(
                username=data['email'],  
                email=data['email'],
                first_name=data['first_name'],
                last_name=data['last_name'],
                password=data['senha']
            )
            user.perfil = perfil
            user.departamento = departamento
            user.save()
            
            return JsonResponse({'message': 'Usuário criado com sucesso!'}, status=201)
        
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'message': 'Método não permitido'}, status=405)

def editar_usuario(request, user_id):
    # Buscar o usuário pelo ID
    user = get_object_or_404(User, id=user_id)
    perfis = Perfil.objects.all()
    departamentos = Departamento.objects.all()

    if request.method == 'GET':
        # Preencher os campos do formulário com os dados do usuário
        return render(request, 'editar_usuario.html', {
            'user': user,
            'perfis': perfis,
            'departamentos': departamentos
        })

    elif request.method == 'POST':
        # Atualizar os dados do usuário
        data = json.loads(request.body)
        
        try:
            perfil = Perfil.objects.get(id=data['perfil'])
            departamento = Departamento.objects.get(id=data['departamento'])
            
            # Atualizar o usuário
            user.first_name = data['first_name']
            user.last_name = data['last_name']
            user.email = data['email']
            user.perfil = perfil
            user.departamento = departamento
            
            # Atualizar a senha apenas se for fornecida
            if data.get('senha'):
                user.set_password(data['senha'])
            
            user.save()

            return JsonResponse({'message': 'Usuário atualizado com sucesso!'}, status=200)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=400)

    return JsonResponse({'message': 'Método não permitido'}, status=405)

def deletar_usuario(request, id):
    try:
        usuario = get_object_or_404(User, id=id)
        usuario.delete()  # Deleta o usuário
        return redirect('funcionarios')  # Redireciona para a página inicial ou onde preferir
    except User.DoesNotExist:
        return JsonResponse({'error': 'Usuário não encontrado'}, status=404)