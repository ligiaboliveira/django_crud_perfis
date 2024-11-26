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
from django.shortcuts import render, redirect
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import logout
from django.http import HttpResponseForbidden
from django.http import JsonResponse

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

            # Criação do usuário
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
    token = request.data.get('access_token')
    print('token')
    print(token)
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
        # Renderiza a página de login
        return render(request, 'login.html')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = authenticate(username=username, password=password)
        if user:
            refresh = RefreshToken.for_user(user)
            access_token = refresh.access_token
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
        # Invalidar a sessão no Django (remove o usuário da sessão)
        logout(request)

        # Resposta de sucesso após logout
        return Response({"message": "Logout realizado com sucesso!"}, status=status.HTTP_200_OK)
