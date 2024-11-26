from django.urls import path
from app_perfis.views import *

urlpatterns = [
    path('api/token', CustomTokenObtainPairView.as_view(), name='token_obtain_pair_custom'),    
    path('api/register', UserRegistrationView.as_view(), name='user_register'),
    path('login/', login_view, name='login'),
    path('home/', home_view, name='home'),  # A home vai passar o JWT como parte do template
    path('api/protected/', ProtectedView.as_view(), name='protected'),
    path('api/logout/', LogoutView.as_view(), name='logout'),  # Rota para logout
    path('api/validate_token', validate_token, name='validate_token'),  # Endpoint para validar o token
    path('perfil/', perfil_view, name='perfil'),
    path('departamento/', departamento_view, name='departamento'),
    path('funcionarios/', funcionarios_view, name='funcionarios'),
    path('criar_usuario/', criar_usuario, name='criar_usuario'),
    path('editar_usuario/<int:user_id>/', editar_usuario, name='editar_usuario'),
    path('deletar_usuario/<int:id>/', deletar_usuario, name='deletar_usuario'),
    path('api/get_perfil/', get_perfil, name='get_perfil'),
]
