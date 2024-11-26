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
    path('cargos/', cargos_view, name='cargos'),
    path('funcionarios/', funcionarios_view, name='funcionarios'),
]
