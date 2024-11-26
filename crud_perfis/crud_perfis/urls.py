from django.urls import path
from app_perfis.views import CustomTokenObtainPairView, UserRegistrationView

urlpatterns = [
    path('api/token', CustomTokenObtainPairView.as_view(), name='token_obtain_pair_custom'),    
    path('api/register', UserRegistrationView.as_view(), name='user_register'),
]
