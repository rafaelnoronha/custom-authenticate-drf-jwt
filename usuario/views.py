from rest_framework import viewsets
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import Usuario
from .serializers import UsuarioSerializer, TokenObtainPairSerializerCustom


class UsuarioViewSet(viewsets.ModelViewSet):
    queryset = Usuario.objects.all()
    serializer_class = UsuarioSerializer


class TokenObtainPairViewCustom(TokenObtainPairView):
    _serializer_class = 'usuario.serializers.TokenObtainPairSerializerCustom'
