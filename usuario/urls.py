from rest_framework import routers
from .views import UsuarioViewSet


usuario_router = routers.SimpleRouter()
usuario_router.register(r'', UsuarioViewSet)