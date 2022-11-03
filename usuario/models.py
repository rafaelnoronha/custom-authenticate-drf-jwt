from django.db import models
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission, Group, PermissionsMixin, _user_has_module_perms, _user_has_perm, _user_get_permissions
from django.contrib.auth.base_user import BaseUserManager, AbstractBaseUser
from django.contrib.auth.hashers import (
    check_password, is_password_usable, make_password,
)
from django.contrib.contenttypes.models import ContentType
from django.utils.crypto import salted_hmac
from django.conf import settings
from django.utils import timezone


ATIVO_CHOICE = (
    ('0', 'Inativo'),
    ('1', 'Ativo'),
)

def update_last_login_custom(sender, user, **kwargs):
    """
    A signal receiver which updates the last_login date for
    the user logging in.
    """

    date_last_login_field = get_user_model().DATE_LAST_LOGIN_FIELD
    time_last_login_field = get_user_model().TIME_LAST_LOGIN_FIELD

    user.__setattr__(date_last_login_field, timezone.now())
    user.__setattr__(time_last_login_field, timezone.now())
    user.save(update_fields=[date_last_login_field, time_last_login_field])


class GerenteGrupo(models.Manager):
    """
    The manager for the auth's Group model.
    """
    # use_in_migrations = True

    # def get_by_natural_key(self, name):
    #     return self.get(gr_nome=name)

    def get_queryset(self):
        return super().get_queryset()

    
class Grupo(Group):
    gr_nome = models.CharField(
        verbose_name='Grupo',
        max_length=150,
        unique=True
    )

    gr_permissoes = models.ManyToManyField(
        Permission,
        verbose_name='Permissões',
        blank=True,
    )

    name = None
    permissions = None

    objects = GerenteGrupo()

    class Meta:
        verbose_name = 'grupo'
        verbose_name_plural = 'grupos'
        proxy = True

    def __str__(self):
        return self.gr_nome

    def natural_key(self):
        return (self.gr_nome,)


# class PermissoesMixin(models.Model):
#     """
#     Add the fields and methods necessary to support the Group and Permission
#     models using the ModelBackend.
#     """
#     is_superuser = models.BooleanField(
#         verbose_name='super usuário',
#         default=False,
#         help_text=(
#             'Designates that this user has all permissions without '
#             'explicitly assigning them.'
#         ),
#     )
#     groups = models.ManyToManyField(
#         Grupo,
#         verbose_name='Grupos',
#         blank=True,
#         help_text=(
#             'The groups this user belongs to. A user will get all permissions '
#             'granted to each of their groups.'
#         ),
#         related_name="user_set",
#         related_query_name="user",
#     )
#     user_permissions = models.ManyToManyField(
#         Permission,
#         verbose_name='Permissoes do Usuário',
#         blank=True,
#         help_text='Especifica as permissões para este usuário',
#         related_name="user_set",
#         related_query_name="user",
#     )

#     class Meta:
#         abstract = True

#     def get_user_permissions(self, obj=None):
#         """
#         Return a list of permission strings that this user has directly.
#         Query all available auth backends. If an object is passed in,
#         return only permissions matching this object.
#         """
#         return _user_get_permissions(self, obj, 'user')

#     def get_group_permissions(self, obj=None):
#         """
#         Return a list of permission strings that this user has through their
#         groups. Query all available auth backends. If an object is passed in,
#         return only permissions matching this object.
#         """
#         return _user_get_permissions(self, obj, 'group')

#     def get_all_permissions(self, obj=None):
#         return _user_get_permissions(self, obj, 'all')

#     def has_perm(self, perm, obj=None):
#         """
#         Return True if the user has the specified permission. Query all
#         available auth backends, but return immediately if any backend returns
#         True. Thus, a user who has permission from a single auth backend is
#         assumed to have permission in general. If an object is provided, check
#         permissions for that object.
#         """
#         # Active superusers have all permissions.
#         if self.is_active and self.is_superuser:
#             return True

#         # Otherwise we need to check the backends.
#         return _user_has_perm(self, perm, obj)

#     def has_perms(self, perm_list, obj=None):
#         """
#         Return True if the user has each of the specified permissions. If
#         object is passed, check if the user has all required perms for it.
#         """
#         return all(self.has_perm(perm, obj) for perm in perm_list)

#     def has_module_perms(self, app_label):
#         """
#         Return True if the user has any permissions in the given app label.
#         Use similar logic as has_perm(), above.
#         """
#         # Active superusers have all permissions.
#         if self.is_active and self.is_superuser:
#             return True

#         return _user_has_module_perms(self, app_label)


class GerenteUsuario(BaseUserManager):
    def _create_user(self, sr_usuario, sr_senha, **extra_fields):
        if not sr_usuario:
            raise ValueError(('The given username must be set'))

        user = self.model(sr_usuario=sr_usuario, sr_senha=sr_senha, **extra_fields)

        user.set_password(sr_senha)
        user.save(using=self._db)
        return user

    def create_user(self, sr_usuario, sr_senha, **extra_fields):
        return self._create_user(sr_usuario, sr_senha, **extra_fields)

    def create_superuser(self, sr_usuario, sr_senha, **extra_fields):
        user = self._create_user(sr_usuario, sr_senha, **extra_fields)
        user.save(using=self._db)
        return user


class Usuario(AbstractBaseUser, Permission):
    sr_usuario = models.CharField(
        max_length=30,
        unique=True,
        verbose_name='usuario'
    )

    sr_senha = models.CharField(
        max_length=100,
        verbose_name='senha'
    )

    sr_nome = models.CharField(
        max_length=100
    )

    sr_data_ultimo_login = models.DateField(
        null=True
    )

    sr_hora_ultimo_login = models.TimeField(
        null=True
    )

    ativo = models.CharField(
        choices=ATIVO_CHOICE,
        max_length=1,
        default='1'
    )

    password = None
    last_login = None
    is_superuser = None

    objects = GerenteUsuario()

    USERNAME_FIELD = 'sr_usuario'
    PASSWORD_FIELD = 'sr_senha'
    ACTIVE_FIELD = 'ativo'
    DATE_LAST_LOGIN_FIELD = 'sr_data_ultimo_login'
    TIME_LAST_LOGIN_FIELD = 'sr_hora_ultimo_login'

    REQUIRED_FIELDS = ['sr_senha',]

    class Meta:
        db_table = 'usuario'
        verbose_name = 'Usuário'
        verbose_name_plural = 'Usuários'
        ordering = ['-id',]
        permissions = (
            ('permite_ativar_inativar_usuario', 'Permite ativar ou inativar um usuário'),
        )


    def get_password(self):
        """Return the password for this User."""
        return getattr(self, self.PASSWORD_FIELD)

    def set_password(self, raw_password):
        self.sr_senha = make_password(raw_password)
        self._password = raw_password

    def check_password(self, raw_password):
        """
        Return a boolean of whether the raw_password was correct. Handles
        hashing formats behind the scenes.
        """
        def setter(raw_password):
            self.set_password(raw_password)
            # Password hash upgrades shouldn't be considered password changes.
            self._password = None
            self.save(update_fields=["sr_senha"])
        return check_password(raw_password, self.sr_senha, setter)

    def set_unusable_password(self):
        # Set a value that will never be a valid hash
        self.sr_senha = make_password(None)

    def has_usable_password(self):
        """
        Return False if set_unusable_password() has been called for this user.
        """
        return is_password_usable(self.sr_senha)

    def _legacy_get_session_auth_hash(self):
        # RemovedInDjango40Warning: pre-Django 3.1 hashes will be invalid.
        key_salt = 'django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash'
        return salted_hmac(key_salt, self.sr_senha, algorithm='sha1').hexdigest()

    def get_session_auth_hash(self):
        """
        Return an HMAC of the password field.
        """
        key_salt = "django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash"
        return salted_hmac(
            key_salt,
            self.sr_senha,
            # RemovedInDjango40Warning: when the deprecation ends, replace
            # with:
            # algorithm='sha256',
            algorithm=settings.DEFAULT_HASHING_ALGORITHM,
        ).hexdigest()


# class PermissionManager(models.Manager):
#     use_in_migrations = True

#     def get_by_natural_key(self, codename, app_label, model):
#         return self.get(
#             codename=codename,
#             content_type=ContentType.objects.db_manager(self.db).get_by_natural_key(app_label, model),
#         )


# class Permissoes(models.Model):
#     """
#     The permissions system provides a way to assign permissions to specific
#     users and groups of users.

#     The permission system is used by the Django admin site, but may also be
#     useful in your own code. The Django admin site uses permissions as follows:

#         - The "add" permission limits the user's ability to view the "add" form
#           and add an object.
#         - The "change" permission limits a user's ability to view the change
#           list, view the "change" form and change an object.
#         - The "delete" permission limits the ability to delete an object.
#         - The "view" permission limits the ability to view an object.

#     Permissions are set globally per type of object, not per specific object
#     instance. It is possible to say "Mary may change news stories," but it's
#     not currently possible to say "Mary may change news stories, but only the
#     ones she created herself" or "Mary may only change news stories that have a
#     certain status or publication date."

#     The permissions listed above are automatically created for each model.
#     """
#     name = models.CharField(verbose_name='Nome', max_length=255)
#     content_type = models.ForeignKey(
#         ContentType,
#         models.CASCADE,
#         verbose_name='Tipo de Conteúdo',
#     )
#     codename = models.CharField(verbose_name='Codnome', max_length=100)

#     objects = PermissionManager()

#     class Meta:
#         verbose_name = 'permissao'
#         verbose_name_plural = 'permissoes'
#         unique_together = [['content_type', 'codename']]
#         ordering = ['content_type__app_label', 'content_type__model', 'codename']

#     def __str__(self):
#         return '%s | %s' % (self.content_type, self.name)

#     def natural_key(self):
#         return (self.codename,) + self.content_type.natural_key()
#     natural_key.dependencies = ['contenttypes.contenttype']
