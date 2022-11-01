from django.contrib.auth import get_user_model
from rest_framework_simplejwt.authentication import JWTAuthentication



class JWTAuthenticationCustom(JWTAuthentication):
    pass


def default_user_authentication_rule_custom(user):
    # Prior to Django 1.10, inactive users could be authenticated with the
    # default `ModelBackend`.  As of Django 1.10, the `ModelBackend`
    # prevents inactive users from authenticating.  App designers can still
    # allow inactive users to authenticate by opting for the new
    # `AllowAllUsersModelBackend`.  However, we explicitly prevent inactive
    # users from authenticating to enforce a reasonable policy and provide
    # sensible backwards compatibility with older Django versions.
    active_field = get_user_model().ACTIVE_FIELD

    return user is not None and user.__getattribute__(active_field) == '1'
