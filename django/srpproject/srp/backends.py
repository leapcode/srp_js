from srp.models import SRPUser

class SRPBackend:
    """
    Authenticate against srp.models.SRPUser
    """
    # TODO: Model, login attribute name and password attribute name should be
    # configurable.
    def authenticate(self, username=None, M=None):
        try:
            user = SRPUser.objects.get(username=username)
            if user.check_password(M):
                return user
        except SRPUser.DoesNotExist:
            return None

    def get_user(self, user_id):
        try:
            return SRPUser.objects.get(pk=user_id)
        except SRPUser.DoesNotExist:
            return None
