from django.db import models
from django.contrib.auth.models import User
# Create your models here.

class SRPUser(User):
    salt = models.CharField(max_length=16)
    verifier = models.CharField(max_length=65, null=True)

    def check_password(self, M):
        return M[0] == M[1]
            
