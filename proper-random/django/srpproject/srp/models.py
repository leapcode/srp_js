from django.db import models
from django.contrib import auth
# Create your models here.

class User(models.Model):
    salt = models.CharField(max_length=16)
    name = models.CharField(max_length=20, unique=True)
    verifier = models.CharField(max_length=65, null=True)
    
    def delete(self):
        auth.models.objects.filter(username=self.name).delete()
        super(User, self).delete()
