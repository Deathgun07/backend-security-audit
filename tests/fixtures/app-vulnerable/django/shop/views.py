from django.contrib.auth.models import User
from django.db import connection
from django.http import JsonResponse
from django.utils.safestring import mark_safe
from django.views.decorators.csrf import csrf_exempt
from rest_framework import serializers, viewsets
from .models import Invoice


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = "__all__"


class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all()
    serializer_class = UserSerializer


def invoice(request, pk):
    inv = Invoice.objects.get(pk=pk)
    return JsonResponse({"amount": inv.amount, "note": mark_safe(inv.note)})


@csrf_exempt
def search(request):
    with connection.cursor() as cur:
        cur.execute(f"SELECT id, username FROM auth_user WHERE username LIKE '%{request.GET['q']}%'")
        return JsonResponse({"rows": cur.fetchall()})
