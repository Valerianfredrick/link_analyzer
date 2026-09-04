from django.urls import path
from . import views

urlpatterns = [
    path('', views.landing),        
    path('analyze/', views.analyze), 
    path('analyze/stream/', views.analyze_stream),
]
