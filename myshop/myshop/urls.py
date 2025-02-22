"""
URL configuration for myshop project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from store.views import get_angel_profile, dashboard, angel_one_callback, home, user_login

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('store.urls')),
    path("dashboard/", dashboard, name="dashboard"),
    path('', home, name='home'),
    path('login/', user_login, name='login'),
    path('callback/', angel_one_callback, name='angel-callback'),
    path('profile/', get_angel_profile, name='get-angel-profile'),
    path('dashboard/',  dashboard, name='dashboard'),
]

