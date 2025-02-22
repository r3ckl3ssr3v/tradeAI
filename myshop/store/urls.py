from django.urls import path
from . import views
from .views import get_option_contracts, get_option_chain, notifier_webhook, update_market_data, get_market_data

urlpatterns = [
    path("", views.home, name="home"),
    path("login/", views.user_login, name="login"),
    path("logout/", views.user_logout, name="logout"),
    path("add-product/", views.add_product, name="add_product"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path('callback/', views.angel_one_callback, name='angel-callback'),
    path('profile/', views.get_angel_profile, name='get-angel-profile'),
    path('chat/', views.chat_with_ai, name='chat-with-ai'),
    path('signup/', views.signup, name='signup'),
    path('upstox-login/', views.upstox_login, name='upstox_login'),
    path('upstox-callback/', views.upstox_callback, name='upstox_callback'),
    path('broker-select/', views.broker_select, name='broker_select'),
    path('angel-one-login/', views.angel_one_login, name='angel_one_login'),
    path('angel-one-callback/', views.angel_one_callback, name='angel_one_callback'),
    path('option-contracts/', get_option_contracts, name='get_option_contracts'),
    path('option-chain/', get_option_chain, name='get_option_chain'),
    path('notifier-webhook/', notifier_webhook, name='notifier_webhook'),
    path('update-market-data/', update_market_data, name='update_market_data'),
    path('get-market-data/', get_market_data, name='get_market_data'),
]
