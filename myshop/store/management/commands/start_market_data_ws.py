from django.core.management.base import BaseCommand
from store.websocket_client import MarketDataWebSocket


class Command(BaseCommand):
    help = 'Start the Market Data WebSocket client. Provide the access token as an argument.'

    def add_arguments(self, parser):
        parser.add_argument('access_token', type=str, help='Access token for Upstox API')

    def handle(self, *args, **kwargs):
        access_token = kwargs['access_token']  # Get the access token from command line arguments

        if access_token:
            market_data_ws = MarketDataWebSocket(access_token)
            market_data_ws.run()
        else:
            self.stdout.write(self.style.ERROR('Access token not found.')) 