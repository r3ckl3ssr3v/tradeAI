import websocket
import json
import threading
import logging
import MarketDataFeed_pb2 as pb
import asyncio
import websockets
import requests

# Set up basic logging
logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

class MarketDataWebSocket:
    def __init__(self, access_token):
        self.access_token = access_token
        self.ws = None

    def on_message(self, ws, message):
        data = pb.FeedResponse()
        data.ParseFromString(message)
        logger.info(f"Received message: {data}")

        # Extract relevant data from the FeedResponse object
        market_data = {
            'currentTs': data.currentTs,
            'marketInfo': {}
        }

        # Check if marketInfo and segmentStatus are present
        if data.marketInfo and data.marketInfo.segmentStatus:
            for segment in data.marketInfo.segmentStatus:
                # Check if segment is a valid object
                if hasattr(segment, 'key') and hasattr(segment, 'value'):
                    market_data['marketInfo'][segment.key] = segment.value
                else:
                    logger.error("Segment does not have key and value attributes.")
                    logger.error(f"Segment data: {segment}")  # Log the segment data for debugging

        # Send the data to the Django backend
        try:
            response = requests.post('http://127.0.0.1:8000/update-market-data/', json=market_data)  # Updated URL
            if response.status_code == 200:
                logger.info("Market data sent to the backend successfully.")
            else:
                logger.error("Failed to send market data to the backend.")
        except Exception as e:
            logger.error(f"Error sending market data to the backend: {e}")

    def on_error(self, ws, error):
        logger.error(f"WebSocket error: {error}")

    def on_close(self, ws, close_status_code):
        logger.info(f"WebSocket closed with code: {close_status_code}")

    def on_open(self, ws):
        logger.info("WebSocket connection opened")
        # Start the subscription in a new asyncio task
        asyncio.run_coroutine_threadsafe(self.subscribe_to_market_data(), asyncio.get_event_loop())

    async def subscribe_to_market_data(self):
        # Example subscription request
        request = {
            "guid": "unique-guid-12345",  # Generate a unique GUID for each request
            "method": "sub",
            "data": {
                "mode": "full",  # Change to "ltpc" or "option_greeks" as needed
                "instrumentKeys": ["NSE_INDEX|Nifty Bank", "NSE_INDEX|Nifty 50"]  # Add multiple instrument keys
            }
        }
        await self.ws.send(json.dumps(request))  # Ensure self.ws is initialized
        logger.info("Subscription request sent.")

    def run(self):
        # Connect to the WebSocket endpoint
        url = "wss://api.upstox.com/v3/feed/market-data-feed"
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        self.ws = websocket.WebSocketApp(url,
                                          on_open=self.on_open,
                                          on_message=self.on_message,
                                          on_error=self.on_error,
                                          on_close=self.on_close,
                                          header=headers)
        self.ws.run_forever()

# Example usage
if __name__ == "__main__":
    access_token = "eyJ0eXAiOiJKV1QiLCJrZXlfaWQiOiJza192MS4wIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiIzRENXQlQiLCJqdGkiOiI2N2I5ZDJkNGJkYzkyODc2NGNiYTRlNjIiLCJpc011bHRpQ2xpZW50IjpmYWxzZSwiaWF0IjoxNzQwMjMxMzgwLCJpc3MiOiJ1ZGFwaS1nYXRld2F5LXNlcnZpY2UiLCJleHAiOjE3NDAyNjE2MDB9.5Nm-HNFWdVJZSBnuJtKt54L0zX7bTQNPZWBD_shj2P8"  # Replace with your actual access token
    market_data_ws = MarketDataWebSocket(access_token)
    market_data_ws.run()