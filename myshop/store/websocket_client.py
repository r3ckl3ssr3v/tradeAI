import websocket
import json
import threading
import logging
import MarketDataFeed_pb2 as pb
import asyncio
import websockets
import requests
import os

# Set up basic logging
logging.basicConfig(level=logging.INFO)

logger = logging.getLogger(__name__)

class MarketDataWebSocket:
    def __init__(self, access_token):
        self.access_token = access_token
        self.ws = None

    def on_message(self, ws, message):
        logger.info(f"Raw message received: {message}")  # Log every raw message
        data = pb.FeedResponse()
        data.ParseFromString(message)
        logger.info(f"Received message: {data}")

        # Check the type of the incoming message
        if data.type == "market_info":
            # Handle market status updates
            logger.info("Market status update received.")
            market_info = data.marketInfo
            # Log segment statuses
            for segment in market_info.segmentStatus:
                logger.info(f"Segment: {segment.key}, Status: {segment.value}")

        elif data.type == "live_feed":
            # Handle live market data updates
            logger.info("Live market data update received.")
            for instrument_key, instrument_data in data.feeds.items():
                if instrument_key in ["NSE_INDEX|Nifty Bank", "NSE_INDEX|Nifty 50"]:
                    # Extract LTP and other relevant data
                    ltp = instrument_data.ltpc.ltp
                    volume = instrument_data.ltpc.volume  # Adjust based on actual structure
                    logger.info(f"Instrument: {instrument_key}, LTP: {ltp}, Volume: {volume}")

                    # Print the live market feed to the terminal
                    print(f"Instrument: {instrument_key}, Last Traded Price: ₹{ltp}, Volume: {volume}")

                    # Prepare the data to send to the backend
                    formatted_market_data = {
                        'status': market_info,  # Adjust based on your needs
                        'last_price': ltp,
                        'volume': volume
                    }

                    # Send the data to the Django backend
                    try:
                        response = requests.post('http://127.0.0.1:8000/update-market-data/', json=formatted_market_data)
                        if response.status_code == 200:
                            logger.info("Market data sent to the backend successfully.")
                        else:
                            logger.error("Failed to send market data to the backend.")
                    except Exception as e:
                        logger.error(f"Error sending market data to the backend: {e}")

        elif data.type == "snapshot":
            logger.info("Market data snapshot received.")
            for instrument_key, instrument_data in data.feeds.items():
                if instrument_key in ["NSE_INDEX|Nifty Bank", "NSE_INDEX|Nifty 50"]:
                    ltp = instrument_data.ltpc.ltp
                    logger.info(f"Snapshot for {instrument_key}: LTP: {ltp}")
                    print(f"Snapshot for {instrument_key}: Last Traded Price: ₹{ltp}")

    def on_error(self, ws, error):
        logger.error(f"WebSocket error: {error}")

    def on_close(self, ws, close_status_code):
        logger.info(f"WebSocket closed with code: {close_status_code}")

    def on_open(self, ws):
        logger.info("WebSocket connection opened")
        # Start the subscription in a new asyncio task
        asyncio.run_coroutine_threadsafe(self.subscribe_to_market_data(), asyncio.get_event_loop())

    async def subscribe_to_market_data(self):
        request = {
            "guid": "13syxu852ztodyqncwt0",  # Generate a unique GUID for each request
            "method": "sub",
            "data": {
                "mode": "full",  # Use "full" mode to get comprehensive data
                "instrumentKeys": ["NSE_INDEX|Nifty Bank", "NSE_INDEX|Nifty 50"]  # Add your instrument keys here
            }
        }
        await self.ws.send(json.dumps(request))
        logger.info("Subscription request sent.")

    async def listen(self):
        while True:
            message = await self.ws.recv()
            self.on_message(message)

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
    access_token = "eyJ0eXAiOiJKV1QiLCJrZXlfaWQiOiJza192MS4wIiwiYWxnIjoiSFMyNTYifQ.eyJzdWIiOiIzRENXQlQiLCJqdGkiOiI2N2JjMmEyOGU5MmI0MDRiMmRiZjZjNmQiLCJpc011bHRpQ2xpZW50IjpmYWxzZSwiaWF0IjoxNzQwMzg0ODA4LCJpc3MiOiJ1ZGFwaS1nYXRld2F5LXNlcnZpY2UiLCJleHAiOjE3NDA0MzQ0MDB9.loYXb3XEUmof8WKngLwwKJQ_STGuT_pjKANUdwiLcoA"  # Replace with your actual access token
    market_data_ws = MarketDataWebSocket(access_token)
    market_data_ws.run()