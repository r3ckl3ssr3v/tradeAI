# Launching a Web Application on Localhost

This guide provides step-by-step instructions for setting up and launching your web application on your local machine.

## Prerequisites

Before starting, ensure you have the following tools installed on your system:

- **Python 3.x** (Preferably Python 3.8 or above)
- **Django** (or any other web framework you're using)
- **Virtual Environment** (for managing dependencies)
- **Ngrok** (if needed for external access via a tunneling service)
- **Text Editor or IDE** (e.g., Visual Studio Code, PyCharm, etc.)

## Steps to Launch the Web Application Locally

### 1. Clone the Repository

Begin by cloning the repository to your local machine. If you have a GitHub repository, use the following command:

- git clone [https://github.com/your-username/your-repository-name.git](https://github.com/r3ckl3ssr3v/django_api.git)
- cd your-repository-name

### 2. Set Up a Virtual Environment
A virtual environment is recommended to isolate your project dependencies.

For Windows:
- python -m venv venv
- .\venv\Scripts\activate

For macOS/Linux:
- python3 -m venv venv
- source venv/bin/activate

### 3. Install Project Dependencies
Next, install all required dependencies listed in the requirements.txt file:
- pip install -r requirements.txt

### 4. Set Up Configuration
Ensure you have the correct settings in place. This might include API keys, database settings, or any other configuration variables. These are typically located in a settings or configuration file, such as settings.py for Django.

Example Configuration (Django):
In settings.py, ensure that the ALLOWED_HOSTS include your local server address (127.0.0.1 or localhost):

ALLOWED_HOSTS = ['127.0.0.1', 'localhost']

### 5. Run Database Migrations (if applicable)
If your project uses a database (such as SQLite, PostgreSQL, etc.), run the following command to set up the database schema:

- python manage.py migrate
  
This command applies the necessary database migrations to ensure everything is set up correctly.

### 6. Launch the Web Server
Now, you can start the Django development server (or the relevant server for your framework):

- python manage.py runserver
- This will start the development server at http://127.0.0.1:8000/.

If using Django, the default address will be http://127.0.0.1:8000/.
If using other frameworks, refer to their respective commands for starting the local server.

### 7. Obtain Access Token
After starting the Django server, navigate to the appropriate endpoint in your web browser to log in and obtain the access token. This token is necessary for the WebSocket client to connect to the market data feed.

### 8. Update WebSocket Client
1. Open the `myshop/store/websocket_client.py` file.
2. Locate line number 91, which should look like this:
   ```python
   access_token = "YOUR_ACCESS_TOKEN"  # Replace with your actual access token
   ```
3. Replace `"YOUR_ACCESS_TOKEN"` with the access token you obtained from the previous step.

### 9. Start the WebSocket Client
After updating the access token, you can start the WebSocket client by running the following command in your terminal:

- python myshop/store/websocket_client.py

### 10. Access the Application
Open your web browser and navigate to the following URL:

- http://127.0.0.1:8000/
  
This will load the homepage of your web application running locally.

### 11. Expose Localhost Externally Using Ngrok
If you want to expose your local development environment to the outside world (e.g., for testing with APIs or sharing with others), you can use Ngrok.

Download and install Ngrok.
Start Ngrok with the following command to tunnel the local server:

- ngrok http 127.0.0.1:8000
  
Ngrok will provide a public URL (e.g., https://abcd-1234.ngrok.io) that you can use to access your local server externally.

### 12. Create an app in the https://smartapi.angelbroking.com/create and paste the ngrok link in the Redirect URL there.
- Add ngrok URL to CSRF_TRUSTED_ORIGINS in settings.py.
- Modify settings.py
- Add the API credentials you received from Angel Broking to your settings.py file

  - ANGEL_API_KEY = "your_api_key_here"
  - ANGEL_API_SECRET = "your_api_secret_here"
  - ANGEL_REDIRECT_URI = "[http://127.0.0.1:8000/angel_callback/](https://smartapi.angelone.in/publisher-login?api_key=xxx&state=statevariable)"


# Trading Dashboard Integration Guide

## Overview
This guide details the integration of Angel One and Upstox trading platforms into a Django-based trading dashboard. The dashboard provides user authentication, profile display, and trading information for both platforms.

## Features Added
- Broker selection interface after login
- Angel One integration with RMS data
- Upstox integration with profile and funds data
- AI Trading Assistant chat interface
- Responsive dashboard design
- Live market data integration via WebSocket

## Prerequisites
- Python 3.9+
- Django 4.2+
- ngrok (for development)
- Angel One API credentials
- Upstox API credentials

## Configuration

### Angel One Setup
1. Register at Angel One Developer Portal
2. Create a new application
3. Note down API key and secret
4. Set callback URL in the developer portal

### Upstox Setup
1. Register at Upstox Developer Portal
2. Create a new application
3. Note down API key and secret
4. Set callback URL in the developer portal

### URL Configuration
Update `myshop/store/urls.py` with new endpoints.

## Running the Application

1. Start the Django development server:

 - python manage.py runserver

2. Use ngrok to expose your local server:

 - ngrok http 127.0.0.1:8000

3. Update the redirect URLs in the developer portals:

- Angel One:

 - Redirect URL: "https://77d3-2401-4900-8fd1-a86a-4db2-d1cc-6ce5-ad2.ngrok-free.app/angel-one-callback/"

- Upstox:

 - Redirect URL: https://77d3-2401-4900-8fd1-a86a-4db2-d1cc-6ce5-ad2.ngrok-free.app/upstox-callback/"

3. Update callback URLs in both broker portals with your ngrok URL

## User Flow

1. User logs into the application
2. Redirected to broker selection page
3. Chooses between Angel One and Upstox
4. Authenticates with chosen broker
5. Redirected back to dashboard showing:
   - Profile information
   - Trading information
   - Funds/RMS data
   - AI Trading Assistant
   - Live market data

## Key Files Modified

- `store/views.py`: Added broker integration logic
- `store/templates/store/broker_select.html`: New broker selection interface
- `store/templates/store/dashboard.html`: Updated dashboard layout to include live market data
- `store/urls.py`: Added new URL patterns
- `myshop/settings.py`: Added broker API configurations

## Security Considerations

- Store sensitive credentials in environment variables
- Implement proper session management
- Use HTTPS for all API communications
- Validate all API responses
- Implement proper error handling

## Troubleshooting

### Common Issues:
1. Callback URL mismatch:
   - Ensure URLs in broker portals match your application
   - Check for trailing slashes

2. Authentication failures:
   - Verify API credentials
   - Check token expiration
   - Validate request headers

3. Data not displaying:
   - Check console for API responses
   - Verify session storage
   - Check template rendering conditions