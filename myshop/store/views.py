import http.client
import json
import logging
import requests
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, JsonResponse
from django.conf import settings
from .forms import LoginForm, ProductForm
from .models import Product, AIChatHistory
from openai import OpenAI
from django.contrib.auth.models import User
from django.contrib import messages
from urllib.parse import quote
from datetime import datetime, timedelta
import re
from django.views.decorators.csrf import csrf_exempt
from django.core.files.storage import FileSystemStorage


logger = logging.getLogger(__name__)

ANGEL_ONE_LOGIN_URL = "https://apiconnect.angelone.in/rest/auth/angelbroking/user/v1/loginByPassword"
ANGEL_ONE_PROFILE_URL = "https://apiconnect.angelone.in/rest/secure/angelbroking/user/v1/getProfile"
ANGEL_TOKEN_URL = "/rest/auth/angelbroking/jwt/v1/generateTokens"

# Initialize OpenAI client
client = OpenAI(api_key=settings.OPENAI_API_KEY)

# Add Upstox configuration to settings.py first
UPSTOX_API_KEY = settings.UPSTOX_API_KEY
UPSTOX_API_SECRET = settings.UPSTOX_API_SECRET
UPSTOX_REDIRECT_URI = settings.UPSTOX_REDIRECT_URI

def angel_one_login(request):
    """Redirect to Angel One login page."""
    # Construct the Angel One login URL using settings
    login_url = settings.ANGEL_ONE_LOGIN_URL
    
    # You can generate a unique state parameter for security
    state = "statevariable"  # You might want to generate this dynamically
    
    # Construct the full login URL with all parameters
    auth_url = "https://smartapi.angelone.in/publisher-login"
    full_url = f"{auth_url}?api_key={settings.ANGEL_API_KEY}&state={state}&redirect_uri={settings.ANGEL_REDIRECT_URI}"
    
    logger.debug(f"Redirecting to Angel One login: {full_url}")
    return redirect(full_url)


def generate_token(request):
    """Generate JWT token using refresh token."""
    refresh_token = request.session.get("angel_refresh_token")
    
    if not refresh_token:
        logger.error("Refresh token missing. Redirecting to login.")
        return redirect("login")

    conn = http.client.HTTPSConnection("apiconnect.angelone.in")
    payload = json.dumps({"refreshToken": refresh_token})

    headers = {
        "Authorization": f"Bearer {request.session.get('angel_auth_token')}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "CLIENT_LOCAL_IP",
        "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
        "X-MACAddress": "MAC_ADDRESS",
        "X-PrivateKey": settings.ANGEL_API_KEY,
    }

    conn.request("POST", ANGEL_TOKEN_URL, payload, headers)
    res = conn.getresponse()
    data = json.loads(res.read().decode("utf-8"))

    if "data" in data and "jwtToken" in data["data"]:
        request.session["auth_token"] = data["data"]["jwtToken"]
        logger.debug("JWT Token successfully updated in session.")
        return redirect("dashboard")
    else:
        logger.error("Token generation failed.")
        return render(request, "error.html", {"message": "Token generation failed."})


def user_login(request):
    if request.method == "POST":
        form = LoginForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data["username"]
            password = form.cleaned_data["password"]
            user = authenticate(request, username=username, password=password)
            if user:
                login(request, user)
                logger.debug(f"User '{username}' authenticated successfully.")
                return redirect('broker_select')  # Redirect to broker selection
            else:
                messages.error(request, "Invalid username or password.")
    else:
        form = LoginForm()
    return render(request, "store/login.html", {"form": form})


@login_required
def add_product(request):
    if request.method == "POST":
        form = ProductForm(request.POST)
        if form.is_valid():
            form.save()
            return redirect("dashboard")
    else:
        form = ProductForm()
    return render(request, "store/add_product.html", {"form": form})


def home(request):
    # Check if this is a callback from Angel One with tokens
    auth_token = request.GET.get('auth_token')
    refresh_token = request.GET.get('refresh_token')
    
    if auth_token and refresh_token:
        # Store tokens in session
        request.session["angel_auth_token"] = auth_token
        request.session["angel_refresh_token"] = refresh_token
        logger.debug("Received tokens from Angel One, redirecting to profile")
        return redirect('get-angel-profile')
    
    return render(request, "store/home.html")


def angel_one_callback(request):
    """Handles the callback from Angel One."""
    print("Angel One Callback received:", request.GET)  # Debug print
    
    # Check if there's an error in the callback
    if 'error' in request.GET:
        logger.error(f"Angel One returned error: {request.GET['error']}")
        return redirect('login')
    
    auth_code = request.GET.get('code')
    if not auth_code:
        logger.error("Authentication failed. Missing authorization code.")
        return redirect('login')
    
    try:
        # Exchange the authorization code for tokens
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-UserType": "USER",
            "X-SourceID": "WEB",
            "X-ClientLocalIP": "CLIENT_LOCAL_IP",
            "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
            "X-MACAddress": "MAC_ADDRESS",
            "X-PrivateKey": settings.ANGEL_API_KEY,
        }
        
        payload = json.dumps({
            "code": auth_code,
            "client_id": settings.ANGEL_API_KEY,
            "redirect_uri": settings.ANGEL_REDIRECT_URI
        })
        
        # Get tokens using the authorization code
        response = requests.post(ANGEL_ONE_LOGIN_URL, headers=headers, data=payload)
        data = response.json()
        
        if response.status_code != 200 or "data" not in data:
            logger.error(f"Failed to exchange auth code for tokens: {data}")
            return redirect('login')
        
        # Save tokens in session
        request.session["angel_auth_token"] = data["data"].get("jwtToken")
        request.session["angel_refresh_token"] = data["data"].get("refreshToken")
        
        # Add debug print
        print("Redirecting to get-angel-profile")
        return redirect('get-angel-profile')
        
    except Exception as e:
        logger.error(f"Exception in angel_one_callback: {str(e)}")
        return redirect('login')


def get_angel_profile(request):
    """Fetch user profile from Angel One API."""
    auth_token = request.session.get("angel_auth_token")
    if not auth_token:
        logger.error("No auth token found. Redirecting to login page.")
        return redirect("login")
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "CLIENT_LOCAL_IP",
        "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
        "X-MACAddress": "MAC_ADDRESS",
        "X-PrivateKey": settings.ANGEL_API_KEY
    }
    
    try:
        profile_url = "https://apiconnect.angelbroking.com/rest/secure/angelbroking/user/v1/getProfile"
        response = requests.get(profile_url, headers=headers)
        print("Profile API Response:", response.text)  # Debug print
        
        if response.status_code == 200:
            profile_data = response.json()
            if 'data' in profile_data:
                user_data = profile_data['data']
                # Convert string representations of lists to actual lists
                try:
                    exchanges = eval(user_data.get('exchanges', '[]'))
                    products = eval(user_data.get('products', '[]'))
                except:
                    exchanges = []
                    products = []

                user_profile = {
                    'client_code': user_data.get('clientcode', ''),
                    'name': user_data.get('name', ''),
                    'email': user_data.get('emailid', user_data.get('email', user_data.get('mail', ''))),
                    'phone_number': user_data.get('mobileno', user_data.get('mobile', user_data.get('phone', ''))),
                    'exchanges': exchanges,
                    'products': products,
                    'last_login': user_data.get('lastlogintime', ''),
                    'broker_id': user_data.get('brokerid', user_data.get('broker_id', '')),
                    'pan': user_data.get('pan', ''),
                    'dob': user_data.get('dob', ''),
                    'gender': user_data.get('gender', ''),
                }
                
                print("Processed user profile:", user_profile)
                
                request.session['user_profile'] = user_profile
                return redirect('dashboard')
            else:
                logger.error(f"Unexpected profile data format: {profile_data}")
        else:
            logger.error(f"Failed to fetch profile. Status: {response.status_code}, Response: {response.text}")
            
        request.session['profile_error'] = 'Failed to fetch profile data. Please try logging in again.'
        return redirect('dashboard')
        
    except Exception as e:
        logger.error(f"Exception while fetching profile: {str(e)}")
        request.session['profile_error'] = 'An error occurred while fetching your profile.'
        return redirect('dashboard')


def get_rms_data(request):
    """Fetch RMS (Risk Management System) data from Angel One API."""
    auth_token = request.session.get("angel_auth_token")
    if not auth_token:
        logger.error("No auth token found for RMS data fetch")
        return None
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Accept": "application/json",
        "X-UserType": "USER",
        "X-SourceID": "WEB",
        "X-ClientLocalIP": "CLIENT_LOCAL_IP",
        "X-ClientPublicIP": "CLIENT_PUBLIC_IP",
        "X-MACAddress": "MAC_ADDRESS",
        "X-PrivateKey": settings.ANGEL_API_KEY
    }
    
    try:
        rms_url = "https://apiconnect.angelone.in/rest/secure/angelbroking/user/v1/getRMS"
        response = requests.get(rms_url, headers=headers)
        
        # Debug prints
        print("\nRMS API Request Headers:", headers)
        print("\nRMS API Response Status:", response.status_code)
        print("\nRMS API Response:", response.text)
        
        if response.status_code == 200:
            rms_data = response.json()
            print("\nProcessed RMS Data:", rms_data)
            if rms_data.get('status') and 'data' in rms_data:
                return rms_data['data']
        logger.error(f"Failed to fetch RMS data: {response.text}")
        return None
    except Exception as e:
        logger.error(f"Exception while fetching RMS data: {str(e)}")
        return None


def get_upstox_funds_and_margin(request):
    """Fetch funds and margin information from Upstox."""
    try:
        access_token = request.session.get('upstox_access_token')
        if not access_token:
            logger.error("No access token found for Upstox funds fetch")
            return None

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }

        url = "https://api.upstox.com/v2/user/get-funds-and-margin"
        response = requests.get(url, headers=headers)
        
        # Debug prints
        print("\nUpstox Funds API Response Status:", response.status_code)
        print("\nUpstox Funds API Response:", response.text)

        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success' and 'data' in data:
                return data['data']
            
        logger.error(f"Failed to fetch Upstox funds data: {response.text}")
        return None

    except Exception as e:
        logger.error(f"Exception while fetching Upstox funds: {str(e)}")
        return None

# def get_upstox_instruments(request):
#     """Fetch available instruments from Upstox."""
#     try:
#         access_token = request.session.get('upstox_access_token')
#         if not access_token:
#             logger.error("No access token found for Upstox instruments fetch")
#             return None

#         headers = {
#             'Authorization': f'Bearer {access_token}',
#             'Accept': 'application/json'
#         }
        
#         # Use the correct market instruments endpoint
#         url = "https://api.upstox.com/v2/market/instruments"
        
#         # Add query parameters for NSE equity segment
#         params = {
#             'segment': 'NSE_EQ'  # Use segment instead of exchange
#         }
        
#         print(f"\nFetching instruments from: {url}")
#         print(f"Headers: {headers}")
#         print(f"Params: {params}")
        
#         response = requests.get(url, headers=headers, params=params)
        
#         print(f"\nInstruments API Response Status: {response.status_code}")
#         print(f"Response: {response.text[:500]}...")  # Print first 500 chars
        
#         if response.status_code == 200:
#             data = response.json()
#             if data.get('status') == 'success' and 'data' in data:
#                 instruments = []
#                 for item in data['data']:
#                     # Construct the instrument key in the correct format
#                     instrument_key = f"NSE_EQ|{item.get('isin', '')}"
                    
#                     instrument = {
#                         'instrument_key': instrument_key,
#                         'symbol': item.get('symbol'),
#                         'name': item.get('name'),
#                         'exchange': 'NSE_EQ',
#                         'last_price': item.get('last_price'),
#                         'tick_size': item.get('tick_size'),
#                         'lot_size': item.get('lot_size'),
#                     }
#                     instruments.append(instrument)
                
#                 print(f"Processed {len(instruments)} instruments")
#                 return instruments
            
#         logger.error(f"Failed to fetch instruments: {response.text}")
#         return None

#     except Exception as e:
#         logger.error(f"Exception while fetching instruments: {str(e)}")
#         return None


def get_upstox_intraday_data(request, instrument_key='NSE_EQ', interval='30minute'):
    """Fetch intraday candle data from Upstox API."""
    try:
        access_token = request.session.get('upstox_access_token')
        if not access_token:
            logger.error("No access token found for Upstox intraday data fetch")
            return None

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        # Construct the URL for intraday data
        url = f"https://api.upstox.com/v2/historical-candle/intraday/{instrument_key}/{interval}"
        
        # Debug prints
        print(f"\nFetching intraday data:")
        print(f"URL: {url}")
        print(f"Headers: {headers}")
        
        response = requests.get(url, headers=headers)
        
        print(f"Response Status: {response.status_code}")
        print(f"Response: {response.text[:500]}...")  # Print first 500 chars
        
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success' and 'data' in data:
                return {
                    'candles': data['data']['candles'],
                    'interval': interval,
                    'instrument_key': instrument_key
                }
        
        logger.error(f"Failed to fetch intraday data: {response.text}")
        return None

    except Exception as e:
        logger.error(f"Exception while fetching intraday data: {str(e)}")
        return None

@login_required
def dashboard(request):
    """Render the dashboard with user profile and additional data."""
    user_profile = None
    broker_name = None
    funds_data = None
    intraday_data = None
    instruments = None
    
    # Get interval from request, default to 1minute
    interval = request.GET.get('interval', '30minute')
    if interval not in ['1minute', '30minute', '60minute']:
        interval = '30minute'  # Default to 1minute if invalid interval
    
    # Check for Upstox profile
    if 'upstox_access_token' in request.session:
        user_profile = request.session.get('upstox_user_data')
        broker_name = 'Upstox'
        funds_data = get_upstox_funds_and_margin(request)
        
        # Get selected instrument from request or use default
        selected_instrument_key = request.GET.get('instrument')
        if selected_instrument_key:
            intraday_data = get_upstox_intraday_data(request, selected_instrument_key, interval)
        else:
            # Default to a specific instrument key if none is selected
            default_instrument_key = "NSE_EQ%7CINE848E01016"  # Example default
            intraday_data = get_upstox_intraday_data(request, default_instrument_key, interval)

    context = {
        'user_profile': user_profile,
        'broker_name': broker_name,
        'funds_data': funds_data,
        'intraday_data': intraday_data,
        'intervals': ['1minute', '30minute'],  # Allowed intervals
    }
    
    return render(request, 'store/dashboard.html', context)


def user_logout(request):
    """Handle both Django and Angel One logout."""
    try:
        # Angel One Logout
        auth_token = request.session.get('angel_auth_token')
        if auth_token:
            headers = {
                'Authorization': f'Bearer {auth_token}',
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-UserType': 'USER',
                'X-SourceID': 'WEB',
                'X-ClientLocalIP': 'CLIENT_LOCAL_IP',
                'X-ClientPublicIP': 'CLIENT_PUBLIC_IP',
                'X-MACAddress': 'MAC_ADDRESS',
                'X-PrivateKey': settings.ANGEL_API_KEY
            }

            # Get client code from session
            user_profile = request.session.get('user_profile', {})
            client_code = user_profile.get('client_code', '')

            payload = json.dumps({
                "clientcode": client_code
            })

            conn = http.client.HTTPSConnection("apiconnect.angelone.in")
            conn.request(
                "POST",
                "/rest/secure/angelbroking/user/v1/logout",
                payload,
                headers
            )
            
            response = conn.getresponse()
            data = response.read()
            logger.info(f"Angel One logout response: {data.decode('utf-8')}")

            # Clear Angel One related session data
            request.session.pop('angel_auth_token', None)
            request.session.pop('angel_refresh_token', None)
            request.session.pop('user_profile', None)
    
    except Exception as e:
        logger.error(f"Error during Angel One logout: {str(e)}")
    
    finally:
        # Django logout
        logout(request)
        return redirect('login')


# Initialize OpenAI client
client = OpenAI(api_key=settings.OPENAI_API_KEY)

def chat_with_ai(request):
    if request.method == 'POST':
        try:
            message = request.POST.get('message')
            uploaded_file = request.FILES.get('file')  # Get the uploaded file
            
            # Handle file upload if present
            if uploaded_file:
                fs = FileSystemStorage()
                filename = fs.save(uploaded_file.name, uploaded_file)  # Save the file
                file_url = fs.url(filename)  # Get the file URL
                print(f"File uploaded: {file_url}")  # Debug print

                # You can process the file as needed here (e.g., save to database, send to AI, etc.)

            print("\n--- OpenAI API Request ---")
            print(f"User Message: {message}")
            
            # Get chat response from OpenAI using the new API format
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "system", "content": "You are a helpful assistant for trading and investment queries. Provide clear, concise advice while reminding users about investment risks."},
                    {"role": "user", "content": message}
                ],
                temperature=0.7,
                max_tokens=500
            )
            
            # Print complete API response
            print("\n--- OpenAI API Response ---")
            print(f"Model: {response.model}")
            print(f"Response ID: {response.id}")
            print(f"Created: {response.created}")
            print(f"Tokens Used: {response.usage}")
            print(f"Response Content: {response.choices[0].message.content}")
            print("------------------------\n")
            
            # Extract response from the new API format
            ai_response = response.choices[0].message.content

            # Save to history
            AIChatHistory.objects.create(
                user=request.user,
                message=message,
                response=ai_response
            )
            
            return JsonResponse({
                'status': 'success',
                'response': ai_response
            })
            
        except Exception as e:
            print(f"Error in chat_with_ai: {str(e)}")  # Debug print
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)


def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']
        
        if password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('signup')
            
        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already exists!")
            return redirect('signup')
            
        # Create user
        user = User.objects.create_user(username=username, password=password)
        messages.success(request, "Account created successfully! Please login.")
        return redirect('login')
        
    return render(request, 'store/signup.html')


def upstox_login(request):
    """Initialize Upstox login flow."""
    try:
        # URL encode the redirect URI
        encoded_redirect_uri = quote(settings.UPSTOX_REDIRECT_URI, safe='')
        
        # Generate a state parameter (optional but recommended for security)
        state = f"upstox_state_{request.user.id}"
        
        # Construct the Upstox login URL with all required parameters
        auth_url = (
            f"https://api.upstox.com/v2/login/authorization/dialog"
            f"?client_id={settings.UPSTOX_API_KEY}"
            f"&redirect_uri={encoded_redirect_uri}"
            f"&response_type=code"  # Required parameter
            f"&state={state}"  # Optional but recommended
        )
        
        # Log the URL for debugging
        print(f"Upstox Login URL: {auth_url}")  # Debug print
        logger.debug(f"Redirecting to Upstox login: {auth_url}")
        
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"Error initiating Upstox login: {str(e)}")
        messages.error(request, "Failed to connect to Upstox. Please try again.")
        return redirect('broker_select')

def upstox_callback(request):
    """Handle the callback from Upstox and exchange code for tokens."""
    try:
        # Log the callback data for debugging
        print("Upstox callback received:", request.GET)
        
        # Check for errors in callback
        if 'error' in request.GET:
            logger.error(f"Upstox returned error: {request.GET['error']}")
            messages.error(request, "Authentication failed with Upstox.")
            return redirect('broker_select')

        # Get the authorization code
        code = request.GET.get('code')
        if not code:
            logger.error("No authorization code received from Upstox")
            messages.error(request, "No authorization code received.")
            return redirect('broker_select')

        # Prepare token exchange request
        token_url = "https://api.upstox.com/v2/login/authorization/token"
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Accept': 'application/json'
        }
        
        payload = {
            'code': code,
            'client_id': settings.UPSTOX_API_KEY,
            'client_secret': settings.UPSTOX_API_SECRET,
            'redirect_uri': settings.UPSTOX_REDIRECT_URI,
            'grant_type': 'authorization_code'
        }

        # Exchange code for tokens
        print("Requesting token with payload:", payload)  # Debug print
        response = requests.post(token_url, headers=headers, data=payload)
        print("Token response status:", response.status_code)  # Debug print
        print("Token response:", response.text)  # Debug print

        if response.status_code == 200:
            token_data = response.json()
            
            # Store tokens and user data in session
            request.session['upstox_access_token'] = token_data.get('access_token')
            request.session['upstox_extended_token'] = token_data.get('extended_token')
            
            # Store additional user data
            user_data = {
                'email': token_data.get('email'),
                'user_id': token_data.get('user_id'),
                'user_name': token_data.get('user_name'),
                'user_type': token_data.get('user_type'),
                'broker': token_data.get('broker'),
                'exchanges': token_data.get('exchanges', []),
                'products': token_data.get('products', []),
                'order_types': token_data.get('order_types', []),
                'is_active': token_data.get('is_active'),
                'poa': token_data.get('poa'),
            }
            
            request.session['upstox_user_data'] = user_data
            
            # Debug prints
            print("Stored access token:", request.session['upstox_access_token'])
            print("Stored user data:", user_data)

            messages.success(request, "Successfully logged in to Upstox!")
            return redirect('dashboard')
            
        else:
            logger.error(f"Failed to get access token. Status: {response.status_code}, Response: {response.text}")
            messages.error(request, "Failed to get access token from Upstox.")
            return redirect('broker_select')

    except Exception as e:
        logger.error(f"Exception in upstox_callback: {str(e)}")
        print(f"Upstox callback error: {str(e)}")  # Debug print
        messages.error(request, "An error occurred during Upstox authentication.")
        return redirect('broker_select')

def get_upstox_profile(request):
    """Fetch user profile from Upstox API."""
    try:
        access_token = request.session.get('upstox_access_token')
        if not access_token:
            logger.error("No access token found for Upstox profile fetch")
            return None

        headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/json'
        }
        
        profile_url = "https://api.upstox.com/v2/user/profile"
        response = requests.get(profile_url, headers=headers)
        
        # Log the response for debugging
        print("Upstox Profile API Response:", response.text)
        
        if response.status_code == 200:
            profile_data = response.json()
            if profile_data['status'] == 'success' and 'data' in profile_data:
                user_data = profile_data['data']
                # Format the profile data
                formatted_profile = {
                    'broker_name': 'Upstox',
                    'user_id': user_data.get('user_id'),
                    'user_name': user_data.get('user_name'),
                    'email': user_data.get('email'),
                    'exchanges': user_data.get('exchanges', []),
                    'products': user_data.get('products', []),
                    'order_types': user_data.get('order_types', []),
                    'user_type': user_data.get('user_type'),
                    'is_active': user_data.get('is_active'),
                    'poa': user_data.get('poa'),
                    'ddpi': user_data.get('ddpi')
                }
                return formatted_profile
            
        logger.error(f"Failed to fetch Upstox profile. Status: {response.status_code}")
        return None

    except Exception as e:
        logger.error(f"Exception while fetching Upstox profile: {str(e)}")
        return None

def broker_select(request):
    """View for broker selection page"""
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'store/broker_select.html')

def get_option_contracts(request):
    if request.method == 'GET':
        instrument_key = request.GET.get('instrument_key')
        expiry_date = request.GET.get('expiry_date', None)

        access_token = request.session.get('upstox_access_token')

        if not access_token:
            return JsonResponse({'status': 'error', 'message': 'Access token is missing or invalid.'}, status=401)

        url = f'https://api.upstox.com/v2/option/contract?instrument_key={instrument_key}&expiry_date={expiry_date}'
        
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {access_token}'
        }

        response = requests.get(url, headers=headers)

        # Log the response content for debugging
        logger.info(f"Response from Upstox API: {response.text}")  # Log the response text

        if response.status_code == 200:
            return JsonResponse(response.json())
        else:
            return JsonResponse({'status': 'error', 'message': response.text}, status=response.status_code)

    return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

def get_option_chain(request):
       if request.method == 'GET':
           instrument_key = request.GET.get('instrument_key')
           expiry_date = request.GET.get('expiry_date')

           access_token = request.session.get('upstox_access_token')

           if not access_token:
               return JsonResponse({'status': 'error', 'message': 'Access token is missing or invalid.'}, status=401)

           url = 'https://api.upstox.com/v2/option/chain'
           params = {
               'instrument_key': instrument_key,
               'expiry_date': expiry_date
           }
           headers = {
               'Accept': 'application/json',
               'Authorization': f'Bearer {access_token}'
           }

           response = requests.get(url, params=params, headers=headers)

           # Log the response for debugging
           logger.info(f"Response from Upstox API: {response.text}")

           if response.status_code == 200:
               return JsonResponse(response.json())
           else:
               return JsonResponse({'status': 'error', 'message': response.text}, status=response.status_code)

       return JsonResponse({'status': 'error', 'message': 'Invalid request'}, status=400)

def get_access_token(code):
    """
    Retrieve the access token from Upstox using the authorization code.
    
    Parameters:
    - code: The authorization code received after user authorization.
    
    Returns:
    - The access token and other user details if successful, otherwise None.
    """
    # Retrieve client_id, client_secret, and redirect_uri from settings
    client_id = settings.UPSTOX_API_KEY  # Ensure this is defined in your settings.py
    client_secret = settings.UPSTOX_API_SECRET  # Ensure this is defined in your settings.py
    redirect_uri = settings.UPSTOX_REDIRECT_URI  # Ensure this is defined in your settings.py

    # Construct the URL for token request
    url = "https://api.upstox.com/v2/login/authorization/token"
    
    # Set the headers
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Accept': 'application/json',
    }
    
    # Set the request body
    payload = {
        'code': code,
        'client_id': client_id,
        'client_secret': client_secret,
        'redirect_uri': redirect_uri,
        'grant_type': 'authorization_code'
    }
    
    # Make the POST request
    response = requests.post(url, headers=headers, data=payload)
    
    # Check the response status
    if response.status_code == 200:
        print("Access token request successful.")
        token_data = response.json()  # Get the JSON response
        print("Response:", token_data)  # Print the JSON response
        return token_data  # Return the token data
    else:
        print("Error requesting access token:", response.status_code, response.text)
        return None

# Example usage
# You would call this function with the authorization code received after user authorization
# For example: token_info = get_access_token("your_authorization_code")

@csrf_exempt  # Disable CSRF protection for this view (only for testing)
def notifier_webhook(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        # Process the incoming data (e.g., save the access token)
        access_token = data.get('access_token')
        if access_token:
            print("Access Token received:", access_token)
            # Save the access token securely (e.g., in the database or session)
            return JsonResponse({'status': 'success'})
        return JsonResponse({'status': 'error', 'message': 'Access token not found.'}, status=400)
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'}, status=405)

def request_access_token_via_notifier():
    """
    Request an access token from Upstox and trigger user notifications.
    
    Returns:
    - The response from the Upstox API if successful, otherwise None.
    """
    # Retrieve client_id and client_secret from settings
    client_id = settings.UPSTOX_API_KEY  # Ensure this is defined in your settings.py
    client_secret = settings.UPSTOX_API_SECRET  # Ensure this is defined in your settings.py

    # Construct the URL for token request
    url = f"https://api.upstox.com/v3/login/auth/token/request/{client_id}"
    
    # Set the headers
    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/json',
    }
    
    # Set the request body
    data = {
        'client_secret': client_secret
    }
    
    # Make the POST request
    response = requests.post(url, headers=headers, json=data)
    
    # Check the response status
    if response.status_code == 200:
        print("Access token request initiated successfully.")
        print("Response:", response.json())  # Print the JSON response
        return response.json()  # Return the response data
    else:
        print("Error requesting access token:", response.status_code, response.text)
        return None

# Example usage
# Call this function to initiate the access token request
# response_data = request_access_token_via_notifier()

@csrf_exempt  # Use this if you're not using CSRF tokens for this endpoint
def update_market_data(request):
    if request.method == 'POST':
        try:
            market_data = json.loads(request.body)
            # Process and store the market data as needed
            # For example, you can store it in the session or a database
            request.session['market_data'] = market_data  # Store in session for simplicity
            return JsonResponse({'status': 'success'})
        except Exception as e:
            return JsonResponse({'status': 'error', 'message': str(e)})
    return JsonResponse({'status': 'error', 'message': 'Invalid request method.'})

def get_market_data(request):
    market_data = request.session.get('market_data', {})
    return JsonResponse({'market_data': market_data})
