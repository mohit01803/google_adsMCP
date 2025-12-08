from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
import sys
from datetime import datetime, timedelta
from pathlib import Path
import hashlib

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import logging

# ============================================================================
# LOAD ENVIRONMENT VARIABLES FIRST
# ============================================================================
try:
    from dotenv import load_dotenv
    env_path = Path('.') / '.env'
    if env_path.exists():
        load_dotenv(dotenv_path=env_path)
        print(f"✓ Loaded .env from: {env_path.absolute()}")
    else:
        print("⚠ .env not found - using hardcoded Neon defaults")
except ImportError:
    print("⚠ python-dotenv not installed")

# Import PostgreSQL storage AFTER loading env vars
from postgres_storage import PostgresTokenStorage

# MCP - Support both package layouts
try:
    from fastmcp import FastMCP
except ImportError:
    from mcp.server.fastmcp import FastMCP

# ============================================================================
# CONFIGURE LOGGING - CONSOLE ONLY (NO FILE LOGGING FOR FASTMCP!)
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stderr)  # Console only - FastMCP compatible
    ]
)
logger = logging.getLogger('google_ads_server')

# ============================================================================
# FASTMCP INITIALIZATION - NO DEPENDENCIES PARAMETER (DEPRECATED)
# ============================================================================
mcp = FastMCP("google-ads-server")

# Constants and configuration
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"

# ============================================================================
# POSTGRES CONFIGURATION - NO FILE FALLBACK! PRODUCTION ONLY!
# ============================================================================
try:
    # FIX #1: CORRECTED HOST - Removed "localhost" prefix typo!
    POSTGRES_STORAGE = PostgresTokenStorage(
        host=os.getenv('POSTGRES_HOST', 'jolly-base-ad5zrzvc-pooler.c-2.us-east-1.aws.neon.tech'),
        port=int(os.getenv('POSTGRES_PORT', '5432')),
        database=os.getenv('POSTGRES_DB', 'neondb'),
        user=os.getenv('POSTGRES_USER', 'neondb_owner'),
        password=os.getenv('POSTGRES_PASSWORD', 'npg_3cGYslJfLRg6')
    )
    USE_POSTGRES = True
    logger.info("=" * 60)
    logger.info("✓ PostgreSQL connection successful!")
    logger.info("✓ Using PostgreSQL token storage (Neon.tech)")
    logger.info(f"  Host: {os.getenv('POSTGRES_HOST', 'jolly-base-ad5zrzvc-pooler.c-2.us-east-1.aws.neon.tech')}")
    logger.info(f"  Database: {os.getenv('POSTGRES_DB', 'neondb')}")
    logger.info("=" * 60)
except Exception as e:
    logger.error("=" * 60)
    logger.error(f"✗ PostgreSQL initialization failed: {e}")
    logger.error(f"  Error type: {type(e).__name__}")
    logger.error("⚠ CRITICAL: PostgreSQL required for production!")
    logger.error("=" * 60)
    USE_POSTGRES = False
    # FIX #2: NO FILE FALLBACK - Production must have PostgreSQL!
    raise Exception("PostgreSQL connection failed! Cannot run without database.")

logger.info("=" * 60)
logger.info("Google Ads MCP Server Starting (MULTI-USER MODE)...")
logger.info("Storage: PostgreSQL (Neon.tech) - NO FILE FALLBACK")
logger.info("=" * 60)

# Get credentials from environment variables
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_CLIENT_ID = os.environ.get("GOOGLE_ADS_CLIENT_ID")
GOOGLE_ADS_CLIENT_SECRET = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")

# MULTI-USER: In-memory cache for user credentials
USER_CREDENTIALS_CACHE = {}

# ============================================================================
# FIX #3: REMOVED ALL FILE STORAGE FUNCTIONS - POSTGRESQL ONLY!
# ============================================================================

def save_user_token(user_id: str, creds: Credentials):
    """Save user's OAuth token - PostgreSQL ONLY (NO FILE FALLBACK)."""
    if not USE_POSTGRES:
        error_msg = "PostgreSQL not available! Cannot save token."
        logger.error(error_msg)
        raise Exception(error_msg)
    
    try:
        if POSTGRES_STORAGE.save_token(user_id, creds):
            USER_CREDENTIALS_CACHE[user_id] = creds
            logger.info(f"✓ Token saved to PostgreSQL for user: {user_id}")
            return True
        else:
            raise Exception("PostgreSQL save_token returned False")
    except Exception as e:
        error_msg = f"Failed to save token to PostgreSQL: {e}"
        logger.error(error_msg)
        raise Exception(error_msg)

def load_user_token(user_id: str) -> Optional[Credentials]:
    """Load user's OAuth token - PostgreSQL ONLY (NO FILE FALLBACK)."""
    # Check in-memory cache first
    if user_id in USER_CREDENTIALS_CACHE:
        logger.info(f"✓ Loaded token from cache for user: {user_id}")
        return USER_CREDENTIALS_CACHE[user_id]
    
    if not USE_POSTGRES:
        logger.error("PostgreSQL not available! Cannot load token.")
        return None
    
    try:
        creds = POSTGRES_STORAGE.load_token(user_id)
        if creds:
            USER_CREDENTIALS_CACHE[user_id] = creds
            logger.info(f"✓ Loaded token from PostgreSQL for user: {user_id}")
            return creds
        else:
            logger.info(f"No token found in PostgreSQL for user: {user_id}")
            return None
    except Exception as e:
        logger.error(f"Failed to load token from PostgreSQL: {e}")
        return None

def delete_user_token(user_id: str):
    """Delete user's token - PostgreSQL ONLY (NO FILE FALLBACK)."""
    if USE_POSTGRES:
        try:
            POSTGRES_STORAGE.delete_token(user_id)
            logger.info(f"✓ Deleted token from PostgreSQL for user: {user_id}")
        except Exception as e:
            logger.error(f"Failed to delete token from PostgreSQL: {e}")
    
    # Always clear from cache
    if user_id in USER_CREDENTIALS_CACHE:
        del USER_CREDENTIALS_CACHE[user_id]
        logger.info(f"✓ Cleared token from cache for user: {user_id}")

def get_user_credentials(user_id: str, refresh_if_needed: bool = True) -> Credentials:
    """Get OAuth credentials for a specific user."""
    if not GOOGLE_ADS_CLIENT_ID or not GOOGLE_ADS_CLIENT_SECRET:
        raise ValueError("GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET must be set")
    
    creds = load_user_token(user_id)
    
    if creds and not creds.valid and refresh_if_needed:
        if creds.expired and creds.refresh_token:
            try:
                logger.info(f"Refreshing expired token for user: {user_id}")
                creds.refresh(Request())
                save_user_token(user_id, creds)
                logger.info(f"✓ Token refreshed successfully for user: {user_id}")
            except RefreshError as e:
                logger.error(f"Error refreshing token for user {user_id}: {e}")
                delete_user_token(user_id)
                raise ValueError(f"Token expired and could not be refreshed. User needs to re-authenticate.")
        else:
            raise ValueError("User credentials are invalid. Re-authentication required.")
    
    if not creds or not creds.valid:
        raise ValueError(f"No valid credentials found for user: {user_id}. Please authenticate first using start_oauth_flow()")
    
    return creds

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    customer_id = str(customer_id)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    return customer_id.zfill(10)

def get_headers(creds: Credentials, login_customer_id: Optional[str] = None):
    """Get headers for Google Ads API requests."""
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")
    
    if not creds.valid:
        raise ValueError("Invalid credentials")
    
    headers = {
        'Authorization': f'Bearer {creds.token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }
    
    if login_customer_id:
        headers['login-customer-id'] = format_customer_id(login_customer_id)
    
    return headers

# ============================================================================
# MULTI-USER AUTHENTICATION TOOLS (4 tools)
# ============================================================================

@mcp.tool()
async def start_oauth_flow(
    user_id: str = Field(description="Unique identifier for the user (email, username, etc.)"),
    redirect_uri: str = Field(default="urn:ietf:wg:oauth:2.0:oob", description="OAuth redirect URI")
) -> str:
    """Start OAuth authentication flow for a new user."""
    try:
        if not GOOGLE_ADS_CLIENT_ID or not GOOGLE_ADS_CLIENT_SECRET:
            return json.dumps({
                "error": "OAuth credentials not configured",
                "message": "GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET must be set"
            })
        
        client_config = {
            "installed": {
                "client_id": GOOGLE_ADS_CLIENT_ID,
                "client_secret": GOOGLE_ADS_CLIENT_SECRET,
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": [redirect_uri]
            }
        }
        
        flow = InstalledAppFlow.from_client_config(
            client_config,
            SCOPES,
            redirect_uri=redirect_uri
        )
        
        auth_url, _ = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'
        )
        
        USER_CREDENTIALS_CACHE[f"{user_id}_flow"] = flow
        
        return json.dumps({
            "success": True,
            "user_id": user_id,
            "authorization_url": auth_url,
            "instructions": [
                "1. Send this URL to the user",
                "2. User clicks the URL and grants access",
                "3. User receives an authorization code",
                "4. Call complete_oauth_flow() with the code"
            ],
            "next_step": f"complete_oauth_flow(user_id='{user_id}', auth_code='CODE_FROM_USER')"
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error starting OAuth flow for user {user_id}: {e}")
        return json.dumps({"error": str(e)})

@mcp.tool()
async def complete_oauth_flow(
    user_id: str = Field(description="Unique identifier for the user"),
    auth_code: str = Field(description="Authorization code received from Google")
) -> str:
    """Complete OAuth flow with the authorization code."""
    try:
        flow_key = f"{user_id}_flow"
        flow = USER_CREDENTIALS_CACHE.get(flow_key)
        
        if not flow:
            return json.dumps({
                "error": "OAuth flow not found",
                "message": f"Please call start_oauth_flow(user_id='{user_id}') first"
            })
        
        flow.fetch_token(code=auth_code)
        creds = flow.credentials
        
        save_user_token(user_id, creds)
        del USER_CREDENTIALS_CACHE[flow_key]
        
        try:
            headers = get_headers(creds)
            url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
            response = requests.get(url, headers=headers)
            
            if response.status_code == 200:
                customers = response.json()
                account_count = len(customers.get('resourceNames', []))
                
                return json.dumps({
                    "success": True,
                    "message": f"Authentication successful for user: {user_id}",
                    "accessible_accounts": account_count,
                    "storage": "PostgreSQL (Neon.tech)",
                    "next_steps": [
                        "User can now use all Google Ads tools",
                        f"Use user_id='{user_id}' in all tool calls"
                    ]
                }, indent=2)
        except Exception as e:
            logger.warning(f"Could not fetch accounts but auth succeeded: {e}")
        
        return json.dumps({
            "success": True,
            "message": f"Authentication successful for user: {user_id}",
            "storage": "PostgreSQL (Neon.tech)",
            "next_steps": [
                "User can now use all Google Ads tools",
                f"Use user_id='{user_id}' in all tool calls"
            ]
        }, indent=2)
        
    except Exception as e:
        logger.error(f"Error completing OAuth flow for user {user_id}: {e}")
        return json.dumps({
            "error": str(e),
            "message": "Failed to complete authentication"
        })

@mcp.tool()
async def check_user_auth(
    user_id: str = Field(description="Unique identifier for the user")
) -> str:
    """Check if a user is authenticated and their token is valid."""
    try:
        creds = load_user_token(user_id)
        
        if not creds:
            return json.dumps({
                "authenticated": False,
                "user_id": user_id,
                "message": "User not authenticated",
                "action": f"Call start_oauth_flow(user_id='{user_id}') to authenticate"
            }, indent=2)
        
        is_valid = creds.valid
        is_expired = creds.expired if hasattr(creds, 'expired') else False
        has_refresh = bool(creds.refresh_token) if hasattr(creds, 'refresh_token') else False
        
        expiry_str = creds.expiry.isoformat() if hasattr(creds, 'expiry') and creds.expiry else "Unknown"
        
        return json.dumps({
            "authenticated": True,
            "user_id": user_id,
            "token_valid": is_valid,
            "token_expired": is_expired,
            "has_refresh_token": has_refresh,
            "token_expiry": expiry_str,
            "storage": "PostgreSQL (Neon.tech)",
            "status": "ready" if is_valid else "needs_refresh"
        }, indent=2)
        
    except Exception as e:
        return json.dumps({
            "error": str(e),
            "user_id": user_id
        })

@mcp.tool()
async def revoke_user_access(
    user_id: str = Field(description="Unique identifier for the user")
) -> str:
    """Revoke access and delete stored credentials for a user."""
    try:
        delete_user_token(user_id)
        return json.dumps({
            "success": True,
            "message": f"Access revoked for user: {user_id}",
            "action": "User must re-authenticate to use tools again"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

# ============================================================================
# GOOGLE ADS TOOLS (21 tools) - WITH USER_ID
# ============================================================================

@mcp.tool()
async def list_accounts(
    user_id: str = Field(description="Unique identifier for the user")
) -> str:
    """List all accessible Google Ads accounts for a user."""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return f"No accessible accounts found for user: {user_id}"
        
        result_lines = [f"Accessible Google Ads Accounts for {user_id}:"]
        result_lines.append("-" * 50)
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            result_lines.append(f"Account ID: {formatted_id}")
        
        result_lines.append("\n" + "=" * 50)
        result_lines.append("💡 TIP: Use get_account_details() to see account names")
        result_lines.append("=" * 50)
        
        return "\n".join(result_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}\nPlease call start_oauth_flow(user_id='{user_id}') to authenticate."
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def get_campaign_performance(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get campaign performance metrics for a user's account."""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        
        query = f"""
            SELECT
                campaign.id,
                campaign.name,
                campaign.status,
                metrics.impressions,
                metrics.clicks,
                metrics.cost_micros,
                metrics.conversions,
                metrics.average_cpc
            FROM campaign
            WHERE segments.date DURING LAST_{days}_DAYS
            ORDER BY metrics.cost_micros DESC
            LIMIT 50
        """
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No campaign data found for the specified period."
        
        result_lines = [f"Campaign Performance for {user_id} - Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        
        for result in results['results']:
            campaign = result.get('campaign', {})
            metrics = result.get('metrics', {})
            
            result_lines.append(f"\nCampaign: {campaign.get('name', 'N/A')}")
            result_lines.append(f"  ID: {campaign.get('id', 'N/A')}")
            result_lines.append(f"  Status: {campaign.get('status', 'N/A')}")
            result_lines.append(f"  Impressions: {metrics.get('impressions', 0):,}")
            result_lines.append(f"  Clicks: {metrics.get('clicks', 0):,}")
            result_lines.append(f"  Cost (micros): {metrics.get('costMicros', 0):,}")
            result_lines.append(f"  Conversions: {metrics.get('conversions', 0)}")
            result_lines.append("-" * 80)
        
        return "\n".join(result_lines)
        
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error getting campaign performance: {str(e)}"

@mcp.tool()
async def execute_gaql_query(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    query: str = Field(description="Valid GAQL query string"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Execute a custom GAQL query for a user's account."""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        result_lines = [f"Query Results for {user_id} - Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        result_lines.append(json.dumps(results, indent=2))
        
        return "\n".join(result_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_account_details(
    user_id: str = Field(description="Unique identifier for the user"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get detailed information about all accessible accounts for a user."""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."
        
        result_lines = [f"📊 Detailed Account Information for {user_id}:"]
        result_lines.append("=" * 100)
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            
            query = """
                SELECT
                    customer.id,
                    customer.descriptive_name,
                    customer.currency_code,
                    customer.time_zone,
                    customer.manager,
                    customer.status
                FROM customer
                LIMIT 1
            """
            
            try:
                detail_url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_id}/googleAds:search"
                payload = {"query": query}
                detail_response = requests.post(detail_url, headers=headers, json=payload)
                
                if detail_response.status_code == 200:
                    detail_results = detail_response.json()
                    if detail_results.get('results'):
                        customer_data = detail_results['results'][0].get('customer', {})
                        
                        account_type = "🏢 Manager Account" if customer_data.get('manager') else "📈 Client Account"
                        
                        result_lines.append(f"\n{account_type}")
                        result_lines.append(f"  Account ID: {formatted_id}")
                        result_lines.append(f"  Name: {customer_data.get('descriptiveName', 'N/A')}")
                        result_lines.append(f"  Currency: {customer_data.get('currencyCode', 'N/A')}")
                        result_lines.append(f"  Time Zone: {customer_data.get('timeZone', 'N/A')}")
                        result_lines.append(f"  Status: {customer_data.get('status', 'N/A')}")
                        result_lines.append("-" * 80)
            except Exception as e:
                result_lines.append(f"\n  Account ID: {formatted_id}")
                result_lines.append(f"  (Error fetching details: {str(e)})")
                result_lines.append("-" * 80)
        
        return "\n".join(result_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error getting account details: {str(e)}"

@mcp.tool()
async def get_ad_performance(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get ad performance metrics for a user's account."""
    query = f"""
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.status,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.cost_micros,
            metrics.conversions
        FROM ad_group_ad
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 50
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def run_gaql(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    query: str = Field(description="Valid GAQL query string"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Execute any arbitrary GAQL query with custom formatting options."""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found for the query."
        
        if format.lower() == "json":
            return json.dumps(results, indent=2)
        
        elif format.lower() == "csv":
            fields = []
            first_result = results['results'][0]
            for key, value in first_result.items():
                if isinstance(value, dict):
                    for subkey in value:
                        fields.append(f"{key}.{subkey}")
                else:
                    fields.append(key)
            
            csv_lines = [",".join(fields)]
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, "")).replace(",", ";")
                    else:
                        value = str(result.get(field, "")).replace(",", ";")
                    row_data.append(value)
                csv_lines.append(",".join(row_data))
            
            return "\n".join(csv_lines)
        
        else:  # table format
            result_lines = [f"Query Results for {user_id} - Account {formatted_customer_id}:"]
            result_lines.append("-" * 100)
            result_lines.append(json.dumps(results, indent=2))
            
            return "\n".join(result_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_ad_creatives(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get ad creative details including headlines, descriptions, and URLs."""
    query = """
        SELECT
            ad_group_ad.ad.id,
            ad_group_ad.ad.name,
            ad_group_ad.ad.type,
            ad_group_ad.ad.final_urls,
            ad_group_ad.status,
            ad_group_ad.ad.responsive_search_ad.headlines,
            ad_group_ad.ad.responsive_search_ad.descriptions,
            ad_group.name,
            campaign.name
        FROM ad_group_ad
        WHERE ad_group_ad.status != 'REMOVED'
        ORDER BY campaign.name, ad_group.name
        LIMIT 50
    """
    
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving ad creatives: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No ad creatives found."
        
        output_lines = [f"Ad Creatives for {user_id} - Account {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            ad = result.get('adGroupAd', {}).get('ad', {})
            ad_group = result.get('adGroup', {})
            campaign = result.get('campaign', {})
            
            output_lines.append(f"\n{i}. Campaign: {campaign.get('name', 'N/A')}")
            output_lines.append(f"   Ad Group: {ad_group.get('name', 'N/A')}")
            output_lines.append(f"   Ad ID: {ad.get('id', 'N/A')}")
            output_lines.append(f"   Ad Name: {ad.get('name', 'N/A')}")
            output_lines.append(f"   Status: {result.get('adGroupAd', {}).get('status', 'N/A')}")
            output_lines.append(f"   Type: {ad.get('type', 'N/A')}")
            
            rsa = ad.get('responsiveSearchAd', {})
            if rsa:
                if 'headlines' in rsa:
                    output_lines.append("   Headlines:")
                    for headline in rsa['headlines']:
                        output_lines.append(f"     - {headline.get('text', 'N/A')}")
                
                if 'descriptions' in rsa:
                    output_lines.append("   Descriptions:")
                    for desc in rsa['descriptions']:
                        output_lines.append(f"     - {desc.get('text', 'N/A')}")
            
            final_urls = ad.get('finalUrls', [])
            if final_urls:
                output_lines.append(f"   Final URLs: {', '.join(final_urls)}")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error retrieving ad creatives: {str(e)}"

@mcp.tool()
async def get_account_currency(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Retrieve the default currency code used by the Google Ads account."""
    query = """
        SELECT
            customer.id,
            customer.currency_code
        FROM customer
        LIMIT 1
    """
    
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving account currency: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No account information found."
        
        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        
        return f"Account {formatted_customer_id} uses currency: {currency_code}"
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error retrieving account currency: {str(e)}"

@mcp.tool()
async def get_image_assets(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    limit: int = Field(default=50, description="Maximum number of image assets to return"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Retrieve all image assets in the account."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.height_pixels,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.file_size
        FROM asset
        WHERE asset.type = 'IMAGE'
        LIMIT {limit}
    """
    
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image assets found."
        
        output_lines = [f"Image Assets for {user_id} - Account {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        for i, result in enumerate(results['results'], 1):
            asset = result.get('asset', {})
            image_asset = asset.get('imageAsset', {})
            full_size = image_asset.get('fullSize', {})
            
            output_lines.append(f"\n{i}. Asset ID: {asset.get('id', 'N/A')}")
            output_lines.append(f"   Name: {asset.get('name', 'N/A')}")
            
            if full_size:
                output_lines.append(f"   Image URL: {full_size.get('url', 'N/A')}")
                output_lines.append(f"   Dimensions: {full_size.get('widthPixels', 'N/A')} x {full_size.get('heightPixels', 'N/A')} px")
            
            file_size = image_asset.get('fileSize', 'N/A')
            if file_size != 'N/A':
                file_size_kb = int(file_size) / 1024
                output_lines.append(f"   File Size: {file_size_kb:.2f} KB")
            
            output_lines.append("-" * 80)
        
        return "\n".join(output_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error retrieving image assets: {str(e)}"

@mcp.tool()
async def get_keyword_performance(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    min_impressions: int = Field(default=100, description="Minimum impressions filter"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get keyword performance metrics including Quality Score."""
    query = f"""
        SELECT
            ad_group_criterion.keyword.text,
            ad_group_criterion.keyword.match_type,
            ad_group_criterion.quality_info.quality_score,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            metrics.conversions,
            metrics.conversions_value
        FROM keyword_view
        WHERE 
            segments.date DURING LAST_{days}_DAYS
            AND metrics.impressions >= {min_impressions}
        ORDER BY metrics.cost_micros DESC
        LIMIT 100
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def get_budget_utilization(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze budget utilization across campaigns."""
    query = """
        SELECT
            campaign.id,
            campaign.name,
            campaign.status,
            campaign_budget.amount_micros,
            campaign_budget.delivery_method,
            metrics.cost_micros,
            metrics.impressions,
            metrics.clicks
        FROM campaign
        WHERE 
            campaign.status = 'ENABLED'
            AND segments.date = TODAY()
        ORDER BY metrics.cost_micros DESC
        LIMIT 50
    """
    
    try:
        result = await execute_gaql_query(user_id, customer_id, query, login_customer_id)
        
        if "Error" not in result and "No results" not in result:
            result += "\n\n💡 Budget Analysis Tips:"
            result += "\n- Check campaigns with cost approaching budget_amount"
            result += "\n- Consider increasing budget for high-performing campaigns"
            result += "\n- Review low-spend campaigns for optimization opportunities"
        
        return result
    except Exception as e:
        return f"Error analyzing budget utilization: {str(e)}"

@mcp.tool()
async def get_search_terms(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    min_impressions: int = Field(default=10, description="Minimum impressions filter"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get actual search terms that triggered your ads."""
    query = f"""
        SELECT
            search_term_view.search_term,
            campaign.name,
            ad_group.name,
            metrics.impressions,
            metrics.clicks,
            metrics.ctr,
            metrics.cost_micros,
            metrics.conversions
        FROM search_term_view
        WHERE 
            segments.date DURING LAST_{days}_DAYS
            AND metrics.impressions >= {min_impressions}
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def get_audience_performance(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze performance by audience demographics."""
    query = f"""
        SELECT
            campaign.name,
            ad_group.name,
            segments.device,
            segments.ad_network_type,
            metrics.impressions,
            metrics.clicks,
            metrics.ctr,
            metrics.cost_micros,
            metrics.conversions
        FROM ad_group
        WHERE 
            segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def get_conversion_actions(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """List all conversion actions configured in the account."""
    query = """
        SELECT
            conversion_action.id,
            conversion_action.name,
            conversion_action.type,
            conversion_action.status,
            conversion_action.category,
            conversion_action.value_settings.default_value,
            conversion_action.counting_type
        FROM conversion_action
        WHERE conversion_action.status != 'REMOVED'
        ORDER BY conversion_action.name
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def get_negative_keywords(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """List all negative keywords at campaign and ad group level."""
    campaign_query = """
        SELECT
            campaign.id,
            campaign.name,
            campaign_criterion.keyword.text,
            campaign_criterion.keyword.match_type
        FROM campaign_criterion
        WHERE 
            campaign_criterion.type = 'KEYWORD'
            AND campaign_criterion.negative = true
        ORDER BY campaign.name
        LIMIT 200
    """
    
    adgroup_query = """
        SELECT
            campaign.name,
            ad_group.name,
            ad_group_criterion.keyword.text,
            ad_group_criterion.keyword.match_type
        FROM ad_group_criterion
        WHERE 
            ad_group_criterion.type = 'KEYWORD'
            AND ad_group_criterion.negative = true
        ORDER BY campaign.name, ad_group.name
        LIMIT 200
    """
    
    try:
        campaign_result = await execute_gaql_query(user_id, customer_id, campaign_query, login_customer_id)
        adgroup_result = await execute_gaql_query(user_id, customer_id, adgroup_query, login_customer_id)
        
        output = "=" * 80
        output += "\n📛 CAMPAIGN-LEVEL NEGATIVE KEYWORDS\n"
        output += "=" * 80 + "\n"
        output += campaign_result
        output += "\n\n" + "=" * 80
        output += "\n📛 AD GROUP-LEVEL NEGATIVE KEYWORDS\n"
        output += "=" * 80 + "\n"
        output += adgroup_result
        
        return output
    except Exception as e:
        return f"Error retrieving negative keywords: {str(e)}"

@mcp.tool()
async def get_location_performance(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze performance by geographic location."""
    query = f"""
        SELECT
            campaign.name,
            geographic_view.country_criterion_id,
            geographic_view.location_type,
            metrics.impressions,
            metrics.clicks,
            metrics.ctr,
            metrics.cost_micros,
            metrics.conversions
        FROM geographic_view
        WHERE 
            segments.date DURING LAST_{days}_DAYS
            AND metrics.impressions > 0
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def get_ad_schedule_performance(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze performance by day of week and hour of day."""
    query = f"""
        SELECT
            campaign.name,
            segments.day_of_week,
            segments.hour,
            metrics.impressions,
            metrics.clicks,
            metrics.ctr,
            metrics.cost_micros,
            metrics.conversions
        FROM campaign
        WHERE 
            segments.date DURING LAST_{days}_DAYS
            AND metrics.impressions > 0
        ORDER BY segments.day_of_week, segments.hour
        LIMIT 200
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def download_image_asset(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save the downloaded image"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Download a specific image asset from a Google Ads account."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url
        FROM asset
        WHERE
            asset.type = 'IMAGE'
            AND asset.id = {asset_id}
        LIMIT 1
    """
    
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image asset: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No image asset found with ID {asset_id}"
        
        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")
        
        if not image_url:
            return f"No download URL found for image asset ID {asset_id}"
        
        # Security: validate output directory
        try:
            base_dir = Path.cwd()
            resolved_output_dir = Path(output_dir).resolve()
            
            try:
                resolved_output_dir.relative_to(base_dir)
            except ValueError:
                resolved_output_dir = base_dir / "ad_images"
                logger.warning(f"Invalid output directory '{output_dir}' - using default './ad_images'")
            
            resolved_output_dir.mkdir(parents=True, exist_ok=True)
            
        except Exception as e:
            return f"Error creating output directory: {str(e)}"
        
        # Download image
        image_response = requests.get(image_url)
        if image_response.status_code != 200:
            return f"Failed to download image: HTTP {image_response.status_code}"
        
        safe_name = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe_name}.jpg"
        file_path = resolved_output_dir / filename
        
        with open(file_path, 'wb') as f:
            f.write(image_response.content)
        
        return f"Successfully downloaded image asset {asset_id} to {file_path}"
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error downloading image asset: {str(e)}"

@mcp.tool()
async def get_asset_usage(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    asset_id: str = Field(default="", description="Optional: specific asset ID"),
    asset_type: str = Field(default="IMAGE", description="Asset type"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Find where specific assets are being used in campaigns."""
    where_clause = f"asset.type = '{asset_type}'"
    if asset_id:
        where_clause += f" AND asset.id = {asset_id}"
    
    query = f"""
        SELECT
            campaign.id,
            campaign.name,
            asset.id,
            asset.name,
            asset.type
        FROM campaign_asset
        WHERE {where_clause}
        LIMIT 500
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def analyze_image_assets(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze image assets with their performance metrics."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.full_size.height_pixels,
            campaign.name,
            metrics.impressions,
            metrics.clicks,
            metrics.conversions,
            metrics.cost_micros
        FROM campaign_asset
        WHERE
            asset.type = 'IMAGE'
            AND segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 200
    """
    
    return await execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
async def list_resources(
    user_id: str = Field(description="Unique identifier for the user"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """List valid resources that can be used in GAQL FROM clauses."""
    query = """
        SELECT
            google_ads_field.name,
            google_ads_field.category,
            google_ads_field.data_type
        FROM google_ads_field
        WHERE google_ads_field.category = 'RESOURCE'
        ORDER BY google_ads_field.name
        LIMIT 100
    """
    
    return await run_gaql(user_id, customer_id, query, "table", login_customer_id)

# ============================================================================
# MAIN - FIX #5: HOST SET TO 0.0.0.0 FOR FASTMCP PRODUCTION!
# ============================================================================

if __name__ == "__main__":
    host = "0.0.0.0"  # FIX #5: Listen on all interfaces for FastMCP
    port = int(os.getenv("PORT", "8001"))
    
    logger.info("=" * 60)
    logger.info(f"Starting MULTI-USER Google Ads MCP server at http://{host}:{port}/mcp")
    logger.info("Storage: PostgreSQL (Neon.tech) - NO FILE FALLBACK")
    logger.info("=" * 60)
    
    mcp.run(
        "http",
        host=host,
        port=port,
        path="/mcp"
    )

