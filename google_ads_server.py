from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
import sys
from datetime import datetime, timedelta
from pathlib import Path

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError
import logging

# MCP - Support both package layouts
try:
    from fastmcp import FastMCP
except ImportError:
    from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('google_ads_mcp_server.log'),
        logging.StreamHandler(sys.stderr)
    ]
)
logger = logging.getLogger('google_ads_server')

mcp = FastMCP(
    "google-ads-server",
    dependencies=[
        "google-auth-oauthlib",
        "google-auth",
        "requests",
        "python-dotenv"
    ]
)

# Constants and configuration
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"  # Google Ads API version
TOKEN_FILE = Path.home() / '.google_ads_token.json'  # Token storage location

logger.info("=" * 60)
logger.info("Google Ads MCP Server Starting (HTTP Streamable)...")
logger.info("=" * 60)

# Load environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
    logger.info("Environment variables loaded from .env file")
except ImportError:
    logger.warning("python-dotenv not installed, skipping .env file loading")

# Get credentials from environment variables
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
# Login customer ID is now optional - can be set per request or in env
GOOGLE_ADS_LOGIN_CUSTOMER_ID = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
GOOGLE_ADS_AUTH_TYPE = os.environ.get("GOOGLE_ADS_AUTH_TYPE", "oauth")  # oauth or service_account

def get_credentials():
    """Get and refresh OAuth credentials or service account credentials based on the auth type."""
    auth_type = GOOGLE_ADS_AUTH_TYPE.lower()
    logger.info(f"Using authentication type: {auth_type}")
    
    if auth_type == "service_account":
        try:
            return get_service_account_credentials()
        except Exception as e:
            logger.error(f"Error with service account authentication: {str(e)}")
            raise
    
    return get_oauth_credentials()

def get_service_account_credentials():
    """Get credentials using service account (if applicable)."""
    logger.info("Loading service account credentials from environment variables")
    
    # For service accounts, you'd typically use a JSON key file
    service_account_file = os.environ.get("GOOGLE_ADS_SERVICE_ACCOUNT_FILE")
    
    if not service_account_file:
        raise ValueError("GOOGLE_ADS_SERVICE_ACCOUNT_FILE must be set for service account auth")
    
    try:
        credentials = service_account.Credentials.from_service_account_file(
            service_account_file,
            scopes=SCOPES
        )
        logger.info("Service account credentials loaded successfully")
        return credentials
        
    except Exception as e:
        logger.error(f"Error loading service account credentials: {str(e)}")
        raise

def get_oauth_credentials():
    """Get and refresh OAuth user credentials with token persistence."""
    creds = None
    
    # Try to load existing token
    if TOKEN_FILE.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_FILE), SCOPES)
            logger.info("Loaded existing OAuth credentials from token file")
        except Exception as e:
            logger.warning(f"Could not load saved credentials: {e}")
    
    # If no valid credentials, do the OAuth flow
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Refresh expired token
            try:
                logger.info("Refreshing expired OAuth token")
                creds.refresh(Request())
                logger.info("Token successfully refreshed")
            except RefreshError as e:
                logger.error(f"Error refreshing token: {str(e)}")
                # Delete invalid token file and re-authenticate
                if TOKEN_FILE.exists():
                    TOKEN_FILE.unlink()
                    logger.info("Deleted invalid token file, will re-authenticate")
                creds = None
        
        if not creds or not creds.valid:
            # Need to do full OAuth flow
            client_id = os.environ.get("GOOGLE_ADS_CLIENT_ID")
            client_secret = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")
            
            if not client_id or not client_secret:
                raise ValueError("GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET must be set")
            
            client_config = {
                "installed": {
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "redirect_uris": ["urn:ietf:wg:oauth:2.0:oob", "http://localhost"]
                }
            }
            
            logger.info("Starting OAuth authentication flow (browser will open)")
            flow = InstalledAppFlow.from_client_config(client_config, SCOPES)
            creds = flow.run_local_server(port=0)
            logger.info("OAuth flow completed successfully")
        
        # Save the credentials for next time
        try:
            with open(TOKEN_FILE, 'w') as f:
                f.write(creds.to_json())
            logger.info(f"Saved credentials to {TOKEN_FILE}")
        except Exception as e:
            logger.warning(f"Could not save credentials: {e}")
    
    return creds

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    customer_id = str(customer_id)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    return customer_id.zfill(10)

def get_headers(creds, login_customer_id: Optional[str] = None):
    """
    Get headers for Google Ads API requests.
    
    Args:
        creds: OAuth or service account credentials
        login_customer_id: Optional login customer ID to use for this request.
                          If provided, overrides the environment variable.
    """
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")
    
    if isinstance(creds, service_account.Credentials):
        auth_req = Request()
        creds.refresh(auth_req)
        token = creds.token
    else:
        if not creds.valid:
            if creds.expired and creds.refresh_token:
                try:
                    logger.info("Refreshing expired OAuth token in get_headers")
                    creds.refresh(Request())
                    logger.info("Token successfully refreshed in get_headers")
                    
                    # Save the refreshed token
                    try:
                        with open(TOKEN_FILE, 'w') as f:
                            f.write(creds.to_json())
                        logger.info("Saved refreshed credentials")
                    except Exception as e:
                        logger.warning(f"Could not save refreshed credentials: {e}")
                        
                except RefreshError as e:
                    logger.error(f"Error refreshing token in get_headers: {str(e)}")
                    raise ValueError(f"Failed to refresh OAuth token: {str(e)}")
                except Exception as e:
                    logger.error(f"Unexpected error refreshing token in get_headers: {str(e)}")
                    raise
            else:
                raise ValueError("OAuth credentials are invalid and cannot be refreshed")
        
        token = creds.token
        
    headers = {
        'Authorization': f'Bearer {token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }
    
    # Use the provided login_customer_id if given, otherwise fall back to env variable
    customer_id_to_use = login_customer_id or GOOGLE_ADS_LOGIN_CUSTOMER_ID
    if customer_id_to_use:
        headers['login-customer-id'] = format_customer_id(customer_id_to_use)
        logger.info(f"Using login-customer-id: {format_customer_id(customer_id_to_use)}")
    
    return headers

@mcp.tool()
async def list_accounts() -> str:
    """
    Lists all accessible Google Ads accounts.
    
    This is typically the first command you should run to identify which accounts 
    you have access to. The returned account IDs can be used in subsequent commands.
    
    Returns:
        A formatted list of all Google Ads accounts accessible with your credentials
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."
        
        # Format the results
        result_lines = ["Accessible Google Ads Accounts:"]
        result_lines.append("-" * 50)
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            result_lines.append(f"Account ID: {formatted_id}")
        
        result_lines.append("\n" + "=" * 50)
        result_lines.append("💡 TIP: Use get_account_details() to see account names and hierarchy")
        result_lines.append("=" * 50)
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error listing accounts: {str(e)}"

@mcp.tool()
async def get_account_details(
    login_customer_id: str = Field(
        default="",
        description="Optional: Manager account ID to use for authentication. Leave empty to use env variable."
    )
) -> str:
    """
    Get detailed information about all accessible accounts including names and hierarchy.
    
    This tool shows you:
    - Account IDs
    - Account Names  
    - Account Types (Manager vs Client)
    - Currency
    - Time Zone
    
    This is very useful when you have multiple accounts and want to see which one is which!
    
    Args:
        login_customer_id: Optional manager account ID. If you have multiple accounts,
                          you might need to specify which manager account to use.
    
    Returns:
        Detailed information about all accessible accounts
        
    Example:
        get_account_details()  # Uses env variable
        get_account_details(login_customer_id="1234567890")  # Uses specific manager account
    """
    try:
        creds = get_credentials()
        
        # First get list of accessible customers
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found."
        
        result_lines = ["📊 Detailed Account Information:"]
        result_lines.append("=" * 100)
        
        # Get detailed info for each account
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            formatted_id = format_customer_id(customer_id)
            
            # Query for account details
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
                # Use this specific customer_id for the query
                detail_headers = get_headers(creds, login_customer_id if login_customer_id else None)
                detail_url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_id}/googleAds:search"
                payload = {"query": query}
                detail_response = requests.post(detail_url, headers=detail_headers, json=payload)
                
                if detail_response.status_code == 200:
                    detail_results = detail_response.json()
                    if detail_results.get('results'):
                        customer_data = detail_results['results'][0].get('customer', {})
                        
                        account_type = "🏢 Manager Account" if customer_data.get('manager') else "📈 Client Account"
                        status = customer_data.get('status', 'UNKNOWN')
                        
                        result_lines.append(f"\n{account_type}")
                        result_lines.append(f"  Account ID: {formatted_id}")
                        result_lines.append(f"  Name: {customer_data.get('descriptiveName', 'N/A')}")
                        result_lines.append(f"  Currency: {customer_data.get('currencyCode', 'N/A')}")
                        result_lines.append(f"  Time Zone: {customer_data.get('timeZone', 'N/A')}")
                        result_lines.append(f"  Status: {status}")
                        result_lines.append("-" * 80)
                else:
                    result_lines.append(f"\n  Account ID: {formatted_id}")
                    result_lines.append(f"  (Could not fetch details: {detail_response.status_code})")
                    result_lines.append("-" * 80)
                    
            except Exception as e:
                result_lines.append(f"\n  Account ID: {formatted_id}")
                result_lines.append(f"  (Error fetching details: {str(e)})")
                result_lines.append("-" * 80)
        
        result_lines.append("\n" + "=" * 100)
        result_lines.append("💡 TIP: Use the Account ID in other commands with customer_id parameter")
        result_lines.append("=" * 100)
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error getting account details: {str(e)}"

@mcp.tool()
async def execute_gaql_query(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"),
    query: str = Field(description="Valid GAQL query string following Google Ads Query Language syntax"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID if needed for authentication")
) -> str:
    """
    Execute a custom GAQL (Google Ads Query Language) query.
    
    This tool allows you to run any valid GAQL query against the Google Ads API.
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        query: The GAQL query to execute (must follow GAQL syntax)
        login_customer_id: Optional manager account ID for authentication
        
    Returns:
        Formatted query results or error message
        
    Example:
        customer_id: "1234567890"
        query: "SELECT campaign.id, campaign.name FROM campaign LIMIT 10"
    """
    try:
        creds = get_credentials()
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
        
        # Format the results as a table
        result_lines = [f"Query Results for Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        
        # Get field names from the first result
        fields = []
        first_result = results['results'][0]
        for key in first_result:
            if isinstance(first_result[key], dict):
                for subkey in first_result[key]:
                    fields.append(f"{key}.{subkey}")
            else:
                fields.append(key)
        
        # Add header
        result_lines.append(" | ".join(fields))
        result_lines.append("-" * 80)
        
        # Add data rows
        for result in results['results']:
            row_data = []
            for field in fields:
                if "." in field:
                    parent, child = field.split(".")
                    value = str(result.get(parent, {}).get(child, ""))
                else:
                    value = str(result.get(field, ""))
                row_data.append(value)
            result_lines.append(" | ".join(row_data))
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_campaign_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get campaign performance metrics for the specified time period."""
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_ad_performance(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get ad performance metrics."""
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def run_gaql(
    customer_id: str = Field(description="Google Ads customer ID"),
    query: str = Field(description="Valid GAQL query string"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Execute any arbitrary GAQL query with custom formatting options."""
    try:
        creds = get_credentials()
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
            result_lines = [f"Query Results for Account {formatted_customer_id}:"]
            result_lines.append("-" * 100)
            
            fields = []
            field_widths = {}
            first_result = results['results'][0]
            
            for key, value in first_result.items():
                if isinstance(value, dict):
                    for subkey in value:
                        field = f"{key}.{subkey}"
                        fields.append(field)
                        field_widths[field] = len(field)
                else:
                    fields.append(key)
                    field_widths[key] = len(key)
            
            for result in results['results']:
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    field_widths[field] = max(field_widths[field], len(value))
            
            header = " | ".join(f"{field:{field_widths[field]}}" for field in fields)
            result_lines.append(header)
            result_lines.append("-" * len(header))
            
            for result in results['results']:
                row_data = []
                for field in fields:
                    if "." in field:
                        parent, child = field.split(".")
                        value = str(result.get(parent, {}).get(child, ""))
                    else:
                        value = str(result.get(field, ""))
                    row_data.append(f"{value:{field_widths[field]}}")
                result_lines.append(" | ".join(row_data))
            
            return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

@mcp.tool()
async def get_ad_creatives(
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
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving ad creatives: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No ad creatives found for this customer ID."
        
        output_lines = [f"Ad Creatives for Customer ID {formatted_customer_id}:"]
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
    
    except Exception as e:
        return f"Error retrieving ad creatives: {str(e)}"

@mcp.tool()
async def get_account_currency(
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
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving account currency: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No account information found for this customer ID."
        
        customer = results['results'][0].get('customer', {})
        currency_code = customer.get('currencyCode', 'Not specified')
        
        return f"Account {formatted_customer_id} uses currency: {currency_code}"
    
    except Exception as e:
        logger.error(f"Error retrieving account currency: {str(e)}")
        return f"Error retrieving account currency: {str(e)}"

@mcp.tool()
async def get_image_assets(
    customer_id: str = Field(description="Google Ads customer ID"),
    limit: int = Field(default=50, description="Maximum number of image assets to return"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Retrieve all image assets in the account including their full-size URLs."""
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type,
            asset.image_asset.full_size.url,
            asset.image_asset.full_size.height_pixels,
            asset.image_asset.full_size.width_pixels,
            asset.image_asset.file_size
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
        LIMIT {limit}
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error retrieving image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image assets found for this customer ID."
        
        output_lines = [f"Image Assets for Customer ID {formatted_customer_id}:"]
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
    
    except Exception as e:
        return f"Error retrieving image assets: {str(e)}"

@mcp.tool()
async def download_image_asset(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save the downloaded image"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Download a specific image asset from a Google Ads account.
    
    This tool allows you to download the full-size version of an image asset
    for further processing, analysis, or backup.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run get_image_assets() to get available image asset IDs
    3. Finally use this command to download specific images
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        asset_id: The ID of the image asset to download
        output_dir: Directory where the image should be saved (default: ./ad_images)
        login_customer_id: Optional manager account ID
        
    Returns:
        Status message indicating success or failure of the download
        
    Example:
        customer_id: "1234567890"
        asset_id: "12345"
        output_dir: "./my_ad_images"
    """
    query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.image_asset.full_size.url
        FROM
            asset
        WHERE
            asset.type = 'IMAGE'
            AND asset.id = {asset_id}
        LIMIT 1
    """
    
    try:
        creds = get_credentials()
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
        
        # Extract the image URL
        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")
        
        if not image_url:
            return f"No download URL found for image asset ID {asset_id}"
        
        # Validate and sanitize the output directory to prevent path traversal
        try:
            # Get the base directory (current working directory)
            base_dir = Path.cwd()
            # Resolve the output directory to an absolute path
            resolved_output_dir = Path(output_dir).resolve()
            
            # Ensure the resolved path is within or under the current working directory
            # This prevents path traversal attacks like "../../../etc"
            try:
                resolved_output_dir.relative_to(base_dir)
            except ValueError:
                # If the path is not relative to base_dir, use the default safe directory
                resolved_output_dir = base_dir / "ad_images"
                logger.warning(f"Invalid output directory '{output_dir}' - using default './ad_images'")
            
            # Create output directory if it doesn't exist
            resolved_output_dir.mkdir(parents=True, exist_ok=True)
            
        except Exception as e:
            return f"Error creating output directory: {str(e)}"
        
        # Download the image
        image_response = requests.get(image_url)
        if image_response.status_code != 200:
            return f"Failed to download image: HTTP {image_response.status_code}"
        
        # Clean the filename to be safe for filesystem
        safe_name = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe_name}.jpg"
        file_path = resolved_output_dir / filename
        
        # Save the image
        with open(file_path, 'wb') as f:
            f.write(image_response.content)
        
        return f"Successfully downloaded image asset {asset_id} to {file_path}"
    
    except Exception as e:
        return f"Error downloading image asset: {str(e)}"

@mcp.tool()
async def get_asset_usage(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    asset_id: str = Field(default="", description="Optional: specific asset ID to look up (leave empty to get all image assets)"),
    asset_type: str = Field(default="IMAGE", description="Asset type to search for ('IMAGE', 'TEXT', 'VIDEO', etc.)"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Find where specific assets are being used in campaigns, ad groups, and ads.
    
    This tool helps you analyze how assets are linked to campaigns and ads across your account,
    which is useful for creative analysis and optimization.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Run get_image_assets() to see available assets
    3. Use this command to see where specific assets are used
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        asset_id: Optional specific asset ID to look up (leave empty to get all assets of the specified type)
        asset_type: Type of asset to search for (default: 'IMAGE')
        login_customer_id: Optional manager account ID
        
    Returns:
        Formatted report showing where assets are used in the account
        
    Example:
        customer_id: "1234567890"
        asset_id: "12345"
        asset_type: "IMAGE"
    """
    # Build the query based on whether a specific asset ID was provided
    where_clause = f"asset.type = '{asset_type}'"
    if asset_id:
        where_clause += f" AND asset.id = {asset_id}"
    
    # First get the assets themselves
    assets_query = f"""
        SELECT
            asset.id,
            asset.name,
            asset.type
        FROM
            asset
        WHERE
            {where_clause}
        LIMIT 100
    """
    
    # Then get the associations between assets and campaigns
    associations_query = f"""
        SELECT
            campaign.id,
            campaign.name,
            asset.id,
            asset.name,
            asset.type
        FROM
            campaign_asset
        WHERE
            {where_clause}
        LIMIT 500
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        
        # First get the assets
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        payload = {"query": assets_query}
        assets_response = requests.post(url, headers=headers, json=payload)
        
        if assets_response.status_code != 200:
            return f"Error retrieving assets: {assets_response.text}"
        
        assets_results = assets_response.json()
        if not assets_results.get('results'):
            return f"No {asset_type} assets found for this customer ID."
        
        # Now get the associations
        payload = {"query": associations_query}
        assoc_response = requests.post(url, headers=headers, json=payload)
        
        if assoc_response.status_code != 200:
            return f"Error retrieving asset associations: {assoc_response.text}"
        
        assoc_results = assoc_response.json()
        
        # Format the results in a readable way
        output_lines = [f"Asset Usage for Customer ID {formatted_customer_id}:"]
        output_lines.append("=" * 80)
        
        # Create a dictionary to organize asset usage by asset ID
        asset_usage = {}
        
        # Initialize the asset usage dictionary with basic asset info
        for result in assets_results.get('results', []):
            asset = result.get('asset', {})
            asset_id_val = asset.get('id')
            if asset_id_val:
                asset_usage[asset_id_val] = {
                    'name': asset.get('name', 'Unnamed asset'),
                    'type': asset.get('type', 'Unknown'),
                    'usage': []
                }
        
        # Add usage information from the associations
        for result in assoc_results.get('results', []):
            asset = result.get('asset', {})
            asset_id_val = asset.get('id')
            
            if asset_id_val and asset_id_val in asset_usage:
                campaign = result.get('campaign', {})
                ad_group = result.get('adGroup', {})
                
                usage_info = {
                    'campaign_id': campaign.get('id', 'N/A'),
                    'campaign_name': campaign.get('name', 'N/A'),
                    'ad_group_id': ad_group.get('id', 'N/A'),
                    'ad_group_name': ad_group.get('name', 'N/A'),
                }
                
                asset_usage[asset_id_val]['usage'].append(usage_info)
        
        # Format the output
        for asset_id_val, info in asset_usage.items():
            output_lines.append(f"\nAsset ID: {asset_id_val}")
            output_lines.append(f"Name: {info['name']}")
            output_lines.append(f"Type: {info['type']}")
            
            if info['usage']:
                output_lines.append("\nUsed in:")
                output_lines.append("-" * 60)
                output_lines.append(f"{'Campaign':<30} | {'Ad Group':<30}")
                output_lines.append("-" * 60)
                
                for usage in info['usage']:
                    campaign_str = f"{usage['campaign_name']} ({usage['campaign_id']})"
                    ad_group_str = f"{usage['ad_group_name']} ({usage['ad_group_id']})"
                    
                    output_lines.append(f"{campaign_str[:30]:<30} | {ad_group_str[:30]:<30}")
            else:
                output_lines.append("\n⚠️  Not currently used in any campaigns")
            
            output_lines.append("=" * 80)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error retrieving asset usage: {str(e)}"

@mcp.tool()
async def analyze_image_assets(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    days: int = Field(default=30, description="Number of days to look back (7, 30, 90, etc.)"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Analyze image assets with their performance metrics across campaigns.
    
    This comprehensive tool helps you understand which image assets are performing well
    by showing metrics like impressions, clicks, and conversions for each image.
    
    RECOMMENDED WORKFLOW:
    1. First run list_accounts() to get available account IDs
    2. Then run get_account_currency() to see what currency the account uses
    3. Finally run this command to analyze image asset performance
    
    Args:
        customer_id: The Google Ads customer ID as a string (10 digits, no dashes)
        days: Number of days to look back (default: 30)
        login_customer_id: Optional manager account ID
        
    Returns:
        Detailed report of image assets and their performance metrics
        
    Example:
        customer_id: "1234567890"
        days: 14
    """
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
        FROM
            campaign_asset
        WHERE
            asset.type = 'IMAGE'
            AND segments.date DURING LAST_30_DAYS
        ORDER BY
            metrics.impressions DESC
        LIMIT 200
    """
    
    try:
        creds = get_credentials()
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)
        
        if response.status_code != 200:
            return f"Error analyzing image assets: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No image asset performance data found for this customer ID and time period."
        
        # Group results by asset ID
        assets_data = {}
        for result in results.get('results', []):
            asset = result.get('asset', {})
            asset_id_val = asset.get('id')
            
            if asset_id_val not in assets_data:
                assets_data[asset_id_val] = {
                    'name': asset.get('name', f"Asset {asset_id_val}"),
                    'url': asset.get('imageAsset', {}).get('fullSize', {}).get('url', 'N/A'),
                    'dimensions': f"{asset.get('imageAsset', {}).get('fullSize', {}).get('widthPixels', 'N/A')} x {asset.get('imageAsset', {}).get('fullSize', {}).get('heightPixels', 'N/A')}",
                    'impressions': 0,
                    'clicks': 0,
                    'conversions': 0,
                    'cost_micros': 0,
                    'campaigns': set()
                }
            
            # Aggregate metrics
            metrics = result.get('metrics', {})
            assets_data[asset_id_val]['impressions'] += int(metrics.get('impressions', 0))
            assets_data[asset_id_val]['clicks'] += int(metrics.get('clicks', 0))
            assets_data[asset_id_val]['conversions'] += float(metrics.get('conversions', 0))
            assets_data[asset_id_val]['cost_micros'] += int(metrics.get('costMicros', 0))
            
            # Add campaign info
            campaign = result.get('campaign', {})
            if campaign.get('name'):
                assets_data[asset_id_val]['campaigns'].add(campaign.get('name'))
        
        # Format the results
        output_lines = [f"Image Asset Performance Analysis for Customer ID {formatted_customer_id} (Last {days} days):"]
        output_lines.append("=" * 100)
        
        # Sort assets by impressions (highest first)
        sorted_assets = sorted(assets_data.items(), key=lambda x: x[1]['impressions'], reverse=True)
        
        for asset_id_val, data in sorted_assets:
            output_lines.append(f"\nAsset ID: {asset_id_val}")
            output_lines.append(f"Name: {data['name']}")
            output_lines.append(f"Dimensions: {data['dimensions']}")
            
            # Calculate CTR if there are impressions
            ctr = (data['clicks'] / data['impressions'] * 100) if data['impressions'] > 0 else 0
            
            # Format metrics
            output_lines.append(f"\nPerformance Metrics:")
            output_lines.append(f"  Impressions: {data['impressions']:,}")
            output_lines.append(f"  Clicks: {data['clicks']:,}")
            output_lines.append(f"  CTR: {ctr:.2f}%")
            output_lines.append(f"  Conversions: {data['conversions']:.2f}")
            output_lines.append(f"  Cost (micros): {data['cost_micros']:,}")
            
            # Show where it's used
            output_lines.append(f"\nUsed in {len(data['campaigns'])} campaigns:")
            for campaign in list(data['campaigns'])[:5]:  # Show first 5 campaigns
                output_lines.append(f"  - {campaign}")
            if len(data['campaigns']) > 5:
                output_lines.append(f"  - ... and {len(data['campaigns']) - 5} more")
            
            # Add URL
            if data['url'] != 'N/A':
                output_lines.append(f"\nImage URL: {data['url']}")
            
            output_lines.append("-" * 100)
        
        return "\n".join(output_lines)
    
    except Exception as e:
        return f"Error analyzing image assets: {str(e)}"

@mcp.tool()
async def list_resources(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    List valid resources that can be used in GAQL FROM clauses.
    
    This tool helps you discover what resources are available in the Google Ads API
    that you can query. Useful for building custom GAQL queries.
    
    Args:
        customer_id: The Google Ads customer ID as a string
        login_customer_id: Optional manager account ID
        
    Returns:
        Formatted list of valid resources
    """
    query = """
        SELECT
            google_ads_field.name,
            google_ads_field.category,
            google_ads_field.data_type
        FROM
            google_ads_field
        WHERE
            google_ads_field.category = 'RESOURCE'
        ORDER BY
            google_ads_field.name
        LIMIT 100
    """
    
    return await run_gaql(customer_id, query, "table", login_customer_id)

# NEW HELPFUL TOOLS BELOW

@mcp.tool()
async def get_keyword_performance(
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    min_impressions: int = Field(default=100, description="Minimum impressions filter"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Get keyword performance metrics including Quality Score.
    
    This tool helps you analyze which keywords are performing well and identify
    opportunities for optimization based on Quality Score and performance metrics.
    
    Args:
        customer_id: Google Ads customer ID
        days: Number of days to look back (default: 30)
        min_impressions: Only show keywords with at least this many impressions
        login_customer_id: Optional manager account ID
        
    Returns:
        Formatted table of keyword performance data
    """
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_budget_utilization(
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Analyze budget utilization across campaigns.
    
    This tool shows you how much of each campaign's budget is being used,
    helping you identify campaigns that might need budget adjustments.
    
    Args:
        customer_id: Google Ads customer ID
        login_customer_id: Optional manager account ID
        
    Returns:
        Budget analysis for active campaigns
    """
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
        result = await execute_gaql_query(customer_id, query, login_customer_id)
        
        # Add budget utilization analysis
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
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    min_impressions: int = Field(default=10, description="Minimum impressions filter"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Get actual search terms that triggered your ads.
    
    This tool shows you what people actually searched for when your ads appeared,
    helping you discover new keyword opportunities and negative keywords.
    
    Args:
        customer_id: Google Ads customer ID
        days: Number of days to look back
        min_impressions: Minimum impressions to include
        login_customer_id: Optional manager account ID
        
    Returns:
        List of search terms with performance metrics
    """
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_audience_performance(
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Analyze performance by audience demographics (age, gender, device).
    
    This tool helps you understand which audience segments are performing best,
    allowing you to optimize bids and targeting.
    
    Args:
        customer_id: Google Ads customer ID
        days: Number of days to look back
        login_customer_id: Optional manager account ID
        
    Returns:
        Audience performance breakdown
    """
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_conversion_actions(
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    List all conversion actions configured in the account.
    
    This tool shows you what conversion actions are being tracked,
    helping you understand your conversion tracking setup.
    
    Args:
        customer_id: Google Ads customer ID
        login_customer_id: Optional manager account ID
        
    Returns:
        List of conversion actions with their settings
    """
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_negative_keywords(
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    List all negative keywords at campaign and ad group level.
    
    This tool helps you review your negative keyword lists to ensure
    you're properly filtering out unwanted traffic.
    
    Args:
        customer_id: Google Ads customer ID
        login_customer_id: Optional manager account ID
        
    Returns:
        List of negative keywords organized by campaign/ad group
    """
    # Campaign-level negative keywords
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
    
    # Ad group-level negative keywords
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
        campaign_result = await execute_gaql_query(customer_id, campaign_query, login_customer_id)
        adgroup_result = await execute_gaql_query(customer_id, adgroup_query, login_customer_id)
        
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
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Analyze performance by geographic location.
    
    This tool shows you which locations are driving the best results,
    helping you optimize location targeting and bids.
    
    Args:
        customer_id: Google Ads customer ID
        days: Number of days to look back
        login_customer_id: Optional manager account ID
        
    Returns:
        Performance breakdown by location
    """
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.tool()
async def get_ad_schedule_performance(
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """
    Analyze performance by day of week and hour of day.
    
    This tool helps you identify the best times to show your ads,
    allowing you to optimize ad scheduling and bid adjustments.
    
    Args:
        customer_id: Google Ads customer ID
        days: Number of days to look back
        login_customer_id: Optional manager account ID
        
    Returns:
        Performance breakdown by time
    """
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
    
    return await execute_gaql_query(customer_id, query, login_customer_id)

@mcp.resource("gaql://reference")
def gaql_reference() -> str:
    """Google Ads Query Language (GAQL) reference documentation."""
    return """
    # Google Ads Query Language (GAQL) Reference
    
    GAQL is similar to SQL but with specific syntax for Google Ads. Here's a quick reference:
    
    ## Basic Query Structure
    ```
    SELECT field1, field2, ... 
    FROM resource_type
    WHERE condition
    ORDER BY field [ASC|DESC]
    LIMIT n
    ```
    
    ## Common Field Types
    
    ### Resource Fields
    - campaign.id, campaign.name, campaign.status
    - ad_group.id, ad_group.name, ad_group.status
    - ad_group_ad.ad.id, ad_group_ad.ad.final_urls
    - keyword.text, keyword.match_type
    
    ### Metric Fields
    - metrics.impressions
    - metrics.clicks
    - metrics.cost_micros
    - metrics.conversions
    - metrics.ctr
    - metrics.average_cpc
    
    ### Segment Fields
    - segments.date
    - segments.device
    - segments.day_of_week
    
    ## Common WHERE Clauses
    
    ### Date Ranges
    - WHERE segments.date DURING LAST_7_DAYS
    - WHERE segments.date DURING LAST_30_DAYS
    - WHERE segments.date BETWEEN '2023-01-01' AND '2023-01-31'
    
    ### Filtering
    - WHERE campaign.status = 'ENABLED'
    - WHERE metrics.clicks > 100
    - WHERE campaign.name LIKE '%Brand%'
    
    ## Tips
    - Always check account currency before analyzing cost data
    - Cost values are in micros (millionths): 1000000 = 1 unit of currency
    - Use LIMIT to avoid large result sets
    """

@mcp.prompt("google_ads_workflow")
def google_ads_workflow() -> str:
    """Provides guidance on the recommended workflow for using Google Ads tools."""
    return """
    I'll help you analyze your Google Ads account data. Here's the recommended workflow:
    
    1. First, let's list all the accounts you have access to:
       - Run the `list_accounts()` tool to get available account IDs
    
    2. Before analyzing cost data, let's check which currency the account uses:
       - Run `get_account_currency(customer_id="ACCOUNT_ID")` with your selected account
    
    3. Now we can explore the account data:
       - For campaign performance: `get_campaign_performance(customer_id="ACCOUNT_ID", days=30)`
       - For ad performance: `get_ad_performance(customer_id="ACCOUNT_ID", days=30)`
       - For keyword performance: `get_keyword_performance(customer_id="ACCOUNT_ID", days=30)`
       - For ad creative review: `get_ad_creatives(customer_id="ACCOUNT_ID")`
    
    4. For custom queries, use the GAQL query tool:
       - `run_gaql(customer_id="ACCOUNT_ID", query="YOUR_QUERY", format="table")`
    
    Important: Always provide the customer_id as a string.
    For example: customer_id="1234567890"
    """

# ----------------------------
# MAIN — Streamable HTTP on 127.0.0.1:8001/mcp
# ----------------------------
if __name__ == "__main__":
    try:
        if not GOOGLE_ADS_DEVELOPER_TOKEN:
            raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN not set")
        
        logger.info("✓ Required environment variables configured")
        logger.info(f"✓ Auth type: {GOOGLE_ADS_AUTH_TYPE}")
        logger.info(f"✓ Token file location: {TOKEN_FILE}")
        
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        sys.exit(1)

    host = "127.0.0.1"
    port = int(os.getenv("PORT", "8001"))
    
    logger.info(f"Starting Google Ads MCP server at http://{host}:{port}/mcp")
    logger.info("=" * 60)
    
    mcp.run(
        "http",
        host=host,
        port=port,
        path="/mcp"
    )
