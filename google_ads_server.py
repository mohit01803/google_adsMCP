"""
Google Ads MCP Server - Complete with All 21 Tools
Multi-user OAuth with PostgreSQL storage (Neon.tech)
"""

from typing import Any, Dict, List, Optional, Union
from pydantic import Field
import os
import json
import requests
import sys
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import logging

from google_auth_oauthlib.flow import InstalledAppFlow
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from google.auth.exceptions import RefreshError

# ============================================================================
# CRITICAL FIX: Import FastMCP before any other imports that use it
# ============================================================================
from fastmcp import FastMCP

# ============================================================================
# CONFIGURE LOGGING - Console only for FastMCP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)]
)
logger = logging.getLogger('google_ads_server')

# ============================================================================
# INITIALIZE FASTMCP FIRST
# ============================================================================
mcp = FastMCP("google-ads-server")

# ============================================================================
# PostgreSQL Storage Class (Inline - No separate file needed)
# ============================================================================
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

class PostgresTokenStorage:
    """PostgreSQL-based token storage for OAuth tokens"""
    
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        try:
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
                connect_timeout=10,
                sslmode='require'  # FIX: Added SSL for Neon.tech
            )
            
            logger.info(f"✓ Connected to PostgreSQL at {host}:{port}/{database}")
            self._create_table()
            
        except psycopg2.OperationalError as e:
            logger.error(f"✗ PostgreSQL connection failed: {e}")
            raise Exception(f"PostgreSQL connection failed: {e}")
    
    def _create_table(self):
        """Create oauth_tokens table if it doesn't exist"""
        create_table_query = """
        CREATE TABLE IF NOT EXISTS oauth_tokens (
            id SERIAL PRIMARY KEY,
            user_hash VARCHAR(32) UNIQUE NOT NULL,
            token TEXT NOT NULL,
            refresh_token TEXT,
            token_uri VARCHAR(500),
            client_id VARCHAR(255),
            client_secret VARCHAR(255),
            scopes JSONB,
            expiry TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP
        );
        
        CREATE INDEX IF NOT EXISTS idx_user_hash ON oauth_tokens(user_hash);
        CREATE INDEX IF NOT EXISTS idx_expires_at ON oauth_tokens(expires_at);
        """
        
        conn = None
        try:
            conn = self.connection_pool.getconn()
            cursor = conn.cursor()
            cursor.execute(create_table_query)
            conn.commit()
            cursor.close()
            logger.info("✓ OAuth tokens table verified/created")
        except Exception as e:
            logger.error(f"✗ Error creating table: {e}")
            if conn:
                conn.rollback()
            raise
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def _hash_user_id(self, user_id: str) -> str:
        """Hash user ID for privacy"""
        return hashlib.sha256(user_id.encode()).hexdigest()[:32]
    
    def save_token(self, user_id: str, creds: Credentials) -> bool:
        """Save user's OAuth credentials to PostgreSQL"""
        conn = None
        try:
            user_hash = self._hash_user_id(user_id)
            expires_at = datetime.now() + timedelta(days=30)
            
            scopes_json = json.dumps(list(creds.scopes) if creds.scopes else [])
            expiry = creds.expiry.isoformat() if hasattr(creds, 'expiry') and creds.expiry else None
            
            conn = self.connection_pool.getconn()
            cursor = conn.cursor()
            
            upsert_query = """
            INSERT INTO oauth_tokens (
                user_hash, token, refresh_token, token_uri,
                client_id, client_secret, scopes, expiry,
                updated_at, expires_at
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (user_hash) 
            DO UPDATE SET
                token = EXCLUDED.token,
                refresh_token = EXCLUDED.refresh_token,
                token_uri = EXCLUDED.token_uri,
                client_id = EXCLUDED.client_id,
                client_secret = EXCLUDED.client_secret,
                scopes = EXCLUDED.scopes,
                expiry = EXCLUDED.expiry,
                updated_at = EXCLUDED.updated_at,
                expires_at = EXCLUDED.expires_at
            """
            
            cursor.execute(upsert_query, (
                user_hash, creds.token, creds.refresh_token, creds.token_uri,
                creds.client_id, creds.client_secret, scopes_json, expiry,
                datetime.now(), expires_at
            ))
            
            conn.commit()
            cursor.close()
            logger.info(f"✓ Saved token for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Error saving token: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def load_token(self, user_id: str) -> Optional[Credentials]:
        """Load user's OAuth credentials from PostgreSQL"""
        conn = None
        try:
            user_hash = self._hash_user_id(user_id)
            
            conn = self.connection_pool.getconn()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            query = """
            SELECT * FROM oauth_tokens 
            WHERE user_hash = %s 
            AND (expires_at IS NULL OR expires_at > NOW())
            """
            
            cursor.execute(query, (user_hash,))
            row = cursor.fetchone()
            cursor.close()
            
            if not row:
                return None
            
            scopes = json.loads(row['scopes']) if row['scopes'] else []
            
            creds = Credentials(
                token=row['token'],
                refresh_token=row['refresh_token'],
                token_uri=row['token_uri'],
                client_id=row['client_id'],
                client_secret=row['client_secret'],
                scopes=scopes
            )
            
            return creds
            
        except Exception as e:
            logger.error(f"✗ Error loading token: {e}")
            return None
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def delete_token(self, user_id: str) -> bool:
        """Delete user's token from PostgreSQL"""
        conn = None
        try:
            user_hash = self._hash_user_id(user_id)
            
            conn = self.connection_pool.getconn()
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM oauth_tokens WHERE user_hash = %s", (user_hash,))
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()
            
            return deleted_count > 0
                
        except Exception as e:
            logger.error(f"✗ Error deleting token: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.connection_pool.putconn(conn)

# ============================================================================
# CONFIGURATION - Environment Variables
# ============================================================================
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v19"

# Get credentials from environment
GOOGLE_ADS_DEVELOPER_TOKEN = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
GOOGLE_ADS_CLIENT_ID = os.environ.get("GOOGLE_ADS_CLIENT_ID")
GOOGLE_ADS_CLIENT_SECRET = os.environ.get("GOOGLE_ADS_CLIENT_SECRET")

# PostgreSQL Configuration
POSTGRES_HOST = os.environ.get('POSTGRES_HOST', 'jolly-base-ad5zrzvc-pooler.c-2.us-east-1.aws.neon.tech')
POSTGRES_PORT = int(os.environ.get('POSTGRES_PORT', '5432'))
POSTGRES_DB = os.environ.get('POSTGRES_DB', 'neondb')
POSTGRES_USER = os.environ.get('POSTGRES_USER', 'neondb_owner')
POSTGRES_PASSWORD = os.environ.get('POSTGRES_PASSWORD', 'npg_3cGYslJfLRg6')

# Initialize PostgreSQL Storage
try:
    POSTGRES_STORAGE = PostgresTokenStorage(
        host=POSTGRES_HOST,
        port=POSTGRES_PORT,
        database=POSTGRES_DB,
        user=POSTGRES_USER,
        password=POSTGRES_PASSWORD
    )
    USE_POSTGRES = True
    logger.info("✓ PostgreSQL token storage initialized")
except Exception as e:
    logger.error(f"✗ PostgreSQL initialization failed: {e}")
    USE_POSTGRES = False
    raise Exception("PostgreSQL connection required!")

# In-memory cache for user credentials
USER_CREDENTIALS_CACHE = {}

# ============================================================================
# TOKEN MANAGEMENT FUNCTIONS
# ============================================================================

def save_user_token(user_id: str, creds: Credentials):
    """Save user's OAuth token to PostgreSQL"""
    if not USE_POSTGRES:
        raise Exception("PostgreSQL not available!")
    
    if POSTGRES_STORAGE.save_token(user_id, creds):
        USER_CREDENTIALS_CACHE[user_id] = creds
        return True
    raise Exception("Failed to save token")

def load_user_token(user_id: str) -> Optional[Credentials]:
    """Load user's OAuth token from cache or PostgreSQL"""
    if user_id in USER_CREDENTIALS_CACHE:
        return USER_CREDENTIALS_CACHE[user_id]
    
    if not USE_POSTGRES:
        return None
    
    creds = POSTGRES_STORAGE.load_token(user_id)
    if creds:
        USER_CREDENTIALS_CACHE[user_id] = creds
    return creds

def delete_user_token(user_id: str):
    """Delete user's token from PostgreSQL and cache"""
    if USE_POSTGRES:
        POSTGRES_STORAGE.delete_token(user_id)
    
    if user_id in USER_CREDENTIALS_CACHE:
        del USER_CREDENTIALS_CACHE[user_id]

def get_user_credentials(user_id: str, refresh_if_needed: bool = True) -> Credentials:
    """Get OAuth credentials for a specific user"""
    if not GOOGLE_ADS_CLIENT_ID or not GOOGLE_ADS_CLIENT_SECRET:
        raise ValueError("OAuth credentials not configured")
    
    creds = load_user_token(user_id)
    
    if creds and not creds.valid and refresh_if_needed:
        if creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
                save_user_token(user_id, creds)
            except RefreshError:
                delete_user_token(user_id)
                raise ValueError("Token expired and could not be refreshed")
    
    if not creds or not creds.valid:
        raise ValueError(f"No valid credentials for user: {user_id}")
    
    return creds

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to 10 digits without dashes"""
    customer_id = str(customer_id).replace('"', '').replace("'", '')
    customer_id = ''.join(c for c in customer_id if c.isdigit())
    return customer_id.zfill(10)

def get_headers(creds: Credentials, login_customer_id: Optional[str] = None):
    """Get headers for Google Ads API requests"""
    if not GOOGLE_ADS_DEVELOPER_TOKEN:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN not set")
    
    headers = {
        'Authorization': f'Bearer {creds.token}',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN,
        'content-type': 'application/json'
    }
    
    if login_customer_id:
        headers['login-customer-id'] = format_customer_id(login_customer_id)
    
    return headers

# ============================================================================
# AUTHENTICATION TOOLS (4 TOOLS)
# ============================================================================

@mcp.tool()
def start_oauth_flow(
    user_id: str = Field(description="Unique user identifier (email)"),
    redirect_uri: str = Field(default="urn:ietf:wg:oauth:2.0:oob", description="OAuth redirect URI")
) -> str:
    """Start OAuth authentication flow for a new user"""
    try:
        if not GOOGLE_ADS_CLIENT_ID or not GOOGLE_ADS_CLIENT_SECRET:
            return json.dumps({
                "error": "OAuth credentials not configured",
                "message": "Set GOOGLE_ADS_CLIENT_ID and GOOGLE_ADS_CLIENT_SECRET"
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
        
        flow = InstalledAppFlow.from_client_config(client_config, SCOPES, redirect_uri=redirect_uri)
        auth_url, _ = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
        
        USER_CREDENTIALS_CACHE[f"{user_id}_flow"] = flow
        
        return json.dumps({
            "success": True,
            "user_id": user_id,
            "authorization_url": auth_url,
            "instructions": [
                "1. Send URL to user",
                "2. User grants access",
                "3. User receives authorization code",
                "4. Call complete_oauth_flow() with code"
            ]
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def complete_oauth_flow(
    user_id: str = Field(description="Unique user identifier"),
    auth_code: str = Field(description="Authorization code from Google")
) -> str:
    """Complete OAuth flow with authorization code"""
    try:
        flow = USER_CREDENTIALS_CACHE.get(f"{user_id}_flow")
        
        if not flow:
            return json.dumps({
                "error": "OAuth flow not found",
                "message": f"Call start_oauth_flow(user_id='{user_id}') first"
            })
        
        flow.fetch_token(code=auth_code)
        creds = flow.credentials
        
        save_user_token(user_id, creds)
        del USER_CREDENTIALS_CACHE[f"{user_id}_flow"]
        
        return json.dumps({
            "success": True,
            "message": f"Authentication successful for: {user_id}",
            "storage": "PostgreSQL (Neon.tech)",
            "next_steps": [
                "User can now use all Google Ads tools",
                f"Use user_id='{user_id}' in all tool calls"
            ]
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def check_user_auth(user_id: str = Field(description="Unique user identifier")) -> str:
    """Check if user is authenticated and token is valid"""
    try:
        creds = load_user_token(user_id)
        
        if not creds:
            return json.dumps({
                "authenticated": False,
                "user_id": user_id,
                "message": "User not authenticated"
            }, indent=2)
        
        return json.dumps({
            "authenticated": True,
            "user_id": user_id,
            "token_valid": creds.valid,
            "storage": "PostgreSQL (Neon.tech)",
            "status": "ready" if creds.valid else "needs_refresh"
        }, indent=2)
        
    except Exception as e:
        return json.dumps({"error": str(e)})

@mcp.tool()
def revoke_user_access(user_id: str = Field(description="Unique user identifier")) -> str:
    """Revoke access and delete stored credentials"""
    try:
        delete_user_token(user_id)
        return json.dumps({
            "success": True,
            "message": f"Access revoked for: {user_id}"
        }, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})

# ============================================================================
# GOOGLE ADS TOOLS (21 TOOLS)
# ============================================================================

@mcp.tool()
def list_accounts(user_id: str = Field(description="Unique user identifier")) -> str:
    """List all accessible Google Ads accounts"""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return f"No accessible accounts found for: {user_id}"
        
        result_lines = [f"Accessible Google Ads Accounts for {user_id}:", "-" * 50]
        
        for resource_name in customers['resourceNames']:
            customer_id = resource_name.split('/')[-1]
            result_lines.append(f"Account ID: {format_customer_id(customer_id)}")
        
        result_lines.append("\n💡 TIP: Use get_account_details() to see account names")
        return "\n".join(result_lines)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def execute_gaql_query(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID (10 digits)"),
    query: str = Field(description="Valid GAQL query string"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Execute a custom GAQL query"""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        response = requests.post(url, headers=headers, json={"query": query})
        
        if response.status_code != 200:
            return f"Error executing query: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found"
        
        return json.dumps(results, indent=2)
    
    except ValueError as e:
        return f"Authentication error: {str(e)}"
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def get_campaign_performance(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get campaign performance metrics"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_account_details(
    user_id: str = Field(description="Unique user identifier"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get detailed information about all accessible accounts"""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)
        
        if response.status_code != 200:
            return f"Error: {response.text}"
        
        customers = response.json()
        if not customers.get('resourceNames'):
            return "No accessible accounts found"
        
        result_lines = [f"📊 Account Details for {user_id}:", "=" * 100]
        
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
                detail_response = requests.post(detail_url, headers=headers, json={"query": query})
                
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
                result_lines.append(f"  (Error: {str(e)})")
                result_lines.append("-" * 80)
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def get_ad_performance(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get ad performance metrics"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def run_gaql(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    query: str = Field(description="Valid GAQL query string"),
    format: str = Field(default="table", description="Output format: 'table', 'json', or 'csv'"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Execute any arbitrary GAQL query with custom formatting"""
    try:
        creds = get_user_credentials(user_id)
        headers = get_headers(creds, login_customer_id if login_customer_id else None)
        
        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"
        
        response = requests.post(url, headers=headers, json={"query": query})
        
        if response.status_code != 200:
            return f"Error: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return "No results found"
        
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
        
        else:
            return json.dumps(results, indent=2)
    
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def get_ad_creatives(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get ad creative details including headlines, descriptions, and URLs"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_account_currency(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Retrieve the default currency code used by the account"""
    query = """
        SELECT
            customer.id,
            customer.currency_code
        FROM customer
        LIMIT 1
    """
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_image_assets(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    limit: int = Field(default=50, description="Maximum number of image assets"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Retrieve all image assets in the account"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_keyword_performance(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    min_impressions: int = Field(default=100, description="Minimum impressions filter"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get keyword performance metrics including Quality Score"""
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
            metrics.conversions
        FROM keyword_view
        WHERE 
            segments.date DURING LAST_{days}_DAYS
            AND metrics.impressions >= {min_impressions}
        ORDER BY metrics.cost_micros DESC
        LIMIT 100
    """
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_budget_utilization(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze budget utilization across campaigns"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_search_terms(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    min_impressions: int = Field(default=10, description="Minimum impressions filter"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Get actual search terms that triggered your ads"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_audience_performance(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze performance by audience demographics"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_conversion_actions(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """List all conversion actions configured in the account"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_negative_keywords(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """List all negative keywords at campaign and ad group level"""
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
        campaign_result = execute_gaql_query(user_id, customer_id, campaign_query, login_customer_id)
        adgroup_result = execute_gaql_query(user_id, customer_id, adgroup_query, login_customer_id)
        
        output = "=" * 80 + "\n📛 CAMPAIGN-LEVEL NEGATIVE KEYWORDS\n" + "=" * 80 + "\n"
        output += campaign_result
        output += "\n\n" + "=" * 80 + "\n📛 AD GROUP-LEVEL NEGATIVE KEYWORDS\n" + "=" * 80 + "\n"
        output += adgroup_result
        
        return output
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def get_location_performance(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze performance by geographic location"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def get_ad_schedule_performance(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze performance by day of week and hour of day"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def download_image_asset(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    asset_id: str = Field(description="The ID of the image asset to download"),
    output_dir: str = Field(default="./ad_images", description="Directory to save image"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Download a specific image asset from Google Ads account"""
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
        
        response = requests.post(url, headers=headers, json={"query": query})
        
        if response.status_code != 200:
            return f"Error: {response.text}"
        
        results = response.json()
        if not results.get('results'):
            return f"No image asset found with ID {asset_id}"
        
        asset = results['results'][0].get('asset', {})
        image_url = asset.get('imageAsset', {}).get('fullSize', {}).get('url')
        asset_name = asset.get('name', f"image_{asset_id}")
        
        if not image_url:
            return f"No download URL found for asset ID {asset_id}"
        
        # Create output directory
        base_dir = Path.cwd()
        resolved_output_dir = Path(output_dir).resolve()
        
        try:
            resolved_output_dir.relative_to(base_dir)
        except ValueError:
            resolved_output_dir = base_dir / "ad_images"
        
        resolved_output_dir.mkdir(parents=True, exist_ok=True)
        
        # Download image
        image_response = requests.get(image_url)
        if image_response.status_code != 200:
            return f"Failed to download image: HTTP {image_response.status_code}"
        
        safe_name = ''.join(c for c in asset_name if c.isalnum() or c in ' ._-')
        filename = f"{asset_id}_{safe_name}.jpg"
        file_path = resolved_output_dir / filename
        
        with open(file_path, 'wb') as f:
            f.write(image_response.content)
        
        return f"✓ Downloaded image asset {asset_id} to {file_path}"
    
    except Exception as e:
        return f"Error: {str(e)}"

@mcp.tool()
def get_asset_usage(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    asset_id: str = Field(default="", description="Optional: specific asset ID"),
    asset_type: str = Field(default="IMAGE", description="Asset type"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Find where specific assets are being used in campaigns"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def analyze_image_assets(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    days: int = Field(default=30, description="Number of days to look back"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """Analyze image assets with their performance metrics"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

@mcp.tool()
def list_resources(
    user_id: str = Field(description="Unique user identifier"),
    customer_id: str = Field(description="Google Ads customer ID"),
    login_customer_id: str = Field(default="", description="Optional: Manager account ID")
) -> str:
    """List valid resources that can be used in GAQL FROM clauses"""
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
    return execute_gaql_query(user_id, customer_id, query, login_customer_id)

# ============================================================================
# SERVER STARTUP
# ============================================================================

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Google Ads MCP Server - Multi-User Mode")
    logger.info("Total Tools: 25 (4 Auth + 21 Google Ads)")
    logger.info("Storage: PostgreSQL (Neon.tech)")
    logger.info("=" * 60)
    
    mcp.run()
