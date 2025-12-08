"""
PostgreSQL Token Storage for Google Ads MCP Server
Simple implementation for remote PostgreSQL
"""

import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
import json
import logging
from typing import Optional
from datetime import datetime, timedelta
from google.oauth2.credentials import Credentials
import hashlib

logger = logging.getLogger('postgres_storage')


class PostgresTokenStorage:
    """PostgreSQL-based token storage for OAuth tokens"""
    
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        """
        Initialize PostgreSQL connection to remote server
        
        Args:
            host: PostgreSQL server hostname/IP
            port: PostgreSQL server port (usually 5432)
            database: Database name
            user: Database username
            password: Database password
        """
        try:
            # Create connection pool (1-10 connections)
            self.connection_pool = psycopg2.pool.ThreadedConnectionPool(
                minconn=1,
                maxconn=10,
                host=host,
                port=port,
                database=database,
                user=user,
                password=password,
                connect_timeout=10
            )
            
            logger.info(f"✓ Connected to remote PostgreSQL at {host}:{port}/{database}")
            
            # Create table if doesn't exist
            self._create_table()
            
        except psycopg2.OperationalError as e:
            logger.error(f"✗ Failed to connect to PostgreSQL: {e}")
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
        """Hash user ID for privacy (same as file-based approach)"""
        return hashlib.sha256(user_id.encode()).hexdigest()[:32]
    
    def save_token(self, user_id: str, creds: Credentials) -> bool:
        """
        Save user's OAuth credentials to PostgreSQL
        
        Args:
            user_id: User identifier (email)
            creds: Google OAuth2 Credentials object
            
        Returns:
            bool: True if successful
        """
        conn = None
        try:
            user_hash = self._hash_user_id(user_id)
            expires_at = datetime.now() + timedelta(days=30)
            
            # Prepare data
            scopes_json = json.dumps(list(creds.scopes) if creds.scopes else [])
            expiry = creds.expiry.isoformat() if hasattr(creds, 'expiry') and creds.expiry else None
            
            conn = self.connection_pool.getconn()
            cursor = conn.cursor()
            
            # Upsert query (INSERT or UPDATE if exists)
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
                user_hash,
                creds.token,
                creds.refresh_token,
                creds.token_uri,
                creds.client_id,
                creds.client_secret,
                scopes_json,
                expiry,
                datetime.now(),
                expires_at
            ))
            
            conn.commit()
            cursor.close()
            
            logger.info(f"✓ Saved token to PostgreSQL for user: {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"✗ Error saving token to PostgreSQL for {user_id}: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def load_token(self, user_id: str) -> Optional[Credentials]:
        """
        Load user's OAuth credentials from PostgreSQL
        
        Args:
            user_id: User identifier
            
        Returns:
            Credentials object or None if not found/expired
        """
        conn = None
        try:
            user_hash = self._hash_user_id(user_id)
            
            conn = self.connection_pool.getconn()
            cursor = conn.cursor(cursor_factory=RealDictCursor)
            
            # Query with expiration check
            query = """
            SELECT * FROM oauth_tokens 
            WHERE user_hash = %s 
            AND (expires_at IS NULL OR expires_at > NOW())
            """
            
            cursor.execute(query, (user_hash,))
            row = cursor.fetchone()
            cursor.close()
            
            if not row:
                logger.info(f"No valid token found in PostgreSQL for user: {user_id}")
                return None
            
            # Reconstruct Credentials object
            scopes = json.loads(row['scopes']) if row['scopes'] else []
            
            creds = Credentials(
                token=row['token'],
                refresh_token=row['refresh_token'],
                token_uri=row['token_uri'],
                client_id=row['client_id'],
                client_secret=row['client_secret'],
                scopes=scopes
            )
            
            logger.info(f"✓ Loaded token from PostgreSQL for user: {user_id}")
            return creds
            
        except Exception as e:
            logger.error(f"✗ Error loading token from PostgreSQL for {user_id}: {e}")
            return None
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def delete_token(self, user_id: str) -> bool:
        """
        Delete user's token from PostgreSQL
        
        Args:
            user_id: User identifier
            
        Returns:
            bool: True if successful
        """
        conn = None
        try:
            user_hash = self._hash_user_id(user_id)
            
            conn = self.connection_pool.getconn()
            cursor = conn.cursor()
            
            delete_query = "DELETE FROM oauth_tokens WHERE user_hash = %s"
            cursor.execute(delete_query, (user_hash,))
            
            deleted_count = cursor.rowcount
            conn.commit()
            cursor.close()
            
            if deleted_count > 0:
                logger.info(f"✓ Deleted token from PostgreSQL for user: {user_id}")
                return True
            else:
                logger.info(f"No token to delete for user: {user_id}")
                return False
                
        except Exception as e:
            logger.error(f"✗ Error deleting token from PostgreSQL for {user_id}: {e}")
            if conn:
                conn.rollback()
            return False
        finally:
            if conn:
                self.connection_pool.putconn(conn)
    
    def close(self):
        """Close all connections in the pool"""
        try:
            self.connection_pool.closeall()
            logger.info("✓ Closed PostgreSQL connection pool")
        except Exception as e:
            logger.error(f"Error closing connection pool: {e}")
