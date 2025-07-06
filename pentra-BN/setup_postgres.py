#!/usr/bin/env python3
"""
PostgreSQL Setup Script for pentra-BN
Creates database and user if they don't exist
"""

import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

def setup_postgres():
    """Setup PostgreSQL database and user"""
    
    # Database configuration
    DB_NAME = "pentrax_db"
    DB_USER = "postgres"
    DB_PASSWORD = "Admin123"
    DB_HOST = "localhost"
    DB_PORT = "5432"
    
    try:
        # Connect to PostgreSQL server
        conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database="postgres"  # Connect to default postgres database
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_database WHERE datname = %s", (DB_NAME,))
        exists = cursor.fetchone()
        
        if not exists:
            # Create database
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"[+] Database '{DB_NAME}' created successfully")
        else:
            print(f"[*] Database '{DB_NAME}' already exists")
        
        cursor.close()
        conn.close()
        
        # Test connection to the new database
        test_conn = psycopg2.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        test_conn.close()
        print(f"[+] Successfully connected to database '{DB_NAME}'")
        
        return True
        
    except psycopg2.Error as e:
        print(f"[!] PostgreSQL error: {e}")
        return False
    except Exception as e:
        print(f"[!] Error: {e}")
        return False

def main():
    """Main setup function"""
    print("🗄️ PostgreSQL Setup for pentra-BN")
    print("=" * 40)
    
    if setup_postgres():
        print("\n✅ PostgreSQL setup completed successfully!")
        print(f"📊 Database: pentrax_db")
        print(f"🔗 Connection: postgresql://postgres:***@localhost:5432/pentrax_db")
        print("\n🚀 You can now run the migration script!")
    else:
        print("\n❌ PostgreSQL setup failed!")
        print("Please ensure PostgreSQL is running and credentials are correct.")

if __name__ == "__main__":
    main() 