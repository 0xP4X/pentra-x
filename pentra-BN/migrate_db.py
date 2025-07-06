#!/usr/bin/env python3
"""
Database Migration Script for pentra-BN
Sets up PostgreSQL database and creates all necessary tables
"""

import os
import sys
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError

# Database Configuration
DATABASE_URL = "postgresql://postgres:Admin123@localhost:5432/pentrax_db"

def create_database():
    """Create the database if it doesn't exist"""
    try:
        # Connect to PostgreSQL server (without specifying database)
        engine = create_engine("postgresql://postgres:Admin123@localhost:5432/postgres")
        
        with engine.connect() as conn:
            # Check if database exists
            result = conn.execute(text("SELECT 1 FROM pg_database WHERE datname = 'pentrax_db'"))
            if not result.fetchone():
                # Create database
                conn.execute(text("CREATE DATABASE pentrax_db"))
                print("[+] Database 'pentrax_db' created successfully")
            else:
                print("[*] Database 'pentrax_db' already exists")
                
    except OperationalError as e:
        print(f"[!] Error connecting to PostgreSQL: {e}")
        print("[!] Please ensure PostgreSQL is running and credentials are correct")
        return False
    except Exception as e:
        print(f"[!] Error creating database: {e}")
        return False
    
    return True

def create_tables():
    """Create all necessary tables"""
    try:
        from botnet_server import app, db
        
        with app.app_context():
            # Create all tables
            db.create_all()
            print("[+] All tables created successfully")
            
            # Verify tables exist
            inspector = db.inspect(db.engine)
            tables = inspector.get_table_names()
            print(f"[*] Created tables: {', '.join(tables)}")
            
    except Exception as e:
        print(f"[!] Error creating tables: {e}")
        return False
    
    return True

def insert_initial_data():
    """Insert any initial data if needed"""
    try:
        from botnet_server import app, db
        
        with app.app_context():
            # Add any initial data here if needed
            print("[+] Initial data setup completed")
            
    except Exception as e:
        print(f"[!] Error inserting initial data: {e}")
        return False
    
    return True

def test_connection():
    """Test database connection"""
    try:
        engine = create_engine(DATABASE_URL)
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version()"))
            version = result.fetchone()[0]
            print(f"[+] Database connection successful")
            print(f"[*] PostgreSQL version: {version}")
            return True
    except Exception as e:
        print(f"[!] Database connection failed: {e}")
        return False

def main():
    """Main migration function"""
    print("🚀 pentra-BN Database Migration")
    print("=" * 40)
    
    # Step 1: Test connection
    print("\n[1] Testing PostgreSQL connection...")
    if not test_connection():
        print("[!] Cannot proceed without database connection")
        sys.exit(1)
    
    # Step 2: Create database
    print("\n[2] Creating database...")
    if not create_database():
        print("[!] Failed to create database")
        sys.exit(1)
    
    # Step 3: Create tables
    print("\n[3] Creating tables...")
    if not create_tables():
        print("[!] Failed to create tables")
        sys.exit(1)
    
    # Step 4: Insert initial data
    print("\n[4] Setting up initial data...")
    if not insert_initial_data():
        print("[!] Failed to insert initial data")
        sys.exit(1)
    
    print("\n✅ Database migration completed successfully!")
    print("�� Database: pentrax_db")
    print("🔗 Connection: postgresql://postgres:***@localhost:5432/pentrax_db")
    print("\n🚀 You can now start the pentra-BN server!")

if __name__ == "__main__":
    main() 