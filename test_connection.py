from pymongo import MongoClient

# Replace with your connection string
connection_string = "mongodb+srv://pmadmin:RohnKeep012!@promptmenu.global.mongocluster.cosmos.azure.com/?tls=true&authMechanism=SCRAM-SHA-256&retrywrites=false&maxIdleTimeMS=120000"

try:
    print("Connecting to MongoDB...")
    client = MongoClient(connection_string, serverSelectionTimeoutMS=10000)  # 10 seconds timeout
    # Test the connection
    print(client.server_info())  # Fetch server info to verify connection
    print("Connected to MongoDB!")
except Exception as e:
    print(f"Connection failed: {e}")