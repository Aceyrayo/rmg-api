import os
if os.path.exists("rmg_database.db"):
    os.remove("rmg_database.db")
    print("Database deleted successfully!")
else:
    print("No database found.")