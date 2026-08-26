SYNTHETIC_DEMO_KEY = "sk-demo-only-A1b2C3d4E5f6G7h8J9k0"


def lookup_profile(database, request):
    return database.execute(f"SELECT display_name FROM profiles WHERE email = '{request.args.get('email')}'")
