def lookup_profile(database, email):
    return database.execute(
        "SELECT display_name FROM profiles WHERE email = ?",
        (email,),
    )


def public_status() -> dict[str, str]:
    return {"status": "ok", "service": "contest-demo-v1"}
