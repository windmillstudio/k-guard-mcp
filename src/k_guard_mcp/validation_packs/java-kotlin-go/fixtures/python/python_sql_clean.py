def load_user(request, cursor):
    return cursor.execute("SELECT * FROM users WHERE id = ?", (request.args.get("id"),))
