def load_user(request, cursor):
    user_id = request.args.get("id")
    return cursor.execute("SELECT * FROM users WHERE id = " + user_id)
