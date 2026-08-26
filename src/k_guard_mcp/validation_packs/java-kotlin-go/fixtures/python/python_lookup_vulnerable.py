def load_record(request, User):
    return User.query.get(request.args.get("id"))
