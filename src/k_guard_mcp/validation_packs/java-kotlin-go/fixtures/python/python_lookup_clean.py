def load_record(request, User, current_user):
    return User.query.filter_by(id=request.args.get("id"), owner_id=current_user.id).one()
