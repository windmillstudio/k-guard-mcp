function loadRecord(req, User) {
  return User.findOwnedById(req.user.id, req.params.id);
}
