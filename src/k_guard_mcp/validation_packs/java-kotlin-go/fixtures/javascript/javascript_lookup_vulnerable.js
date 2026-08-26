function loadRecord(req, User) {
  return User.findById(req.params.id);
}
