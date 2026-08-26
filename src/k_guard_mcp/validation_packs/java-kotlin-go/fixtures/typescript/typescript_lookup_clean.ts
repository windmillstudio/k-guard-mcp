function loadRecord(req: any, User: any) {
  return User.findOwnedById(req.user.id, req.params.id);
}
