function loadRecord(req: any, User: any) {
  return User.findByPk(req.params.id);
}
