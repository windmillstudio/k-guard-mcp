function loadUser(req: any, db: any) {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + id);
}
