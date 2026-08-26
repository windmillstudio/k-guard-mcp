function loadUser(req: any, db: any) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}
