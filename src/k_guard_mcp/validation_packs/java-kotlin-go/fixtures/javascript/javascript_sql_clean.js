function loadUser(req, db) {
  return db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}
