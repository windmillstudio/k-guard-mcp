function loadUser(req, db) {
  const id = req.query.id;
  return db.query("SELECT * FROM users WHERE id = " + id);
}
