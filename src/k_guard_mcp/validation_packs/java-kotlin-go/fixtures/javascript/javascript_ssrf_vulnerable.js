function preview(req) {
  const url = req.query.url;
  return fetch(url);
}
