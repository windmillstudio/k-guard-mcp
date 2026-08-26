function preview(req: any) {
  const url = req.query.url;
  return fetch(url);
}
