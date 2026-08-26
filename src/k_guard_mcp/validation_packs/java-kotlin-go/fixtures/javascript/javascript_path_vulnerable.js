function download(req, fs, respond) {
  const path = req.query.path;
  return fs.readFile(path, respond);
}
