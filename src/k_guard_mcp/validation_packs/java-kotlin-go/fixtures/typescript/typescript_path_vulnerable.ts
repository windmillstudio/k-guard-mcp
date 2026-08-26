function download(req: any, fs: any, respond: any) {
  const path = req.query.path;
  return fs.readFile(path, respond);
}
