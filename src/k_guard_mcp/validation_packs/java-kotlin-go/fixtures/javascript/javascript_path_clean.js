function download(fs, respond) {
  return fs.readFile("/srv/public/index.html", respond);
}
