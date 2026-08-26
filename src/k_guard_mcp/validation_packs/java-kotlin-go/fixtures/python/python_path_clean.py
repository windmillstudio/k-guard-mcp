def download():
    with open("/srv/public/index.html", encoding="utf-8") as handle:
        return handle.read()
