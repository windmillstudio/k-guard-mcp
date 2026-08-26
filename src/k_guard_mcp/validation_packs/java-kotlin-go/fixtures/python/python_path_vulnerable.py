def download(request):
    path = request.args.get("path")
    with open(path, encoding="utf-8") as handle:
        return handle.read()
