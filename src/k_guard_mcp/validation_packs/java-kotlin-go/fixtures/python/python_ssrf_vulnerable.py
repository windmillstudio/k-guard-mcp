import requests


def preview(request):
    url = request.args.get("url")
    return requests.get(url, timeout=2)
