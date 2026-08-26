import requests


def status():
    return requests.get("https://api.example.test/status", timeout=2)
