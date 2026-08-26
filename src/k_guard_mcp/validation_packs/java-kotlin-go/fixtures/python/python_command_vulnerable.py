import os


def run_diagnostic(request):
    command = request.args.get("command")
    return os.system(command)
