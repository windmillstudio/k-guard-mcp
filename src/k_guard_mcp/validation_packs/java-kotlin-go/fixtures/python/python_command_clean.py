import subprocess


def run_diagnostic():
    return subprocess.run(["/usr/bin/id", "--user", "service"], shell=False, check=True)
