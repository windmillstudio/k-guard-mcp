function runDiagnostic(childProcess) {
  return childProcess.execFile("/usr/bin/id", ["--user", "service"]);
}
