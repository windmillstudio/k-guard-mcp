function runDiagnostic(childProcess: any) {
  return childProcess.execFile("/usr/bin/id", ["--user", "service"]);
}
