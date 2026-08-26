const childProcess = require("node:child_process");

function runDiagnostic(req) {
  const command = req.query.command;
  return childProcess.exec(command);
}
