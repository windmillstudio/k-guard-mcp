import * as childProcess from "node:child_process";

function runDiagnostic(req: any) {
  const command = req.query.command;
  return childProcess.exec(command);
}
