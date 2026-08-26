using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

sealed class CSharpCommandVulnerable : ControllerBase
{
    void RunReport()
    {
        string command = Request.Form["command"];
        Process.Start(command);
    }
}
