using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;

sealed class CSharpCommandClean : ControllerBase
{
    void RunReport()
    {
        string requestedFormat = Request.Form["format"];
        string format = requestedFormat == "csv" ? "csv" : "json";
        Process.Start(new ProcessStartInfo
        {
            FileName = "/usr/bin/report",
            Arguments = "--format " + format,
            UseShellExecute = false,
        });
    }
}
