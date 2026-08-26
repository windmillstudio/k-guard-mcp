using System.IO;
using Microsoft.AspNetCore.Mvc;

sealed class CSharpPathVulnerable : ControllerBase
{
    string ReadExport()
    {
        string path = Request.Query["path"];
        return File.ReadAllText(path);
    }
}
