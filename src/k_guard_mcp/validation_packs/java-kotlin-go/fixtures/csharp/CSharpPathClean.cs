using System;
using System.IO;
using Microsoft.AspNetCore.Mvc;

sealed class CSharpPathClean : ControllerBase
{
    string ReadGuide()
    {
        string document = Request.Query["document"];
        if (document != "guide" && document != "terms")
            throw new ArgumentException("unknown document");
        return File.ReadAllText("/srv/public/guide.txt");
    }
}
