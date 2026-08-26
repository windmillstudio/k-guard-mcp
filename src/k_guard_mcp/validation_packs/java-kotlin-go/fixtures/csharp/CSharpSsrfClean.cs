using System;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

sealed class CSharpSsrfClean : ControllerBase
{
    Task<string> FetchHealth(HttpClient client)
    {
        string service = Request.Query["service"];
        if (service != "health")
            throw new ArgumentException("unknown service");
        return client.GetStringAsync("https://api.example.com/health");
    }
}
