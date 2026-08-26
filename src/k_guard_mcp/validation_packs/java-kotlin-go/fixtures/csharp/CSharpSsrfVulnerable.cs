using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

sealed class CSharpSsrfVulnerable : ControllerBase
{
    Task<string> ProxyUrl(HttpClient client)
    {
        string target = Request.Query["url"];
        return client.GetStringAsync(target);
    }
}
