using Microsoft.AspNetCore.Mvc;

interface IAccountRepository
{
    object FindById(object accountId);
}

sealed class CSharpLookupVulnerable : ControllerBase
{
    object LoadAccount(IAccountRepository repository)
    {
        return repository.FindById(Request.RouteValues["accountId"]);
    }
}
