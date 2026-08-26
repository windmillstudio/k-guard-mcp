using Microsoft.AspNetCore.Mvc;

interface IOwnedAccountRepository
{
    object FindOwned(string ownerId, object accountId);
}

sealed class CSharpLookupClean : ControllerBase
{
    object LoadOwnedAccount(IOwnedAccountRepository repository, string authenticatedOwnerId)
    {
        return repository.FindOwned(authenticatedOwnerId, Request.RouteValues["accountId"]);
    }
}
