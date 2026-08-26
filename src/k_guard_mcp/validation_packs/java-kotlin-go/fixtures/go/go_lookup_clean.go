package fixtures

type GoOwnedLookupContext interface {
	Param(string) string
}

type GoOwnedLookupStore interface {
	GetOwned(string, string) (any, error)
}

func goLookupClean(
	context GoOwnedLookupContext,
	store GoOwnedLookupStore,
	authenticatedOwnerID string,
) (any, error) {
	return store.GetOwned(authenticatedOwnerID, context.Param("accountId"))
}
