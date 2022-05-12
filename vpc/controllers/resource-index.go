package controllers

const (
	// ManagedResourceByGroup causes the indexer to return all ManagedResource in a ResourceGroup.
	ManagedResourceByGroup = "managedResourceByGroup"
	// HostConnectedToTOR causes the indexer to return all HostInterfaces connected to a TOR.
	HostConnectedToTOR = "hostConnectedToTOR"
	// TORsConnectedHost causes the indexer to return all the TORs connected to a host.
	TORsConnectedHost = "TORsConnectedHost"
	// ManagedResourceByIdentifier causes the indexer to return a ManagedResource matches identifier.
	ManagedResourceByIdentifier = "managedResourceByIdentifier"
)
