package cache

// PKCEVerifierCache
type PKCEVerifierCache interface {
	// Set saves PKCE secret in cache.
	Set(key, value string) error
	// Get retrieves PKCE secret from cache.
	Get(key string) (string, bool, error)
}
