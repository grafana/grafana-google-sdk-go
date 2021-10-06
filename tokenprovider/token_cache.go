package tokenprovider

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

var (
	// timeNow makes it possible to test usage of time
	timeNow = time.Now
)

// AccessToken contains a token and its expiration
type AccessToken struct {
	Token     string
	ExpiresOn time.Time
}

// TokenRetriever allows a token source to use the cache
type TokenRetriever interface {
	GetCacheKey() string
	GetAccessToken(ctx context.Context, scopes []string) (*AccessToken, error)
}

// ConcurrentTokenCache stores the previous tokens
type ConcurrentTokenCache interface {
	GetAccessToken(ctx context.Context, tokenRetriever TokenRetriever, scopes []string) (string, error)
}

// NewConcurrentTokenCache returns a new cache
func NewConcurrentTokenCache() ConcurrentTokenCache {
	return &tokenCacheImpl{}
}

type tokenCacheImpl struct {
	cache sync.Map // of *credentialCacheEntry
}
type credentialCacheEntry struct {
	retriever TokenRetriever
	cache     sync.Map // of *scopesCacheEntry
}

type scopesCacheEntry struct {
	retriever TokenRetriever
	scopes    []string

	cond        *sync.Cond
	refreshing  bool
	accessToken *AccessToken
}

// GetAccessToken looks up a token for the given parameters, and generates one if one isn't found
func (c *tokenCacheImpl) GetAccessToken(ctx context.Context, tokenRetriever TokenRetriever, scopes []string) (string, error) {
	return c.getEntryFor(tokenRetriever).getAccessToken(ctx, scopes)
}

func (c *tokenCacheImpl) getEntryFor(credential TokenRetriever) *credentialCacheEntry {
	var entry interface{}

	key := credential.GetCacheKey()

	entry, _ = c.cache.LoadOrStore(key, &credentialCacheEntry{
		retriever: credential,
	})

	return entry.(*credentialCacheEntry)
}

func (c *credentialCacheEntry) getAccessToken(ctx context.Context, scopes []string) (string, error) {
	return c.getEntryFor(scopes).getAccessToken(ctx)
}

func (c *credentialCacheEntry) getEntryFor(scopes []string) *scopesCacheEntry {
	var entry interface{}

	key := getKeyForScopes(scopes)

	entry, _ = c.cache.LoadOrStore(key, &scopesCacheEntry{
		retriever: c.retriever,
		scopes:    scopes,
		cond:      sync.NewCond(&sync.Mutex{}),
	})

	return entry.(*scopesCacheEntry)
}

func (c *scopesCacheEntry) getAccessToken(ctx context.Context) (string, error) {
	var accessToken *AccessToken
	var err error
	shouldRefresh := false

	c.cond.L.Lock()
	for {
		if c.accessToken != nil && c.accessToken.ExpiresOn.After(timeNow().Add(time.Second*10)) {
			// Use the cached token since it's available and not expired yet
			accessToken = c.accessToken
			break
		}

		if !c.refreshing {
			// Start refreshing the token
			c.refreshing = true
			shouldRefresh = true
			break
		}

		// Wait for the token to be refreshed
		c.cond.Wait()
	}
	c.cond.L.Unlock()

	if shouldRefresh {
		accessToken, err = c.refreshAccessToken(ctx)
		if err != nil {
			return "", err
		}
	}

	return accessToken.Token, nil
}

func (c *scopesCacheEntry) refreshAccessToken(ctx context.Context) (*AccessToken, error) {
	var accessToken *AccessToken

	// Safeguarding from panic caused by retriever implementation
	defer func() {
		c.cond.L.Lock()

		c.refreshing = false

		if accessToken != nil {
			c.accessToken = accessToken
		}

		c.cond.Broadcast()
		c.cond.L.Unlock()
	}()

	token, err := c.retriever.GetAccessToken(ctx, c.scopes)
	if err != nil {
		return nil, err
	}
	accessToken = token
	return accessToken, nil
}

func getKeyForScopes(scopes []string) string {
	if len(scopes) > 1 {
		arr := make([]string, len(scopes))
		copy(arr, scopes)
		sort.Strings(arr)
		scopes = arr
	}

	return strings.Join(scopes, " ")
}
