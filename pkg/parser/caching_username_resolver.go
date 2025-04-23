// Package parser provides utilities for parsing and resolving data,
// including caching mechanisms for username resolution.
package parser

import (
	"os"
	"os/user"
	"sync"
	"time"
)

// CachingUsernameResolver is the caching based resolver
type CachingUsernameResolver struct {
	cacheLock  *sync.Mutex
	cache      map[string]string
	lastFlush  time.Time
	passwdPath string
}

// NewCachingUsernameResolver constructs a new username resolver with caching
func NewCachingUsernameResolver(passwdPath string) UsernameResolver {
	return &CachingUsernameResolver{
		cacheLock:  &sync.Mutex{},
		cache:      make(map[string]string),
		lastFlush:  time.Now(),
		passwdPath: passwdPath,
	}
}

// Resolve takes a UID and resolves it to a username
func (r *CachingUsernameResolver) Resolve(uid string) string {
	uname := "UNKNOWN_USER"

	if cacheValue, ok := r.cache[uid]; ok && r.checkCache() {
		return cacheValue
	}

	luser, err := user.LookupId(uid)
	if err == nil {
		uname = luser.Username
	}

	r.save(uid, uname)

	return uname
}

func (r *CachingUsernameResolver) checkCache() bool {
	filestat, err := os.Stat(r.passwdPath)
	if err == nil {
		lastMod := filestat.ModTime()
		if lastMod.After(r.lastFlush) {
			// if the passwd file was modified after the last flush of the cache
			// then flush the cache
			r.flush()
			return false
		}
	}

	return true
}

func (r *CachingUsernameResolver) flush() {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()

	r.cache = make(map[string]string)
	r.lastFlush = time.Now()
}

func (r *CachingUsernameResolver) save(uid string, uname string) {
	r.cacheLock.Lock()
	defer r.cacheLock.Unlock()
	r.cache[uid] = uname
}
