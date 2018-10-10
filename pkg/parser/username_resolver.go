package parser

import (
	"os/user"
)

// UsernameResolver is the abstraction for ways to get usernames from uids
type UsernameResolver interface {
	Resolve(uid string) string
}

// DefaultUsernameResolver is the default system resolver
type DefaultUsernameResolver struct{}

func NewDefaultUsernameResolver() UsernameResolver {
	return &DefaultUsernameResolver{}
}

// Resolve takes a UID and resolves it to a username
func (r *DefaultUsernameResolver) Resolve(uid string) string {
	uname := "UNKNOWN_USER"
	luser, err := user.LookupId(uid)
	if err == nil {
		uname = luser.Username
	}
	return uname
}
