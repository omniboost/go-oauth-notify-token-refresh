package tokennotify

import (
	"sync"

	"golang.org/x/oauth2"
)

// TokenNotifyFunc is a function that accepts an oauth2 Token upon refresh, and
// returns an error if it should not be used.
type TokenNotifyFunc func(*oauth2.Token) error

func notifyFunc(t *oauth2.Token) error {
	return nil
}

func NotifyRefreshTokenSource(t *oauth2.Token, src oauth2.TokenSource) *notifyRefreshTokenSource {
	// Don't wrap a notifyRefreshTokenSource in itself. That would work,
	// but cause an unnecessary number of mutex operations.
	// Just build the equivalent one.
	if rt, ok := src.(*notifyRefreshTokenSource); ok {
		if t == nil {
			// Just use it directly.
			return rt
		}
		src = rt.new
	}
	return &notifyRefreshTokenSource{
		t:          t,
		new:        src,
		notifyFunc: notifyFunc,
	}
}

// NotifyRefreshTokenSource is essentially `oauth2.ResuseTokenSource` with `TokenNotifyFunc` added.
type notifyRefreshTokenSource struct {
	new        oauth2.TokenSource
	mu         sync.Mutex // guards t
	t          *oauth2.Token
	notifyFunc TokenNotifyFunc // called when token refreshed so new refresh token can be persisted
}

// Token returns the current token if it's still valid, else will
// refresh the current token (using r.Context for HTTP client
// information) and return the new one.
func (s notifyRefreshTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.t.Valid() {
		// token is still valid, just return it
		return s.t, nil
	}

	// request new token
	t, err := s.new.Token()
	if err != nil {
		return nil, err
	}

	// assign new token
	s.t = t

	if s.notifyFunc != nil {
		// return new token and execute notify func
		return t, s.notifyFunc(t)
	}
	return t, nil
}

// WithNotifyFunc
func (s notifyRefreshTokenSource) WithNotifyFunc(f TokenNotifyFunc) notifyRefreshTokenSource {
	s.notifyFunc = f
	return s
}
