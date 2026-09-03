package sessions

import (
	"crypto/subtle"
	"net/http"
	"net/url"
	"time"

	"github.com/bootdotdev/learn-web-security/internal/accounts"
)

const CookieName = "session_id"

const recentAuthenticationWindow = 10 * time.Minute

func Current(request *http.Request, accountStore *accounts.Store) (accounts.CurrentSession, bool, error) {
	cookie, err := request.Cookie(CookieName)
	if err != nil {
		return accounts.CurrentSession{}, false, nil
	}
	return accountStore.CurrentSession(request.Context(), cookie.Value)
}

func Require(responseWriter http.ResponseWriter, request *http.Request, accountStore *accounts.Store) (accounts.CurrentSession, bool, error) {
	return RequireWithReturnTo(responseWriter, request, accountStore, "")
}

func RequireWithReturnTo(responseWriter http.ResponseWriter, request *http.Request, accountStore *accounts.Store, returnTo string) (accounts.CurrentSession, bool, error) {
	currentSession, found, err := Current(request, accountStore)
	if err != nil || found {
		return currentSession, found, err
	}
	loginPath := "/login"
	if returnTo != "" {
		loginPath += "?" + url.Values{"returnTo": {returnTo}}.Encode()
	}
	http.Redirect(responseWriter, request, loginPath, http.StatusFound)
	return accounts.CurrentSession{}, false, nil
}

func CSRFTokensMatch(expected, actual string) bool {
	expectedBytes := []byte(expected)
	actualBytes := []byte(actual)
	return len(expectedBytes) == len(actualBytes) && subtle.ConstantTimeCompare(expectedBytes, actualBytes) == 1
}

func HasRecentAuthentication(current accounts.CurrentSession, now time.Time) bool {
	authenticatedAt, err := time.Parse(time.RFC3339, current.Session.LastAuthenticatedAt)
	if err != nil {
		return false
	}
	return !authenticatedAt.After(now) && !authenticatedAt.Before(now.Add(-recentAuthenticationWindow))
}

func SetCookie(responseWriter http.ResponseWriter, session accounts.Session) {
	http.SetCookie(responseWriter, &http.Cookie{
		Name:     CookieName,
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Lax permits cross-site requests from the same origin
	})
}

func ClearCookie(responseWriter http.ResponseWriter) {
	http.SetCookie(responseWriter, &http.Cookie{
		Name:     CookieName,
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}
