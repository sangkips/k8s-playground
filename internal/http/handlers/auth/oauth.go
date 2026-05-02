package authhandler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"golang.org/x/oauth2/google"
)

// OAuthHandler handles the OAuth2 initiation endpoint.
type OAuthHandler struct {
	stateStore OAuthStateStorer
	providers  map[string]*oauth2.Config
}

func NewOAuthHandler(stateStore OAuthStateStorer, githubClientID, githubClientSecret, googleClientID, googleClientSecret string) *OAuthHandler {
	providers := map[string]*oauth2.Config{
		"github": {
			ClientID:     githubClientID,
			ClientSecret: githubClientSecret,
			Endpoint:     github.Endpoint,
			Scopes:       []string{"user:email"},
		},
		"google": {
			ClientID:     googleClientID,
			ClientSecret: googleClientSecret,
			Endpoint:     google.Endpoint,
			Scopes:       []string{"openid", "email", "profile"},
		},
	}
	return &OAuthHandler{stateStore: stateStore, providers: providers}
}

// oauthRequest is the body for POST /api/v1/auth/oauth/:provider
type oauthRequest struct {
	RedirectURI string `json:"redirect_uri"`
}

// OAuthStart handles POST /api/v1/auth/oauth/{provider}
// It validates the provider, generates a state token, stores it in Redis,
// and returns the provider's authorization URL.
func (h *OAuthHandler) OAuthStart(w http.ResponseWriter, r *http.Request) {
	// Extract {provider} from the URL path.
	// Go 1.22+ ServeMux supports path values via r.PathValue.
	provider := strings.ToLower(r.PathValue("provider"))

	cfg, ok := h.providers[provider]
	if !ok {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported provider %q; use github or google", provider))
		return
	}

	var req oauthRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.RedirectURI == "" {
		writeError(w, http.StatusUnprocessableEntity, "redirect_uri is required")
		return
	}

	// Generate a cryptographically random state token.
	stateBytes := make([]byte, 16)
	if _, err := rand.Read(stateBytes); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	state := hex.EncodeToString(stateBytes)

	// Persist state → redirect_uri in Redis (10-minute TTL).
	if err := h.stateStore.Save(r.Context(), state, req.RedirectURI); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// Build the provider authorization URL with the state param.
	authURL := cfg.AuthCodeURL(state, oauth2.AccessTypeOnline)

	writeJSON(w, http.StatusOK, map[string]string{
		"authorization_url": authURL,
	})
}
