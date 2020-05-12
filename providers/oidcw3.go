package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"

	"github.com/oauth2-proxy/oauth2-proxy/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/pkg/requests"
)

// OIDCIBMW3idProvider represents an OIDC based Identity Provider
type OIDCIBMW3idProvider struct {
	*ProviderData

	Verifier             *oidc.IDTokenVerifier
	AllowUnverifiedEmail bool
}

// NewOIDCIBMW3idProvider initiates a new OIDCProvider
func NewOIDCIBMW3idProvider(p *ProviderData) *OIDCIBMW3idProvider {
	p.ProviderName = "IBM w3id's OpenID Connect"
	return &OIDCIBMW3idProvider{ProviderData: p}
}

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCIBMW3idProvider) Redeem(ctx context.Context, redirectURL, code string) (s *sessions.SessionState, err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
		RedirectURL: redirectURL,
	}
	// 20180629 - TL: Added logging
	//fmt.Printf("Client ID: %s\n", p.ClientID)
	//fmt.Printf("Client Secret: %s\n", p.ClientSecret)
	//fmt.Printf("Token URL: %s\n", p.RedeemURL.String())
	//fmt.Printf("Redirect URL: %s\n", redirectURL)
	//fmt.Printf("Code: %s\n", code)

	// 20180629 - TL: Add in a parameter to handle registering broken oauth2's
	oauth2.RegisterBrokenAuthHeaderProvider(p.RedeemURL.String())

	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}
	fmt.Printf("Token: %v\n", token)

	// in the initial exchange the id token is mandatory
	idToken, err := p.findVerifiedIDToken(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("could not verify id_token: %v", err)
	} else if idToken == nil {
		return nil, fmt.Errorf("token response did not contain an id_token")
	}

	s, err = p.createSessionState(ctx, token, idToken)
	if err != nil {
		return nil, fmt.Errorf("unable to update session: %v", err)
	}

	return
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access Token (and optional ID token) if required
func (p *OIDCIBMW3idProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	fmt.Printf("RefreshSessionIfNeeded() - %v\n", s)
	if s == nil || s.ExpiresOn.After(time.Now()) || s.RefreshToken == "" {
		return false, nil
	}
	origExpiration := s.ExpiresOn

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		fmt.Printf("RefreshSessionIfNeeded() - Error: %v\n", err)
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed id token %s (expired on %s)\n", s, origExpiration)
	return true, nil
}

func (p *OIDCIBMW3idProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) (err error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return
	}

	c := oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			TokenURL: p.RedeemURL.String(),
		},
	}
	t := &oauth2.Token{
		RefreshToken: s.RefreshToken,
		Expiry:       time.Now().Add(-time.Hour),
	}
	token, err := c.TokenSource(ctx, t).Token()
	fmt.Printf("redeemRefreshToken() - token: %v\n", token)
	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	// in the token refresh response the id_token is optional
	idToken, err := p.findVerifiedIDToken(ctx, token)
	if err != nil {
		return fmt.Errorf("unable to extract id_token from response: %v", err)
	}

	newSession, err := p.createSessionState(ctx, token, idToken)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the session will not contain an id token
	// if it doesn't it's probably better to retain the old one
	if newSession.IDToken != "" {
		s.IDToken = newSession.IDToken
		s.Email = newSession.Email
		s.User = newSession.User
		s.PreferredUsername = newSession.PreferredUsername
	}

	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	return
}

func (p *OIDCIBMW3idProvider) findVerifiedIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {

	getIDToken := func() (string, bool) {
		rawIDToken, _ := token.Extra("id_token").(string)
		return rawIDToken, len(strings.TrimSpace(rawIDToken)) > 0
	}

	if rawIDToken, present := getIDToken(); present {
		verifiedIDToken, err := p.Verifier.Verify(ctx, rawIDToken)
		return verifiedIDToken, err
	}
	return nil, nil
}

func (p *OIDCIBMW3idProvider) createSessionState(ctx context.Context, token *oauth2.Token, idToken *oidc.IDToken) (*sessions.SessionState, error) {

	newSession := &sessions.SessionState{}

	fmt.Printf("createSessionState() - rawIDToken: %v\n", idToken)
	if idToken != nil {
		claims, err := findClaimsFromIDTokenIBMw3(idToken, token.AccessToken, p.ProfileURL.String())
		if err != nil {
			return nil, fmt.Errorf("couldn't extract claims from id_token (%e)", err)
		}

		if claims != nil {

			if !p.AllowUnverifiedEmail && claims.Verified != nil && !*claims.Verified {
				return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.Email)
			}

			newSession.Email = claims.Email
			newSession.User = claims.Subject
			newSession.PreferredUsername = claims.PreferredUsername

			// 20180629 - TL: Remove unnecessary bloat due to BlueGroups
			bmrgIDToken, err := removeW3idBlueGroupsInIDToken(token.Extra("id_token").(string))
			if err != nil {
				fmt.Errorf("Unable to Remove W3id Blue Groups in ID Token: %v", err)
				bmrgIDToken = token.Extra("id_token").(string)
			}
			fmt.Printf("Boomerang IDToken: %s\n", bmrgIDToken)
			newSession.IDToken = bmrgIDToken
		}

	}

	newSession.AccessToken = token.AccessToken
	newSession.RefreshToken = token.RefreshToken
	newSession.CreatedAt = time.Now()
	newSession.ExpiresOn = token.Expiry
	return newSession, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCIBMW3idProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	if err != nil {
		return false
	}

	return true
}

func findClaimsFromIDTokenIBMw3(idToken *oidc.IDToken, accessToken string, profileURL string) (*IBMClaims, error) {

	// Extract custom claims.
	claims := &IBMClaims{}
	if err := idToken.Claims(claims); err != nil {
		return nil, fmt.Errorf("failed to parse id_token claims: %v", err)
	}

	if claims.Email == "" {
		if profileURL == "" {
			return nil, fmt.Errorf("id_token did not contain an email")
		}

		// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
		// contents at the profileURL contains the email.
		// Make a query to the userinfo endpoint, and attempt to locate the email from there.

		req, err := http.NewRequest("GET", profileURL, nil)
		if err != nil {
			return nil, err
		}
		req.Header = getOIDCHeader(accessToken)

		respJSON, err := requests.Request(req)
		if err != nil {
			return nil, err
		}

		email, err := respJSON.Get("email").String()
		if err != nil {
			return nil, fmt.Errorf("neither id_token nor userinfo endpoint contained an email")
		}

		claims.Email = email
	}

	return claims, nil
}

func removeW3idBlueGroupsInIDToken(p string) (string, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("oidcibm removeW3idBlueGroupsInIDToken() - malformed jwt, expected 3 parts got %d", len(parts))
	}
	bytePayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidcibm removeW3idBlueGroupsInIDToken() - malformed jwt payload: %v", err)
	}
	//fmt.Printf("Original Payload: %q\n", bytePayload)
	var jsonPayload map[string]interface{}
	json.Unmarshal(bytePayload, &jsonPayload)
	for k := range jsonPayload {
		if k == "blueGroups" {
			delete(jsonPayload, k)
		}
	}
	bytePayload2, err := json.Marshal(jsonPayload)
	//fmt.Printf("Payload no BlueGroups: %q\n", bytePayload2)
	parts[1] = base64.RawURLEncoding.EncodeToString(bytePayload2)

	return strings.Join(parts, "."), nil
}

// IBMClaims with IBM w3id structure
type IBMClaims struct {
	Subject           string `json:"sub"`
	Email             string `json:"emailAddress"`
	Verified          *bool  `json:"email_verified"`
	PreferredUsername string `json:"preferred_username"`
}
