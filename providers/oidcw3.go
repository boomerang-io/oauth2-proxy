package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	UserIDClaim          string
}

// NewOIDCIBMW3idProvider initiates a new OIDCIBMW3idProvider
func NewOIDCIBMW3idProvider(p *ProviderData) *OIDCIBMW3idProvider {
	p.ProviderName = "IBM w3id's OpenID Connect"
	return &OIDCIBMW3idProvider{ProviderData: p}
}

var _ Provider = (*OIDCIBMW3idProvider)(nil)

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

	// Added logging
	//logger.Printf("Client ID: %s", p.ClientID)
	//logger.Printf("Client Secret: %s", p.ClientSecret)
	//logger.Printf("Token URL: %s", p.RedeemURL.String())
	//logger.Printf("Redirect URL: %s", redirectURL)
	//logger.Printf("Code: %s", code)

	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange: %v", err)
	}

	//logger.Printf("Token: %v\n", token)

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
	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	fmt.Printf("refreshed access token %s (expired on %s)\n", s, s.ExpiresOn)
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
	//fmt.Printf("redeemRefreshToken() - token: %v\n", token)
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
		//logger.Printf("findVerifiedIDToken() - %v ", rawIDToken)
		//logger.Printf("findVerifiedIDToken() isPresent - %v ", present)
		//logger.Printf("findVerifiedIDToken() Verifier - %v ", p.Verifier)
		verifiedIDToken, err := p.Verifier.Verify(ctx, rawIDToken)
		return verifiedIDToken, err
	}
	return nil, nil
}

func (p *OIDCIBMW3idProvider) createSessionState(ctx context.Context, token *oauth2.Token, idToken *oidc.IDToken) (*sessions.SessionState, error) {

	var newSession *sessions.SessionState

	//logger.Printf("createSessionState() - rawIDToken: %v\n", idToken)
	if idToken == nil {
		newSession = &sessions.SessionState{}
	} else {
		var err error
		newSession, err = p.createSessionStateInternal(ctx, idToken, token)
		if err != nil {
			return nil, err
		}
	}

	created := time.Now()
	newSession.AccessToken = token.AccessToken
	newSession.RefreshToken = token.RefreshToken
	newSession.CreatedAt = &created
	newSession.ExpiresOn = &token.Expiry
	return newSession, nil
}

func (p *OIDCIBMW3idProvider) CreateSessionStateFromBearerToken(ctx context.Context, rawIDToken string, idToken *oidc.IDToken) (*sessions.SessionState, error) {
	//logger.Printf("ID Token: %v\n", idToken)
	//logger.Printf("rawIDToken: %v\n", rawIDToken)
	newSession, err := p.createSessionStateInternal(ctx, idToken, nil)
	if err != nil {
		return nil, err
	}

	newSession.AccessToken = rawIDToken
	newSession.IDToken = rawIDToken
	newSession.RefreshToken = ""
	newSession.ExpiresOn = &idToken.Expiry

	return newSession, nil
}

func (p *OIDCIBMW3idProvider) createSessionStateInternal(ctx context.Context, idToken *oidc.IDToken, token *oauth2.Token) (*sessions.SessionState, error) {
	//logger.Printf("createSessionStateInternal - ID Token: %v\n", idToken)
	//logger.Printf("createSessionStateInternal - token: %v\n", token)
	newSession := &sessions.SessionState{}

	if idToken == nil {
		return newSession, nil
	}

	claims, err := p.findClaimsFromIDToken(ctx, idToken, token)
	if err != nil {
		return nil, fmt.Errorf("couldn't extract claims from id_token (%v)", err)
	}

	if token != nil {
		newSession.IDToken = token.Extra("id_token").(string)
	}

	newSession.Email = claims.UserID // TODO Rename SessionState.Email to .UserID in the near future

	newSession.User = claims.Subject
	newSession.PreferredUsername = claims.PreferredUsername

	//Remove unnecessary bloat due to BlueGroups
	bmrgIDToken, err := removeW3idBlueGroupsInIDToken(token.Extra("id_token").(string))
	if err != nil {
		fmt.Errorf("Unable to Remove W3id Blue Groups in ID Token: %v", err)
		bmrgIDToken = token.Extra("id_token").(string)
	}
	//logger.Printf("Boomerang IDToken: %s\n", bmrgIDToken)
	newSession.IDToken = bmrgIDToken

	verifyEmail := (p.UserIDClaim == emailClaim) && !p.AllowUnverifiedEmail
	if verifyEmail && claims.Verified != nil && !*claims.Verified {
		return nil, fmt.Errorf("email in id_token (%s) isn't verified", claims.UserID)
	}

	return newSession, nil
}

// ValidateSessionState checks that the session's IDToken is still valid
func (p *OIDCIBMW3idProvider) ValidateSessionState(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	return err == nil
}

func (p *OIDCIBMW3idProvider) findClaimsFromIDToken(ctx context.Context, idToken *oidc.IDToken, token *oauth2.Token) (*OIDCClaims, error) {
	claims := &OIDCClaims{}
	// Extract default claims.
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("failed to parse default id_token claims: %v", err)
	}
	// Extract custom claims.
	if err := idToken.Claims(&claims.rawClaims); err != nil {
		return nil, fmt.Errorf("failed to parse all id_token claims: %v", err)
	}

	userID := claims.rawClaims[p.UserIDClaim]
	if userID != nil {
		claims.UserID = fmt.Sprint(userID)
	}

	// userID claim was not present or was empty in the ID Token
	if claims.UserID == "" {
		// BearerToken case, allow empty UserID
		// ProfileURL checks below won't work since we don't have an access token
		if token == nil {
			claims.UserID = claims.Subject
			return claims, nil
		}

		profileURL := p.ProfileURL.String()
		if profileURL == "" || token.AccessToken == "" {
			return nil, fmt.Errorf("id_token did not contain user ID claim (%q)", p.UserIDClaim)
		}

		// If the userinfo endpoint profileURL is defined, then there is a chance the userinfo
		// contents at the profileURL contains the email.
		// Make a query to the userinfo endpoint, and attempt to locate the email from there.
		respJSON, err := requests.New(profileURL).
			WithContext(ctx).
			WithHeaders(makeOIDCHeader(token.AccessToken)).
			Do().
			UnmarshalJSON()
		if err != nil {
			return nil, err
		}

		userID, err := respJSON.Get(p.UserIDClaim).String()
		if err != nil {
			return nil, fmt.Errorf("neither id_token nor userinfo endpoint contained user ID claim (%q)", p.UserIDClaim)
		}

		claims.UserID = userID
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
	//logger.Printf("Original Payload: %q\n", bytePayload)
	var jsonPayload map[string]interface{}
	json.Unmarshal(bytePayload, &jsonPayload)
	for k := range jsonPayload {
		if k == "blueGroups" {
			delete(jsonPayload, k)
		}
	}
	bytePayload2, err := json.Marshal(jsonPayload)
	//logger.Printf("Payload no BlueGroups: %q\n", bytePayload2)
	parts[1] = base64.RawURLEncoding.EncodeToString(bytePayload2)

	return strings.Join(parts, "."), nil
}
