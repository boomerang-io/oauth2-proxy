package providers

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/apis/sessions"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/logger"
	"github.com/oauth2-proxy/oauth2-proxy/v7/pkg/requests"
	"golang.org/x/oauth2"
)

// OIDCIBMidProvider represents an OIDC based Identity Provider
type OIDCIBMidProvider struct {
	*ProviderData
}

// NewOIDCIBMidProvider initiates a new OIDCIBMidProvider
func NewOIDCIBMidProvider(p *ProviderData) *OIDCIBMidProvider {
	p.ProviderName = "IBMid's OpenID Connect"
	return &OIDCIBMidProvider{ProviderData: p}
}

var _ Provider = (*OIDCIBMidProvider)(nil)

// Redeem exchanges the OAuth2 authentication token for an ID token
func (p *OIDCIBMidProvider) Redeem(ctx context.Context, redirectURL, code string) (*sessions.SessionState, error) {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return nil, err
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
	logger.Printf("Client ID: %s", p.ClientID)
	logger.Printf("Client Secret: %s", p.ClientSecret)
	logger.Printf("Token URL: %s", p.RedeemURL.String())
	logger.Printf("Redirect URL: %s", redirectURL)
	logger.Printf("Code: %s", code)

	token, err := c.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %v", err)
	}

	// Added logging
	logger.Printf("Token: %v\n", token)

	return p.createSession(ctx, token, false)
}

// EnrichSession is called after Redeem to allow providers to enrich session fields
// such as User, Email, Groups with provider specific API calls.
func (p *OIDCIBMidProvider) EnrichSession(ctx context.Context, s *sessions.SessionState) error {
	if p.ProfileURL.String() == "" {
		if s.Email == "" {
			return errors.New("id_token did not contain an email and profileURL is not defined")
		}
		return nil
	}

	// Try to get missing emails or groups from a profileURL
	if s.Email == "" || s.Groups == nil {
		err := p.enrichFromProfileURL(ctx, s)
		if err != nil {
			logger.Errorf("Warning: Profile URL request failed: %v", err)
		}
	}

	// If a mandatory email wasn't set, error at this point.
	if s.Email == "" {
		return errors.New("neither the id_token nor the profileURL set an email")
	}
	return nil
}

// enrichFromProfileURL enriches a session's Email & Groups via the JSON response of
// an OIDC profile URL
func (p *OIDCIBMidProvider) enrichFromProfileURL(ctx context.Context, s *sessions.SessionState) error {
	respJSON, err := requests.New(p.ProfileURL.String()).
		WithContext(ctx).
		WithHeaders(makeOIDCHeader(s.AccessToken)).
		Do().
		UnmarshalJSON()
	if err != nil {
		return err
	}

	email, err := respJSON.Get(p.EmailClaim).String()
	if err == nil && s.Email == "" {
		s.Email = email
	}

	if len(s.Groups) > 0 {
		return nil
	}
	for _, group := range coerceArray(respJSON, p.GroupsClaim) {
		formatted, err := formatGroup(group)
		if err != nil {
			logger.Errorf("Warning: unable to format group of type %s with error %s",
				reflect.TypeOf(group), err)
			continue
		}
		s.Groups = append(s.Groups, formatted)
	}

	return nil
}

// ValidateSession checks that the session's IDToken is still valid
func (p *OIDCIBMidProvider) ValidateSession(ctx context.Context, s *sessions.SessionState) bool {
	_, err := p.Verifier.Verify(ctx, s.IDToken)
	return err == nil
}

// RefreshSessionIfNeeded checks if the session has expired and uses the
// RefreshToken to fetch a new Access Token (and optional ID token) if required
func (p *OIDCIBMidProvider) RefreshSessionIfNeeded(ctx context.Context, s *sessions.SessionState) (bool, error) {
	// Added logging
	logger.Printf("RefreshSessionIfNeeded() - %v\n", s)

	if s == nil || (s.ExpiresOn != nil && s.ExpiresOn.After(time.Now())) || s.RefreshToken == "" {
		return false, nil
	}

	err := p.redeemRefreshToken(ctx, s)
	if err != nil {
		return false, fmt.Errorf("unable to redeem refresh token: %v", err)
	}

	logger.Printf("refreshed session: %s", s)
	return true, nil
}

// redeemRefreshToken uses a RefreshToken with the RedeemURL to refresh the
// Access Token and (probably) the ID Token.
func (p *OIDCIBMidProvider) redeemRefreshToken(ctx context.Context, s *sessions.SessionState) error {
	clientSecret, err := p.GetClientSecret()
	if err != nil {
		return err
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

	// Added logging
	fmt.Printf("redeemRefreshToken() - token: %v\n", token)

	if err != nil {
		return fmt.Errorf("failed to get token: %v", err)
	}

	newSession, err := p.createSession(ctx, token, true)
	if err != nil {
		return fmt.Errorf("unable create new session state from response: %v", err)
	}

	// It's possible that if the refresh token isn't in the token response the
	// session will not contain an id token.
	// If it doesn't it's probably better to retain the old one
	// fmt.Println("redeemRefreshToken() - newSession.IDToken:", newSession.IDToken)
	if newSession.IDToken != "" {
		// fmt.Println("redeemRefreshToken() - s.IDToken (newSession.IDToken != \"\"):", s.IDToken)
		s.IDToken = newSession.IDToken
		s.Email = newSession.Email
		s.User = newSession.User
		s.Groups = newSession.Groups
		s.PreferredUsername = newSession.PreferredUsername
	}

	s.AccessToken = newSession.AccessToken
	s.RefreshToken = newSession.RefreshToken
	s.CreatedAt = newSession.CreatedAt
	s.ExpiresOn = newSession.ExpiresOn

	// fmt.Println("redeemRefreshToken() - s.IDToken:", s.IDToken)
	// fmt.Println("redeemRefreshToken() - s.Email:", s.Email)
	// fmt.Println("redeemRefreshToken() - s.User:", s.User)
	// fmt.Println("redeemRefreshToken() - s.Groups:", s.Groups)
	// fmt.Println("redeemRefreshToken() - s.PreferredUsername:", s.PreferredUsername)
	// fmt.Println("redeemRefreshToken() - s.AccessToken:", s.AccessToken)
	// fmt.Println("redeemRefreshToken() - s.RefreshToken:", s.RefreshToken)
	// fmt.Println("redeemRefreshToken() - s.CreatedAt:", s.CreatedAt)
	// fmt.Println("redeemRefreshToken() - s.ExpiresOn:", s.ExpiresOn)

	return nil
}

// CreateSessionFromToken converts Bearer IDTokens into sessions
func (p *OIDCIBMidProvider) CreateSessionFromToken(ctx context.Context, token string) (*sessions.SessionState, error) {
	// Added logging
	logger.Printf("Token: %v\n", token)

	idToken, err := p.Verifier.Verify(ctx, token)
	if err != nil {
		return nil, err
	}

	// Added logging
	logger.Printf("Token: %v\n", idToken)

	ss, err := p.buildSessionFromClaims(idToken)
	if err != nil {
		return nil, err
	}

	// Allow empty Email in Bearer case since we can't hit the ProfileURL
	if ss.Email == "" {
		ss.Email = ss.User
	}

	ss.AccessToken = token
	ss.IDToken = token
	ss.RefreshToken = ""
	ss.ExpiresOn = &idToken.Expiry

	return ss, nil
}

// createSession takes an oauth2.Token and creates a SessionState from it.
// It alters behavior if called from Redeem vs Refresh
func (p *OIDCIBMidProvider) createSession(ctx context.Context, token *oauth2.Token, refresh bool) (*sessions.SessionState, error) {
	idToken, err := p.verifyIDToken(ctx, token)
	if err != nil {
		switch err {
		case ErrMissingIDToken:
			// IDToken is mandatory in Redeem but optional in Refresh
			if !refresh {
				return nil, errors.New("token response did not contain an id_token")
			}
		default:
			return nil, fmt.Errorf("could not verify id_token: %v", err)
		}
	}

	ss, err := p.buildSessionFromClaims(idToken)
	if err != nil {
		return nil, err
	}

	ss.AccessToken = token.AccessToken
	ss.RefreshToken = token.RefreshToken

	//Remove unnecessary bloat due to BlueGroups
	bmrgIDToken, err := removeIBMidBlueGroupsInIDToken(token.Extra("id_token").(string))
	if err != nil {
		logger.Errorf("Unable to Remove IBMid Blue Groups in ID Token: %v", err)
		bmrgIDToken = token.Extra("id_token").(string)
	}
	logger.Printf("Boomerang IDToken: %s\n", bmrgIDToken)
	ss.IDToken = bmrgIDToken

	// ss.IDToken = getIDToken(token)

	created := time.Now()
	ss.CreatedAt = &created
	ss.ExpiresOn = &token.Expiry

	return ss, nil
}

func removeIBMidBlueGroupsInIDToken(p string) (string, error) {
	parts := strings.Split(p, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("oidcibm removeIBMidBlueGroupsInIDToken() - malformed jwt, expected 3 parts got %d", len(parts))
	}
	bytePayload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("oidcibm removeIBMidBlueGroupsInIDToken() - malformed jwt payload: %v", err)
	}
	//fmt.Printf("Original Payload: %q\n", bytePayload)
	var jsonPayload map[string]interface{}
	json.Unmarshal(bytePayload, &jsonPayload)
	for k := range jsonPayload {
		if k == "blueGroups" {
			delete(jsonPayload, k)
		} else if k == "ext" {
			//bluegroups are part of 'ext' block (case of IBMid federated auth to w3id)
			delete(jsonPayload, k)
			//add the first, last name and emailAddress for the bmrg to take them, just like in w3id structure
			//jsonPayload["firstName"] = jsonPayload["given_name"]
			//jsonPayload["lastName"] = jsonPayload["family_name"]
			//jsonPayload["emailAddress"] = jsonPayload["email"]
		}

	}
	bytePayload2, err := json.Marshal(jsonPayload)
	if err != nil {
		logger.Errorln(err)
	}
	//fmt.Printf("Payload no BlueGroups: %q\n", bytePayload2)
	parts[1] = base64.RawURLEncoding.EncodeToString(bytePayload2)

	return strings.Join(parts, "."), nil
}
