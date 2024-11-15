package jwt

import (
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"net/http"
)

// GetOauth2Token 根据回调url中的Code字段和上下文获取oauth2Token
func GetOauth2Token(w http.ResponseWriter, r *http.Request, config *oauth2.Config) *oauth2.Token {
	fmt.Println("\nThis is function: GetOauth2Token")

	// 从授权服务器的回调url中获取到授权码(Code)
	code := r.URL.Query().Get("code")
	fmt.Printf("code: %s\n", code)
	if code == "" {
		http.Error(w, "Missing code parameter", http.StatusBadRequest)
		return nil
	}

	ctx := context.Background()
	// 将授权码转换为oauth2的token
	oauth2Token, err := config.Exchange(ctx, code)
	fmt.Printf("oauth2Token: %+v\n", oauth2Token)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}

	return oauth2Token
}

// GetIdTokenHint 获取JWT格式的id_token
func GetIdTokenHint(w http.ResponseWriter, _ *http.Request, oauth2Token *oauth2.Token) string {
	fmt.Println("\nThis is function: GetIdTokenHint")
	idTokenHint, ok := oauth2Token.Extra("id_token").(string)
	fmt.Printf("rawIdToken: %+v\n", idTokenHint)
	if !ok {
		http.Error(w, "No id_token field in oauth2 token.", http.StatusInternalServerError)
		return ""
	}

	return idTokenHint
}

// VerifyAndGetIdToken 验证id_token并解析得到id_token中包含的数据
func VerifyAndGetIdToken(w http.ResponseWriter, _ *http.Request,
	idTokenVerifier *oidc.IDTokenVerifier, idTokenHint string) *oidc.IDToken {
	fmt.Println("\nThis is function: VerifyAndGetIdToken")

	ctx := context.Background()

	idToken, err := idTokenVerifier.Verify(ctx, idTokenHint)
	fmt.Printf("idToken: %+v\n", idToken)
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
		return nil
	}

	return idToken
}
