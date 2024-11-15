package cookie

import (
	"awesomeProject/src/testOIDC/jwt"
	"fmt"
	"golang.org/x/oauth2"
	"net/http"
	"time"
)

// SetSecureCookieIdTokenHint 将JWT格式的id_token存入cookie，并设置访问权限
func SetSecureCookieIdTokenHint(w http.ResponseWriter, r *http.Request, oauth2Token *oauth2.Token) {
	fmt.Println("\nThis is function SetSecureCookieIdTokenHint.")

	idTokenHint := jwt.GetIdTokenHint(w, r, oauth2Token)
	if idTokenHint == "" {
		http.Error(w, "Failed to get JWT id_token.", http.StatusInternalServerError)
		return
	}

	cookieIdTokenHint := &http.Cookie{
		Name:     "id_token_hint",
		Value:    idTokenHint,
		Path:     "/",
		HttpOnly: true,                             // 禁止JS访问
		Secure:   true,                             // 仅https传输
		SameSite: http.SameSiteStrictMode,          // 防止csrf攻击
		Expires:  time.Now().Add(20 * time.Minute), // 过期时间
	}

	http.SetCookie(w, cookieIdTokenHint)
	fmt.Println("Secure cookie with JWT id_token_hint has been set.")
}

// ReadSecureCookieIdTokenHint 从cookie中读JWT id_token
func ReadSecureCookieIdTokenHint(w http.ResponseWriter, r *http.Request) {
	fmt.Println("\nThis is function ReadSecureCookieIdTokenHint.")

	cookie, err := r.Cookie("id_token_hint")
	if err != nil {
		http.Error(w, "Failed to get cookie which includes id_token_hint.", http.StatusInternalServerError)
	}

	fmt.Printf("id_token_hint from cookie: \nName: %s, \nValue: %s", cookie.Name, cookie.Value)
}

// GetIdTokenHintFromCookie 从cookie中获取JWT格式的id_token
func GetIdTokenHintFromCookie(w http.ResponseWriter, r *http.Request) string {
	fmt.Println("\nThis is function GetIdTokenHintFromCookie.")

	cookie, err := r.Cookie("id_token_hint")
	if err != nil {
		http.Error(w, "Failed to get cookie which includes id_token_hint.", http.StatusInternalServerError)
	}
	return cookie.Value
}
