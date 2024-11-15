package main

import (
	"awesomeProject/src/testOIDC/cookie"
	"awesomeProject/src/testOIDC/jwt"
	"context"
	"fmt"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"log"
	"net/http"
)

// 全局变量定义
var (
	ctx       = context.Background() // 上下文
	cliId     string                 // 客户端Id (APPID)
	cliSecret string                 // 客户端Secret (APP_Secret)

	redirectURL     = "https://localhost:8080/callback" // 登录重定向URL
	provider        *oidc.Provider                      // oidc 提供者
	config          *oauth2.Config                      // oauth2的配置
	idTokenVerifier *oidc.IDTokenVerifier               // oidc id_token的校验器
)

func init() {
	//设置Client_Id和Client_Secret
	cliId = "6729be8c79d971c128a71243"
	cliSecret = "6d49695719851cddacd8d402dff27a29"

	var err error //如果不首先定义error
	//而在下面这一行使用 := 操作符，provider则会变成局部变量。后续使用全局变量provider时会报空指针错误。
	provider, err = oidc.NewProvider(ctx, "https://rdoidctest.authing.cn/oidc")
	if err != nil {
		log.Fatalf("Faild to create OIDC provider: %v", err)
	}

	idTokenVerifier = provider.Verifier(&oidc.Config{ClientID: cliId})

	config = &oauth2.Config{
		ClientID:     cliId,
		ClientSecret: cliSecret,
		RedirectURL:  redirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "phone", "email"},
	}
}

func main() {
	// 使用handle函数映射到路由
	http.HandleFunc("/", HandleMain)
	http.HandleFunc("/login", HandleLogin)
	http.HandleFunc("/callback", HandleLoginCallback)
	http.HandleFunc("/logged-in", HandleLoggedIn)
	http.HandleFunc("/logout", HandleLogout)
	http.HandleFunc("/logged-out", HandleLogoutCallback)

	fmt.Println("Server started at https://localhost:8080")
	// 设置tls以启动https服务
	log.Fatal(http.ListenAndServeTLS(":8080",
		"src/testOIDC/tls/localhost.pem", "src/testOIDC/tls/localhost-key.pem", nil))
}

// HandleMain localhost:8080 的 handler
func HandleMain(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	_, err := fmt.Fprintf(w, "Hello World, Please <a href='/login'>login</a>\n")
	if err != nil {
		return
	}
}

// HandleLogin localhost:8080/login 的 handler
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	// 生成带有用户信息的oidc请求url
	url := config.AuthCodeURL("state", oauth2.AccessTypeOffline)

	// 重定向到验证url，http状态码302
	http.Redirect(w, r, url, http.StatusFound)
}

// HandleLoginCallback 从服务提供者获取的登录信息回调处理handler
func HandleLoginCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	//ctx = r.Context()

	// 获取oauth2的token
	oauth2Token := jwt.GetOauth2Token(w, r, config)
	if oauth2Token == nil {
		http.Error(w, "Failed to get oauth2Token.", http.StatusInternalServerError)
		return
	}

	// 从oauth2token中的raw字段获取JWT格式的id_token (Extract)
	idTokenHint := jwt.GetIdTokenHint(w, r, oauth2Token)
	if idTokenHint == "" {
		http.Error(w, "Failed to get JWT id_token.", http.StatusInternalServerError)
		return
	}

	cookie.SetSecureCookieIdTokenHint(w, r, oauth2Token)

	//if domain, ok := profile["domain"].(string); !ok || domain != r.Host {
	//	http.Error(w, "The domain does not match.", http.StatusUnauthorized)
	//	return
	//}
	http.Redirect(w, r, "https://localhost:8080/logged-in", 302)

}

// HandleLoggedIn logged-in重定向页面处理函数
func HandleLoggedIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")

	cookie.ReadSecureCookieIdTokenHint(w, r)

	idToken := jwt.VerifyAndGetIdToken(w, r, idTokenVerifier, cookie.GetIdTokenHintFromCookie(w, r))

	var phone map[string]interface{}
	// 根据scope获取claim
	if err := idToken.Claims(&phone); err != nil {
		http.Error(w, "Failed to parse ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	idTokenHint := cookie.GetIdTokenHintFromCookie(w, r)

	var err error
	_, err = fmt.Fprintf(w, "You are logged in as %s, <a href='/logout?id_token=%s'>Logout</a>",
		phone["phone_number"], idTokenHint)
	if err != nil {
		return
	}

}

// HandleLogout 点击logout后的handler
func HandleLogout(w http.ResponseWriter, r *http.Request) {

	idTokenHint := r.URL.Query().Get("id_token")
	fmt.Printf("\nidTokenHint from HandleLogout: \n%s\n", idTokenHint)

	endSessionEndpoint := "https://rdoidctest.authing.cn/oidc/session/end"
	//验证
	_, err := idTokenVerifier.Verify(ctx, r.URL.Query().Get("id_token"))
	if err != nil {
		http.Error(w, "Failed to verify ID Token: "+err.Error(), http.StatusInternalServerError)
	}

	logoutRedirectURL := "https://localhost:8080/logged-out"

	logoutURL := fmt.Sprintf("%s?id_token_hint=%s&post_logout_redirect_uri=%s", endSessionEndpoint, idTokenHint, logoutRedirectURL)

	http.Redirect(w, r, logoutURL, http.StatusFound)
}

// HandleLogoutCallback Logout回调处理函数
func HandleLogoutCallback(w http.ResponseWriter, _ *http.Request) {

	fmt.Println("\nThis is HandleLogoutCallback()")

	w.Header().Set("Content-Type", "text/html")
	_, err := fmt.Fprint(w, "You have successfully logged out. <a href='/'>Go to Home</a>\n")
	if err != nil {
		return
	}
}
