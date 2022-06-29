// Command oauth is a tool for getting OAuth tokens.
//
// Original author: Allen Li <ayatane@google.com>
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"

	"golang.org/x/oauth2"
)

func main() {
	c := oauth2.Config{
		Scopes: []string{"https://mail.google.com/"},
	}
	flag.StringVar(&c.ClientID, "client-id", "", "Client ID")
	flag.StringVar(&c.ClientSecret, "client-secret", "", "Client secret")
	flag.StringVar(&c.Endpoint.AuthURL, "auth-url", "https://accounts.google.com/o/oauth2/v2/auth", "Auth URL")
	flag.StringVar(&c.Endpoint.TokenURL, "token-url", "https://oauth2.googleapis.com/token", "Token URL")
	flag.Var(Comma{Var: &c.Scopes}, "scope", "Scopes")
	flag.Parse()

	verifier := genVerifier()
	state := "state"
	http.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		log.Printf("Got %q", req.URL.String())
		v := req.URL.Query()
		if s := v.Get("state"); s != state {
			log.Fatalf("Got bad state %q", s)
		}
		if e := v.Get("error"); e != "" {
			log.Fatalf("Got error %q", e)
		}
		code := v.Get("code")
		if code == "" {
			log.Fatal("missing code")
		}
		ctx := context.Background()
		tok, err := c.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("\nAccessToken: %s\n", tok.AccessToken)
		fmt.Printf("TokenType: %s\n", tok.TokenType)
		fmt.Printf("RefreshToken: %s\n", tok.RefreshToken)
		fmt.Printf("Expiry: %s\n", tok.Expiry)
		os.Exit(0)
	})
	c.RedirectURL = "http://127.0.0.1:8181"
	url := c.AuthCodeURL(state, oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("code_challenge", verifier),
		oauth2.SetAuthURLParam("code_challenge_method", "plain"))
	fmt.Printf("Visit the URL for the auth dialog: %v\n", url)
	http.ListenAndServe("127.0.0.1:8181", nil)
}

func genVerifier() string {
	const verifierChars = `abcdefghijklmnopqrstuvwxyz` +
		`ABCDEFGHIJKLMNOPQRSTUVWXYZ` +
		`1234567890` +
		`-._~`
	count := big.NewInt(int64(len(verifierChars)))
	getRand := func() int {
		n, err := rand.Int(rand.Reader, count)
		if err != nil {
			// Only if max <= 0, impossible.
			panic(err)
		}
		return int(n.Int64())
	}
	var b strings.Builder
	for i := 0; i < 80; i++ {
		b.WriteByte(verifierChars[int(getRand())])
	}
	return b.String()
}

// A Comma is a flag.Var that sets string slices with a comma separated input.
type Comma struct {
	Var *[]string
}

func (c Comma) Set(s string) error {
	*c.Var = strings.Split(s, ",")
	return nil
}

func (c Comma) String() string {
	if c.Var == nil {
		return ""
	}
	return strings.Join(*c.Var, ",")
}
