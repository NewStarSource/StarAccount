package account

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProductionTransportBoundary(t *testing.T) {
	app := &App{config: Config{Mode: "production", Origin: "https://app.example.test", TrustedProxies: []string{"127.0.0.1/32"}}}
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.RemoteAddr != "198.51.100.8:0" || r.URL.Scheme != "https" || r.Header.Get("Forwarded") != "" || r.Header.Get("X-Forwarded-Host") != "" {
			t.Errorf("unchecked forwarding metadata: %v", r)
		}
		w.WriteHeader(204)
	})
	for _, tc := range []struct {
		name, peer, proto, client string
		want                      int
	}{
		{"trusted", "127.0.0.1:1234", "https", "198.51.100.8", 204},
		{"untrusted", "198.51.100.1:1234", "https", "198.51.100.8", 400},
		{"plaintext", "127.0.0.1:1234", "http", "198.51.100.8", 400},
		{"missing-client", "127.0.0.1:1234", "https", "", 400},
		{"forged-chain", "127.0.0.1:1234", "https", "198.51.100.8, 198.51.100.9", 400},
		{"invalid-client", "127.0.0.1:1234", "https", "bad", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "http://app.example.test/", nil)
			r.RemoteAddr = tc.peer
			r.Header.Set("X-Forwarded-Proto", tc.proto)
			r.Header.Set("X-Forwarded-For", tc.client)
			r.Header.Set("Forwarded", "host=evil.test")
			r.Header.Set("X-Forwarded-Host", "evil.test")
			w := httptest.NewRecorder()
			app.transport(next).ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d", w.Code)
			}
		})
	}
}
func TestProductionConfigOriginBoundary(t *testing.T) {
	if err := validateTransport("production", "127.0.0.1:4200", "https://app.example.test", []string{"127.0.0.1/32"}); err != nil {
		t.Fatal(err)
	}
	for _, origin := range []string{"http://app.example.test", "https://user@app.example.test", "https://app.example.test/", "https://127.0.0.1", "https://app.example.test?"} {
		if validateTransport("production", "127.0.0.1:4200", origin, []string{"127.0.0.1/32"}) == nil {
			t.Fatal("unsafe origin", origin)
		}
	}
	for _, proxies := range [][]string{nil, {"0.0.0.0/0"}, {"invalid"}} {
		if validateTransport("production", "127.0.0.1:4200", "https://app.example.test", proxies) == nil {
			t.Fatal("unsafe proxy", proxies)
		}
	}
}
