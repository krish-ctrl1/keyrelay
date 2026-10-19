// Command mock-upstream is a demo "external API" that requires a real API key.
// It plays the role of a third-party provider: it knows its own keys, but the
// agents calling through KeyRelay never do. It never echoes the key.
package main

import (
	"crypto/subtle"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := envOr("LISTEN", ":9000")
	mux := http.NewServeMux()
	mux.Handle("/weather/", requireBearer(os.Getenv("WEATHER_API_KEY"), "weather"))
	mux.Handle("/payments/", requireBearer(os.Getenv("PAYMENTS_API_KEY"), "payments"))
	log.Printf("mock-upstream listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func requireBearer(key, api string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		ok := key != "" && subtle.ConstantTimeCompare([]byte(got), []byte("Bearer "+key)) == 1
		resp := map[string]any{
			"api":           api,
			"authenticated": ok,
			"host":          r.Host,
			"path":          r.URL.Path,
			"query":         r.URL.RawQuery,
			// Proves the agent's placeholder never reached the provider.
			"saw_placeholder": strings.Contains(got, "KEYRELAY_MANAGED"),
		}
		w.Header().Set("Content-Type", "application/json")
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
		} else if api == "weather" {
			resp["forecast"] = map[string]any{"city": r.URL.Query().Get("city"), "temp_c": 18, "conditions": "partly cloudy"}
		} else {
			resp["charge"] = map[string]any{"id": "ch_demo_001", "status": "succeeded"}
		}
		log.Printf("%s %s authenticated=%v", r.Method, r.URL.Path, ok)
		_ = json.NewEncoder(w).Encode(resp)
	})
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
