package policy

import (
	"fmt"
	"net/http"
	"time"
)

func Security(contactEmail, policyURL string, now func() time.Time) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Contact: mailto:%s\n", contactEmail)
		fmt.Fprintf(w, "Policy: %s\n", policyURL)
		fmt.Fprintf(w, "Expires: %s", now().Add(180*24*time.Hour).Format(time.RFC3339))
	})
}
