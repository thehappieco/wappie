package main

import (
	"net/http"

	"whatserver2/internal/webui"
)

// unrouted hands every request a route claims to the mux, and answers the
// rest: the web client, when there is one, for whatever the mux would 404
// (its pages, its files, and the API's JSON 404 under the API's prefixes);
// without one, the JSON 404 alone, since a headless server is all API.
//
// Not a catch-all pattern on the mux. A pattern that matches every method
// also takes a route asked with a method it does not take: a write to a
// read-only REST route, or a GET of the sign-in, answered the console
// document or the client's 405, never the router's 405 with the route's
// Allow header (docs/rest-api.md). Here the mux keeps its own 405s and its
// redirects to the cleaned path, and only its 404 is replaced.
func unrouted(mux *http.ServeMux, web *webui.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// No pattern is the mux's own answer: a 404, a 405 for a path a route
		// of other methods claims, or a redirect to the cleaned path. None of
		// them has an effect, so it can be asked first and its status read.
		if _, pattern := mux.Handler(r); pattern == "" {
			probe := muxStatus{header: http.Header{}}
			mux.ServeHTTP(&probe, r)
			if probe.status == http.StatusNotFound {
				if web != nil {
					web.ServeHTTP(w, r)
				} else {
					webui.NoSuchRoute(w)
				}
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}

// muxStatus keeps the status of the mux's own answer and drops the rest.
type muxStatus struct {
	header http.Header
	status int
}

func (s *muxStatus) Header() http.Header { return s.header }

func (s *muxStatus) WriteHeader(status int) {
	if s.status == 0 {
		s.status = status
	}
}

func (s *muxStatus) Write(b []byte) (int, error) {
	s.WriteHeader(http.StatusOK)
	return len(b), nil
}
