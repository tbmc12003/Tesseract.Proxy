package main

import (
	"net/http"
)

type server struct {
	cfgDir string
	mux    *http.ServeMux
	bro    *brokerStore
}

func newServer(cfgDir string) *server {
	s := &server{
		cfgDir: cfgDir,
		mux:    http.NewServeMux(),
		bro:    newBrokerStore(cfgDir),
	}
	s.routes()
	return s
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *server) routes() {
	s.mux.HandleFunc("GET /api/brokers", s.bro.list)
	s.mux.HandleFunc("GET /api/brokers/{name}", s.bro.get)
	s.mux.HandleFunc("PUT /api/brokers/{name}", s.bro.put)
	s.mux.HandleFunc("POST /api/brokers", s.bro.create)
	s.mux.HandleFunc("DELETE /api/brokers/{name}", s.bro.delete)

	s.mux.Handle("/", http.FileServer(http.FS(webRoot())))
}
