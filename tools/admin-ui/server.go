package main

import (
	"net/http"
)

type server struct {
	cfgDir string
	mux    *http.ServeMux
	bro    *brokerStore
	pub    *publishHandler
}

func newServer(cfgDir string, dep *deployConfig) *server {
	s := &server{
		cfgDir: cfgDir,
		mux:    http.NewServeMux(),
		bro:    newBrokerStore(cfgDir),
		pub:    &publishHandler{cfgDir: cfgDir, cfg: dep},
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
	s.mux.HandleFunc("POST /api/publish", s.pub.handle)

	s.mux.Handle("/", http.FileServer(http.FS(webRoot())))
}
