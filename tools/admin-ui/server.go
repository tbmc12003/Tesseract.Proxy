package main

import (
	"net/http"
)

type server struct {
	cfgDir string
	dep    *deployConfig
	mux    *http.ServeMux
	bro    *brokerStore
	pub    *publishHandler
	dif    *diffHandler
	aud    *auditHandler
}

func newServer(cfgDir string, dep *deployConfig) *server {
	s := &server{
		cfgDir: cfgDir,
		dep:    dep,
		mux:    http.NewServeMux(),
		bro:    newBrokerStore(cfgDir),
		pub:    &publishHandler{cfgDir: cfgDir, cfg: dep},
		dif:    &diffHandler{cfgDir: cfgDir, cfg: dep},
	}
	s.aud = &auditHandler{get: s.proxyClient}
	s.routes()
	return s
}

// proxyClient builds a fresh mTLS client to the proxy on each call. We
// re-read cert/key/CA every time so the operator can rotate material via
// gen-mtls.sh without restarting admin-ui. Returns 424 to the caller (via
// the err) when deployConfig.mtlsMissing reports unset/unreadable fields.
func (s *server) proxyClient() (*proxyClient, error) {
	return newProxyClient(s.dep)
}

// proxyCheck reports whether admin-ui can build the mTLS client and
// reveals the loaded cert's subject/issuer/expiry. Used both by the
// operator (curl /api/proxy/check) and the UI badge in later phases.
// Does not actually call the proxy — that's /admin/healthz once R7.6 wires.
func (s *server) proxyCheck(w http.ResponseWriter, r *http.Request) {
	pc, err := s.proxyClient()
	if err != nil {
		writeErr(w, http.StatusFailedDependency, err.Error())
		return
	}
	info, err := pc.certInfo()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, info)
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
	s.mux.HandleFunc("GET /api/diff", s.dif.handle)
	s.mux.HandleFunc("GET /api/proxy/check", s.proxyCheck)
	s.mux.HandleFunc("GET /api/audit/tail", s.aud.tail)
	s.mux.HandleFunc("GET /api/audit/range", s.aud.rangeHist)
	s.mux.HandleFunc("GET /api/log/stat", s.aud.logStat)
	s.mux.HandleFunc("POST /api/log/rotate", s.aud.logRotate)
	s.mux.HandleFunc("GET /api/proxy/health", s.aud.health)

	s.mux.Handle("/", http.FileServer(http.FS(webRoot())))
}
