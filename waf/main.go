// A detection-only WAF verdict service: OWASP Core Rule Set via Coraza. It does NOT proxy or block; it
// evaluates one request and reports whether the CRS would have flagged it, so the gateway can DETONATE the
// request in a shadow clone instead of blocking it (signatures without the false-positive tax).
//
//	POST /eval  {method, path, query, headers:{k:v}, body_b64}  ->  {anomalous, rule_id, status, msg}
//	GET  /health -> 200
package main

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"
	"os"

	coreconf "github.com/corazawaf/coraza-coreruleset/coraza/v3"
	crs "github.com/corazawaf/coraza-coreruleset/crs/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/jcchavezs/mergefs"
)

type evalReq struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Query   string            `json:"query"`
	Headers map[string]string `json:"headers"`
	BodyB64 string            `json:"body_b64"`
}

type evalResp struct {
	Anomalous bool   `json:"anomalous"`
	RuleID    int    `json:"rule_id"`
	Status    int    `json:"status"`
	Msg       string `json:"msg"`
}

func main() {
	waf, err := coraza.NewWAF(
		coraza.NewWAFConfig().
			WithRootFS(mergefs.Merge(crs.FS, coreconf.FS)).
			WithDirectivesFromFile("@coraza.conf-recommended").
			WithDirectivesFromFile("@crs-setup.conf.example").
			WithDirectivesFromFile("@owasp_crs/*.conf").
			// the recommended config ships DetectionOnly; turn the engine on so a would-be block
			// surfaces as an interruption we can report (the gateway decides what to do with it).
			WithDirectives("SecRuleEngine On"),
	)
	if err != nil {
		log.Fatalf("waf init: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	mux.HandleFunc("/eval", func(w http.ResponseWriter, r *http.Request) {
		var in evalReq
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			http.Error(w, "bad json", 400)
			return
		}
		out := evaluate(waf, in)
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
	})

	addr := os.Getenv("WAF_ADDR")
	if addr == "" {
		addr = "0.0.0.0:8080"
	}
	log.Printf("coraza waf (owasp crs) listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func evaluate(waf coraza.WAF, in evalReq) evalResp {
	tx := waf.NewTransaction()
	defer func() { tx.ProcessLogging(); _ = tx.Close() }()

	tx.ProcessConnection("127.0.0.1", 0, "127.0.0.1", 0)
	uri := in.Path
	if in.Query != "" {
		uri += "?" + in.Query
	}
	method := in.Method
	if method == "" {
		method = "GET"
	}
	tx.ProcessURI(uri, method, "HTTP/1.1")
	for k, v := range in.Headers {
		tx.AddRequestHeader(k, v)
	}
	if it := tx.ProcessRequestHeaders(); it != nil {
		return evalResp{Anomalous: true, RuleID: it.RuleID, Status: it.Status, Msg: "request headers"}
	}
	if in.BodyB64 != "" {
		if body, err := base64.StdEncoding.DecodeString(in.BodyB64); err == nil && len(body) > 0 {
			_, _, _ = tx.WriteRequestBody(body)
		}
	}
	// phase 2 runs here and covers the query ARGS too, so always process it, even for a body-less GET.
	if it, err := tx.ProcessRequestBody(); err == nil && it != nil {
		return evalResp{Anomalous: true, RuleID: it.RuleID, Status: it.Status, Msg: "request"}
	}
	return evalResp{Anomalous: false}
}
