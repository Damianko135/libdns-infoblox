package infoblox

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// fakeWAPI is a minimal in-memory stand-in for the Infoblox NIOS WAPI, enough
// to exercise Provider end to end through the real infoblox-go-client request
// path (URL building, forceProxy fallback, [] => NotFoundError, ref round-trips).
//
// It is NOT a spec-accurate emulator: it models only what this provider sends
// (record:{txt,a,aaaa,cname,mx,srv} search/create/update/delete, and logout).
type fakeWAPI struct {
	ver string

	mu      sync.Mutex
	seq     int
	objects map[string]map[string]any // ref -> stored object (with "_ref")

	// failFirst maps "<METHOD> <objtype>" to a countdown of HTTP hits that
	// should be answered with failStatus before normal service resumes.
	failFirst  map[string]int
	failStatus int

	// hits records every served request line, for assertions on retry counts.
	hits []string
}

func newFakeWAPI() *fakeWAPI {
	return &fakeWAPI{
		ver:        "2.12",
		objects:    map[string]map[string]any{},
		failFirst:  map[string]int{},
		failStatus: http.StatusServiceUnavailable,
	}
}

// start returns a Provider wired to a fresh TLS test server backed by f.
func (f *fakeWAPI) start(t *testing.T) *Provider {
	t.Helper()
	srv := httptest.NewTLSServer(f)
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	return &Provider{
		Host:     u.Hostname(),
		Port:     u.Port(),
		Version:  f.ver,
		Username: "tester",
		Password: "secret",
		Insecure: true,
	}
}

// seed inserts an object of objtype directly into the store and returns its ref.
// Fields are round-tripped through JSON so a seeded object has the same shape
// (numbers as float64, etc.) as one created via a POST body.
func (f *fakeWAPI) seed(objtype string, fields map[string]any) string {
	b, _ := json.Marshal(fields)
	norm := map[string]any{}
	_ = json.Unmarshal(b, &norm)

	f.mu.Lock()
	defer f.mu.Unlock()
	return f.putLocked(objtype, norm)
}

func (f *fakeWAPI) putLocked(objtype string, fields map[string]any) string {
	f.seq++
	ref := fmt.Sprintf("%s/%s%d:x/%s", objtype, "id", f.seq, strOr(fields["view"], "default"))
	obj := map[string]any{}
	for k, v := range fields {
		obj[k] = v
	}
	obj["_ref"] = ref
	f.objects[ref] = obj
	return ref
}

func (f *fakeWAPI) count(objtype string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for ref := range f.objects {
		if strings.HasPrefix(ref, objtype+"/") {
			n++
		}
	}
	return n
}

func (f *fakeWAPI) hitCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.hits)
}

func (f *fakeWAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	prefix := "/wapi/v" + f.ver + "/"
	tail := strings.TrimPrefix(r.URL.Path, prefix)
	f.hits = append(f.hits, r.Method+" "+tail)

	if tail == "logout" {
		writeJSON(w, http.StatusOK, "")
		return
	}

	objtype := tail
	ref := ""
	if i := strings.IndexByte(tail, '/'); i >= 0 {
		objtype, ref = tail[:i], tail
	}

	if n := f.failFirst[r.Method+" "+objtype]; n > 0 {
		f.failFirst[r.Method+" "+objtype] = n - 1
		w.WriteHeader(f.failStatus)
		_, _ = io.WriteString(w, http.StatusText(f.failStatus))
		return
	}

	switch r.Method {
	case http.MethodGet:
		if ref != "" {
			obj, ok := f.objects[ref]
			if !ok {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			writeJSON(w, http.StatusOK, obj)
			return
		}
		writeJSON(w, http.StatusOK, f.searchLocked(objtype, r.URL.Query()))

	case http.MethodPost:
		body := decodeBody(r)
		if f.hasDuplicateLocked(objtype, body) {
			// NIOS rejects a create that exactly duplicates an existing record.
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "The record already exists.")
			return
		}
		newRef := f.putLocked(objtype, body)
		writeJSON(w, http.StatusCreated, newRef)

	case http.MethodPut:
		obj, ok := f.objects[ref]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		for k, v := range decodeBody(r) {
			obj[k] = v
		}
		obj["_ref"] = ref
		writeJSON(w, http.StatusOK, ref)

	case http.MethodDelete:
		if _, ok := f.objects[ref]; !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		delete(f.objects, ref)
		writeJSON(w, http.StatusOK, ref)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// hasDuplicateLocked reports whether a stored object of objtype already has the
// same fields as body (ignoring the assigned _ref), i.e. an exact-duplicate
// create that NIOS would reject.
func (f *fakeWAPI) hasDuplicateLocked(objtype string, body map[string]any) bool {
	for ref, obj := range f.objects {
		if !strings.HasPrefix(ref, objtype+"/") {
			continue
		}
		stripped := map[string]any{}
		for k, v := range obj {
			if k != "_ref" {
				stripped[k] = v
			}
		}
		if reflect.DeepEqual(stripped, body) {
			return true
		}
	}
	return false
}

// searchLocked filters stored objects of objtype by the name/zone/view query
// params, mimicking how NIOS resolves a record's zone from its name.
func (f *fakeWAPI) searchLocked(objtype string, q url.Values) []map[string]any {
	var out []map[string]any
	for ref, obj := range f.objects {
		if !strings.HasPrefix(ref, objtype+"/") {
			continue
		}
		name, _ := obj["name"].(string)
		if v := q.Get("name"); v != "" && name != v {
			continue
		}
		if v := q.Get("zone"); v != "" && name != v && !strings.HasSuffix(name, "."+v) {
			continue
		}
		if v := q.Get("view"); v != "" && strOr(obj["view"], "default") != v {
			continue
		}
		out = append(out, obj)
	}
	return out
}

func decodeBody(r *http.Request) map[string]any {
	b, _ := io.ReadAll(r.Body)
	m := map[string]any{}
	_ = json.Unmarshal(b, &m)
	return m
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func strOr(v any, def string) string {
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return def
}
