package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

var brokerNameRe = regexp.MustCompile(`^[a-z][a-z0-9_]{1,31}$`)

type brokerStore struct {
	cfgDir string

	mu     sync.Mutex
	schema *jsonschema.Schema
}

func newBrokerStore(cfgDir string) *brokerStore {
	return &brokerStore{cfgDir: cfgDir}
}

func (b *brokerStore) brokersDir() string { return filepath.Join(b.cfgDir, "brokers") }
func (b *brokerStore) schemaPath() string {
	return filepath.Join(b.cfgDir, "schemas", "bundle.schema.json")
}

func (b *brokerStore) loadSchema() (*jsonschema.Schema, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.schema != nil {
		return b.schema, nil
	}
	f, err := os.Open(b.schemaPath())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	doc, err := jsonschema.UnmarshalJSON(f)
	if err != nil {
		return nil, err
	}
	c := jsonschema.NewCompiler()
	if err := c.AddResource("bundle.schema.json", doc); err != nil {
		return nil, err
	}
	sch, err := c.Compile("bundle.schema.json")
	if err != nil {
		return nil, err
	}
	b.schema = sch
	return sch, nil
}

func (b *brokerStore) list(w http.ResponseWriter, r *http.Request) {
	entries, err := os.ReadDir(b.brokersDir())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	type item struct {
		ID          string `json:"id"`
		DisplayName string `json:"display_name"`
		Enabled     bool   `json:"enabled"`
	}
	out := make([]item, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".yaml")
		obj, err := b.read(name)
		if err != nil {
			continue
		}
		dn, _ := obj["display_name"].(string)
		en, _ := obj["enabled"].(bool)
		id, _ := obj["id"].(string)
		if id == "" {
			id = name
		}
		out = append(out, item{ID: id, DisplayName: dn, Enabled: en})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	writeJSON(w, http.StatusOK, out)
}

func (b *brokerStore) get(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !brokerNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid broker name")
		return
	}
	obj, err := b.read(name)
	if err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "broker not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (b *brokerStore) put(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !brokerNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid broker name")
		return
	}
	if _, err := os.Stat(b.path(name)); err != nil {
		writeErr(w, http.StatusNotFound, "broker not found")
		return
	}
	b.write(w, r, name, false)
}

func (b *brokerStore) create(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	obj, err := decodeJSON(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	id, _ := obj["id"].(string)
	if !brokerNameRe.MatchString(id) {
		writeErr(w, http.StatusBadRequest, "id must match ^[a-z][a-z0-9_]{1,31}$")
		return
	}
	if _, err := os.Stat(b.path(id)); err == nil {
		writeErr(w, http.StatusConflict, fmt.Sprintf("broker %q already exists", id))
		return
	}
	if err := b.validate(obj); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := b.persist(id, obj); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, obj)
}

func (b *brokerStore) delete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if !brokerNameRe.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "invalid broker name")
		return
	}
	if err := os.Remove(b.path(name)); err != nil {
		if os.IsNotExist(err) {
			writeErr(w, http.StatusNotFound, "broker not found")
			return
		}
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// write handles PUT — body must validate and id in body must match URL name.
func (b *brokerStore) write(w http.ResponseWriter, r *http.Request, name string, _ bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	obj, err := decodeJSON(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if id, _ := obj["id"].(string); id != name {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("id %q in body does not match URL %q", id, name))
		return
	}
	if err := b.validate(obj); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := b.persist(name, obj); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, obj)
}

func (b *brokerStore) validate(obj map[string]any) error {
	sch, err := b.loadSchema()
	if err != nil {
		return fmt.Errorf("load schema: %w", err)
	}
	if err := sch.Validate(obj); err != nil {
		return fmt.Errorf("schema validation failed: %w", err)
	}
	return nil
}

// persist writes YAML atomically (tmp + rename).
func (b *brokerStore) persist(name string, obj map[string]any) error {
	dst := b.path(name)
	tmp := dst + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := yaml.NewEncoder(f)
	enc.SetIndent(2)
	if err := enc.Encode(obj); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := enc.Close(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, dst)
}

func (b *brokerStore) path(name string) string {
	return filepath.Join(b.brokersDir(), name+".yaml")
}

// read returns the broker YAML decoded into a JSON-compatible map (string keys).
func (b *brokerStore) read(name string) (map[string]any, error) {
	raw, err := os.ReadFile(b.path(name))
	if err != nil {
		return nil, err
	}
	var y any
	if err := yaml.Unmarshal(raw, &y); err != nil {
		return nil, err
	}
	conv, ok := normalizeYAML(y).(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: top-level is not a mapping", name)
	}
	return conv, nil
}

// normalizeYAML converts map[interface{}]interface{} (legacy yaml.v2 shape)
// and map[string]interface{} branches into JSON-compatible maps. yaml.v3
// already uses string keys for mapping nodes, so this mostly just walks
// arrays + maps, but it keeps the contract explicit.
func normalizeYAML(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = normalizeYAML(vv)
		}
		return x
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[fmt.Sprint(k)] = normalizeYAML(vv)
		}
		return out
	case []any:
		for i, vv := range x {
			x[i] = normalizeYAML(vv)
		}
		return x
	default:
		return v
	}
}

func decodeJSON(body []byte) (map[string]any, error) {
	var obj map[string]any
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.UseNumber()
	if err := dec.Decode(&obj); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return jsonNumbersToFloats(obj).(map[string]any), nil
}

// jsonNumbersToFloats converts json.Number to int64 if integral, else float64,
// so the schema validator sees the right types (jsonschema/v6 expects float64
// or int, not json.Number).
func jsonNumbersToFloats(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, vv := range x {
			x[k] = jsonNumbersToFloats(vv)
		}
		return x
	case []any:
		for i, vv := range x {
			x[i] = jsonNumbersToFloats(vv)
		}
		return x
	case json.Number:
		if i, err := x.Int64(); err == nil {
			return i
		}
		if f, err := x.Float64(); err == nil {
			return f
		}
		return x.String()
	default:
		return v
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
