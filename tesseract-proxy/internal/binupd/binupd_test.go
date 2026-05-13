package binupd_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/equinomics/tesseract-proxy/internal/binupd"
)

type kit struct {
	dir       string
	pubkey    string
	current   string
	previous  string
	staged    string
	priv      ed25519.PrivateKey
	otherPriv ed25519.PrivateKey
}

func newKit(t *testing.T) *kit {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pubkeyPath := filepath.Join(dir, "pubkey.pem")
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pubkeyPath,
		pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &kit{
		dir:       dir,
		pubkey:    pubkeyPath,
		current:   filepath.Join(dir, "proxy"),
		previous:  filepath.Join(dir, "proxy.previous"),
		staged:    filepath.Join(dir, "proxy.staged"),
		priv:      priv,
		otherPriv: otherPriv,
	}
}

func (k *kit) receiver(t *testing.T) *binupd.Receiver {
	t.Helper()
	r, err := binupd.New(binupd.Options{
		PubkeyPath: k.pubkey, CurrentPath: k.current,
		PreviousPath: k.previous, StagedPath: k.staged,
	})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestApply_HappyPath(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	writeFile(t, k.current, []byte("v1"))

	newBin := []byte("v2-binary-bytes")
	sig := ed25519.Sign(k.priv, newBin)
	if err := k.receiver(t).Apply(newBin, sig); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	gotCurrent, _ := os.ReadFile(k.current)
	gotPrevious, _ := os.ReadFile(k.previous)
	if !bytes.Equal(gotCurrent, newBin) {
		t.Errorf("current = %q, want %q", gotCurrent, newBin)
	}
	if !bytes.Equal(gotPrevious, []byte("v1")) {
		t.Errorf("previous = %q, want v1", gotPrevious)
	}
	if _, err := os.Stat(k.staged); !os.IsNotExist(err) {
		t.Errorf("staged path should be gone after promote, got err=%v", err)
	}
}

func TestApply_BadSignatureLeavesCurrent(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	writeFile(t, k.current, []byte("v1"))

	bin := []byte("malicious")
	sig := ed25519.Sign(k.otherPriv, bin) // wrong key
	err := k.receiver(t).Apply(bin, sig)
	if err == nil || !strings.Contains(err.Error(), "verification failed") {
		t.Fatalf("expected verification failure, got %v", err)
	}
	got, _ := os.ReadFile(k.current)
	if string(got) != "v1" {
		t.Errorf("current changed despite bad sig: %q", got)
	}
	if _, err := os.Stat(k.previous); !os.IsNotExist(err) {
		t.Errorf("previous should not have been written")
	}
}

func TestApply_TamperedBinaryFailsVerify(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	writeFile(t, k.current, []byte("v1"))

	bin := []byte("legit-binary")
	sig := ed25519.Sign(k.priv, bin)
	bin[0] = 'X' // tamper after signing
	if err := k.receiver(t).Apply(bin, sig); err == nil {
		t.Error("expected verification failure on tampered binary")
	}
}

func TestApply_WrongLengthSignature(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	if err := k.receiver(t).Apply([]byte("anything"), []byte("short")); err == nil {
		t.Error("expected wrong-length signature error")
	}
}

func TestApply_FirstInstallNoPrevious(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	bin := []byte("v1")
	sig := ed25519.Sign(k.priv, bin)
	if err := k.receiver(t).Apply(bin, sig); err != nil {
		t.Fatalf("Apply (no prior current): %v", err)
	}
	if _, err := os.Stat(k.previous); !os.IsNotExist(err) {
		t.Errorf("previous should not exist when there was no prior current; got err=%v", err)
	}
	got, _ := os.ReadFile(k.current)
	if !bytes.Equal(got, bin) {
		t.Errorf("current mismatch: %q", got)
	}
}

func TestApply_StagedFileIsExecutable(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file mode bits are not meaningful on Windows")
	}
	k := newKit(t)
	bin := []byte("v1")
	sig := ed25519.Sign(k.priv, bin)
	if err := k.receiver(t).Apply(bin, sig); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(k.current)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o100 == 0 {
		t.Errorf("current is not user-executable: %v", info.Mode())
	}
}

func TestRollback_SwapsCurrentAndPrevious(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	writeFile(t, k.current, []byte("v2"))
	writeFile(t, k.previous, []byte("v1"))
	if err := k.receiver(t).Rollback(); err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	cur, _ := os.ReadFile(k.current)
	prev, _ := os.ReadFile(k.previous)
	if string(cur) != "v1" || string(prev) != "v2" {
		t.Errorf("after rollback: current=%q previous=%q (want v1 / v2)", cur, prev)
	}
}

func TestRollback_NoPreviousErrors(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	writeFile(t, k.current, []byte("only"))
	if err := k.receiver(t).Rollback(); err == nil {
		t.Error("expected error when no previous binary exists")
	}
}

func TestApply_ThenRollback_RoundTrip(t *testing.T) {
	t.Parallel()
	k := newKit(t)
	writeFile(t, k.current, []byte("v1"))

	v2 := []byte("v2-content")
	if err := k.receiver(t).Apply(v2, ed25519.Sign(k.priv, v2)); err != nil {
		t.Fatal(err)
	}
	if err := k.receiver(t).Rollback(); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(k.current)
	if string(got) != "v1" {
		t.Errorf("after Apply+Rollback: current=%q, want v1", got)
	}
}

func TestNew_RequiresAllPaths(t *testing.T) {
	t.Parallel()
	full := binupd.Options{
		PubkeyPath: "p", CurrentPath: "c", PreviousPath: "pr", StagedPath: "s",
	}
	for _, mut := range []func(o binupd.Options) binupd.Options{
		func(o binupd.Options) binupd.Options { o.PubkeyPath = ""; return o },
		func(o binupd.Options) binupd.Options { o.CurrentPath = ""; return o },
		func(o binupd.Options) binupd.Options { o.PreviousPath = ""; return o },
		func(o binupd.Options) binupd.Options { o.StagedPath = ""; return o },
	} {
		if _, err := binupd.New(mut(full)); err == nil {
			t.Error("expected error for empty path")
		}
	}
}

func TestNew_BadPubkey(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.pem")
	_ = os.WriteFile(bad, []byte("not pem"), 0o600)
	if _, err := binupd.New(binupd.Options{
		PubkeyPath: bad, CurrentPath: "c", PreviousPath: "p", StagedPath: "s",
	}); err == nil {
		t.Error("expected error on non-PEM pubkey")
	}
}

