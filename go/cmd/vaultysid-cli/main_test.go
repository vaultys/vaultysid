package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

type runResult struct {
	stdout string
	stderr string
	err    error
}

// run executes a fresh command tree. stdin feeds --secret-file -.
func run(t *testing.T, stdin string, args ...string) runResult {
	t.Helper()
	c := newCLI()
	c.stdin = strings.NewReader(stdin)
	c.isTTY = func() bool { return false }
	return runWith(t, c, args...)
}

func runWith(t *testing.T, c *cli, args ...string) runResult {
	t.Helper()
	root := newRootCmd(c)
	var out, errb bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errb)
	root.SetArgs(args)
	err := root.Execute()
	return runResult{stdout: out.String(), stderr: errb.String(), err: err}
}

func decodeJSON(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	var m map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(s), &m), s)
	return m
}

func clearEnv(t *testing.T) {
	t.Setenv(envSecret, "")
	t.Setenv(envPassword, "")
	t.Setenv(envEntropy, "")
}

// newIdentity generates an identity through the CLI and returns its secret
// file path, public id (hex) and secret (hex).
func newIdentity(t *testing.T, dir, kind string) (secretFile, id, secret string) {
	t.Helper()
	secretFile = filepath.Join(dir, kind+".secret")
	r := run(t, "", "generate", kind, "--out", secretFile)
	require.NoError(t, r.err, r.stderr)
	res := decodeJSON(t, r.stdout)
	raw, err := os.ReadFile(secretFile)
	require.NoError(t, err)
	return secretFile, res["id"].(string), strings.TrimSpace(string(raw))
}

func TestGenerate_WritesSecretFileOnly(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()

	r := run(t, "", "generate", "person")
	require.Error(t, r.err, "generate without --out must fail")

	for _, kind := range []string{"machine", "person", "organization"} {
		secretFile, id, secret := newIdentity(t, dir, kind)

		st, err := os.Stat(secretFile)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())

		r := run(t, "", "generate", kind, "--out", secretFile)
		require.Error(t, r.err, "must refuse to overwrite an existing secret")

		sec, err := hex.DecodeString(secret)
		require.NoError(t, err)
		vid, err := vaultysid.FromSecret(sec)
		require.NoError(t, err)
		gotID, _ := vid.ToString("hex")
		assert.Equal(t, gotID, id)
	}

	// The secret never appears on stdout.
	f := filepath.Join(dir, "x.secret")
	r = run(t, "", "generate", "person", "--out", f)
	require.NoError(t, r.err)
	raw, _ := os.ReadFile(f)
	assert.NotContains(t, r.stdout, strings.TrimSpace(string(raw)))
	assert.NotContains(t, decodeJSON(t, r.stdout), "secret")

	r = run(t, "", "generate", "alien", "--out", filepath.Join(dir, "y"))
	assert.Error(t, r.err)
}

func TestGenerate_Dilithium(t *testing.T) {
	clearEnv(t)
	f := filepath.Join(t.TempDir(), "d.secret")
	r := run(t, "", "generate", "person", "--alg", "dilithium", "--out", f)
	require.NoError(t, r.err, r.stderr)
	r = run(t, "", "from-secret", "--secret-file", f)
	require.NoError(t, r.err, r.stderr)
}

func TestSecretsNeverFromArgv(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	_, _, secret := newIdentity(t, dir, "person")

	for _, args := range [][]string{
		{"from-secret", secret},
		{"sign", "data", secret, "aabb"},
		{"sign", "challenge", secret, "aabb"},
		{"hmac", secret, "input"},
		{"manager", "init", secret, filepath.Join(dir, "s.json")},
		{"from-entropy", "person", strings.Repeat("ab", 32)},
	} {
		r := run(t, "", args...)
		assert.Error(t, r.err, "argv secret accepted: %v", args[:2])
	}

	// No secret source at all is an explicit error.
	r := run(t, "", "sign", "data", "aabb")
	require.Error(t, r.err)
	assert.Contains(t, r.err.Error(), "--secret-file")
}

func TestSecretSources(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, id, secret := newIdentity(t, dir, "person")

	check := func(r runResult) {
		t.Helper()
		require.NoError(t, r.err, r.stderr)
		assert.Equal(t, id, decodeJSON(t, r.stdout)["id"])
		assert.NotContains(t, r.stdout, secret)
	}
	check(run(t, "", "from-secret", "--secret-file", secretFile))
	check(run(t, secret+"\n", "from-secret", "--secret-file", "-"))
	t.Setenv(envSecret, secret)
	check(run(t, "", "from-secret"))
	t.Setenv(envSecret, "")

	// World-readable secret file: works, but warns.
	loose := filepath.Join(dir, "loose.secret")
	require.NoError(t, os.WriteFile(loose, []byte(secret), 0o644))
	r := run(t, "", "from-secret", "--secret-file", loose)
	check(r)
	assert.Contains(t, r.stderr, "warning")
	r = run(t, "", "from-secret", "--secret-file", secretFile)
	assert.NotContains(t, r.stderr, "warning")

	r = run(t, "not hex at all!", "from-secret", "--secret-file", "-")
	assert.Error(t, r.err)
}

func TestFromEntropy(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	entropy := strings.Repeat("01", 32)
	ef := filepath.Join(dir, "entropy")
	require.NoError(t, os.WriteFile(ef, []byte(entropy), 0o600))

	out1 := filepath.Join(dir, "a.secret")
	r := run(t, "", "from-entropy", "person", "--entropy-file", ef, "--out", out1)
	require.NoError(t, r.err, r.stderr)
	id1 := decodeJSON(t, r.stdout)["id"]

	out2 := filepath.Join(dir, "b.secret")
	r = run(t, entropy, "from-entropy", "person", "--entropy-file", "-", "--out", out2)
	require.NoError(t, r.err, r.stderr)
	assert.Equal(t, id1, decodeJSON(t, r.stdout)["id"], "deterministic")

	r = run(t, "", "from-entropy", "person", "--entropy-file", ef)
	assert.Error(t, r.err, "--out required")
}

func TestSignVerifyData_RawDomain(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, id, secret := newIdentity(t, dir, "person")

	r := run(t, "", "sign", "data", "48656c6c6f", "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	res := decodeJSON(t, r.stdout)
	sig := res["signature"].(string)
	assert.Equal(t, "VAULTYS_RAW", res["scheme"])

	r = run(t, "", "verify", "data", id, "48656c6c6f", sig)
	require.NoError(t, r.err)
	assert.Equal(t, true, decodeJSON(t, r.stdout)["valid"])

	r = run(t, "", "verify", "data", id, "48656c6c6e", sig)
	require.NoError(t, r.err)
	assert.Equal(t, false, decodeJSON(t, r.stdout)["valid"])

	// The CLI signature is domain separated: not a raw key signature and
	// not a handshake signature.
	sec, _ := hex.DecodeString(secret)
	vid, _ := vaultysid.FromSecret(sec)
	sigBytes, _ := hex.DecodeString(sig)
	data, _ := hex.DecodeString("48656c6c6f")
	assert.Error(t, vid.KeyManager.Verify(data, sigBytes))
	assert.Error(t, vid.VerifyHandshake(data, sigBytes))
	assert.NoError(t, vid.Verify(data, sigBytes))
}

func TestSignVerifyChallenge(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, id, _ := newIdentity(t, dir, "person")

	r := run(t, "", "sign", "challenge", "636861", "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	sig := decodeJSON(t, r.stdout)["signature"].(string)

	r = run(t, "", "verify", "challenge", id, "636861", sig)
	require.NoError(t, r.err)
	assert.Equal(t, true, decodeJSON(t, r.stdout)["valid"])

	// A challenge signature is not a data signature.
	r = run(t, "", "verify", "data", id, "636861", sig)
	require.NoError(t, r.err)
	assert.Equal(t, false, decodeJSON(t, r.stdout)["valid"])
}

func TestSignVerifyFile(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, id, _ := newIdentity(t, dir, "person")
	doc := filepath.Join(dir, "doc.txt")
	require.NoError(t, os.WriteFile(doc, []byte("important"), 0o644))

	r := run(t, "", "sign", "file", doc, "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	res := decodeJSON(t, r.stdout)

	r = run(t, "", "verify", "file", id, doc, res["signature"].(string), "--challenge", res["challenge"].(string))
	require.NoError(t, r.err)
	assert.Equal(t, true, decodeJSON(t, r.stdout)["valid"], r.stdout)

	require.NoError(t, os.WriteFile(doc, []byte("tampered"), 0o644))
	r = run(t, "", "verify", "file", id, doc, res["signature"].(string), "--challenge", res["challenge"].(string))
	require.NoError(t, r.err)
	assert.Equal(t, false, decodeJSON(t, r.stdout)["valid"])

	// Without the challenge, verification fails closed.
	r = run(t, "", "verify", "file", id, doc, res["signature"].(string))
	require.NoError(t, r.err)
	assert.Equal(t, false, decodeJSON(t, r.stdout)["valid"])
}

func TestInfoDIDHMAC(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, id, secret := newIdentity(t, dir, "person")

	r := run(t, "", "info", id)
	require.NoError(t, r.err)
	info := decodeJSON(t, r.stdout)
	assert.Equal(t, "public", info["capability"])

	r = run(t, "", "info", "--secret-file", secretFile)
	require.NoError(t, r.err)
	info = decodeJSON(t, r.stdout)
	assert.Equal(t, "private", info["capability"])
	assert.Equal(t, id, info["id"])
	assert.NotContains(t, r.stdout, secret)

	r1 := run(t, "", "did", id)
	r2 := run(t, "", "did", "--secret-file", secretFile)
	require.NoError(t, r1.err)
	require.NoError(t, r2.err)
	assert.Equal(t, r1.stdout, r2.stdout)
	assert.Contains(t, r1.stdout, "did:vaultys:")

	h1 := run(t, "", "hmac", "input", "--secret-file", secretFile)
	h2 := run(t, "", "hmac", "input", "--secret-file", secretFile)
	require.NoError(t, h1.err)
	assert.Equal(t, h1.stdout, h2.stdout)
}

func TestEncryptDecrypt(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, _, _ := newIdentity(t, dir, "person")
	plain := filepath.Join(dir, "secret.txt")
	require.NoError(t, os.WriteFile(plain, []byte("top secret"), 0o644))

	// Encrypt no longer takes a peer id and does not overwrite the input.
	r := run(t, "", "encrypt", "peer-id-not-accepted", plain, "--secret-file", secretFile)
	require.Error(t, r.err)

	r = run(t, "", "encrypt", plain, "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	enc := plain + ".encrypted"
	orig, _ := os.ReadFile(plain)
	assert.Equal(t, "top secret", string(orig), "input must be left intact")
	_, err := os.Stat(enc)
	require.NoError(t, err)

	r = run(t, "", "encrypt", plain, "--secret-file", secretFile)
	require.Error(t, r.err, "must not clobber an existing output")

	require.NoError(t, os.Remove(plain))
	r = run(t, "", "decrypt", enc, "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	got, _ := os.ReadFile(plain)
	assert.Equal(t, "top secret", string(got))
	st, _ := os.Stat(plain)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "decrypted output must be 0600")

	// Another identity cannot decrypt.
	other, _, _ := newIdentity(t, dir, "machine")
	r = run(t, "", "decrypt", enc, "--secret-file", other, "--out", filepath.Join(dir, "nope"))
	assert.Error(t, r.err)

	// --in-place
	inplace := filepath.Join(dir, "inplace.txt")
	require.NoError(t, os.WriteFile(inplace, []byte("data"), 0o600))
	r = run(t, "", "encrypt", inplace, "--in-place", "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	b, _ := os.ReadFile(inplace)
	assert.NotEqual(t, "data", string(b))
	r = run(t, "", "decrypt", inplace, "--out", filepath.Join(dir, "inplace.dec"), "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	b, _ = os.ReadFile(filepath.Join(dir, "inplace.dec"))
	assert.Equal(t, "data", string(b))
}

func TestManagerWorkflow(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, _, secret := newIdentity(t, dir, "person")
	_, contactID, _ := newIdentity(t, dir, "organization")
	_, appID, _ := newIdentity(t, dir, "machine")
	store := filepath.Join(dir, "store.json")

	r := run(t, "", "manager", "init", store, "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	st, err := os.Stat(store)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm(), "store holds secrets")

	for _, args := range [][]string{
		{"manager", "set-name", store, "Alice"},
		{"manager", "set-email", store, "alice@example.com"},
		{"manager", "set-phone", store, "+1-555"},
		{"manager", "save-contact", store, contactID, "name=ACME Corp"},
		{"manager", "save-app", store, "app.example.com", appID},
	} {
		r := run(t, "", append(args, "--secret-file", secretFile)...)
		require.NoError(t, r.err, "%v: %s", args, r.stderr)
	}

	r = run(t, "", "manager", "contacts", store, "--secret-file", secretFile)
	require.NoError(t, r.err)
	assert.Contains(t, r.stdout, "ACME Corp")
	r = run(t, "", "manager", "apps", store, "--secret-file", secretFile)
	require.NoError(t, r.err)
	assert.Contains(t, r.stdout, "app.example.com")

	// Export requires a non-empty password.
	r = run(t, "", "manager", "export", store, "--secret-file", secretFile)
	require.Error(t, r.err, "no password source and no TTY")
	empty := filepath.Join(dir, "empty.pw")
	require.NoError(t, os.WriteFile(empty, []byte("\n"), 0o600))
	r = run(t, "", "manager", "export", store, "--secret-file", secretFile, "--password-file", empty)
	require.Error(t, r.err, "empty password")

	pwFile := filepath.Join(dir, "pw")
	require.NoError(t, os.WriteFile(pwFile, []byte("correct horse\n"), 0o600))
	backupFile := filepath.Join(dir, "backup.b64")
	r = run(t, "", "manager", "export", store, "--secret-file", secretFile, "--password-file", pwFile, "--out", backupFile)
	require.NoError(t, r.err, r.stderr)
	st, _ = os.Stat(backupFile)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
	backup, _ := os.ReadFile(backupFile)
	assert.NotContains(t, string(backup), secret)

	// Wrong password fails, right password restores.
	restored := filepath.Join(dir, "restored.json")
	t.Setenv(envPassword, "wrong")
	r = run(t, "", "manager", "import", restored, "@"+backupFile, "--secret-file", secretFile)
	require.Error(t, r.err)
	t.Setenv(envPassword, "correct horse")
	r = run(t, "", "manager", "import", restored, "@"+backupFile, "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	t.Setenv(envPassword, "")

	r = run(t, "", "manager", "contacts", restored, "--secret-file", secretFile)
	require.NoError(t, r.err)
	assert.Contains(t, r.stdout, "ACME Corp")
	r = run(t, "", "manager", "apps", restored, "--secret-file", secretFile)
	require.NoError(t, r.err)
	assert.Contains(t, r.stdout, "app.example.com")

	// A corrupt store is reported, not silently replaced.
	require.NoError(t, os.WriteFile(store, []byte("{corrupt"), 0o600))
	r = run(t, "", "manager", "contacts", store, "--secret-file", secretFile)
	require.Error(t, r.err)
	b, _ := os.ReadFile(store)
	assert.Equal(t, "{corrupt", string(b))
}

func TestPasswordPrompt(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	secretFile, _, _ := newIdentity(t, dir, "person")
	store := filepath.Join(dir, "store.json")
	require.NoError(t, run(t, "", "manager", "init", store, "--secret-file", secretFile).err)

	prompt := func(answers ...string) *cli {
		c := newCLI()
		c.isTTY = func() bool { return true }
		c.readPass = func() ([]byte, error) {
			a := answers[0]
			answers = answers[1:]
			return []byte(a), nil
		}
		return c
	}

	r := runWith(t, prompt("pw", "pw"), "manager", "export", store, "--secret-file", secretFile)
	require.NoError(t, r.err, r.stderr)
	assert.NotEmpty(t, strings.TrimSpace(r.stdout))
	assert.Contains(t, r.stderr, "password")

	r = runWith(t, prompt("pw", "other"), "manager", "export", store, "--secret-file", secretFile)
	assert.Error(t, r.err, "mismatched confirmation")

	r = runWith(t, prompt("", ""), "manager", "export", store, "--secret-file", secretFile)
	assert.Error(t, r.err, "empty password")
}

func TestFromIDAndErrors(t *testing.T) {
	clearEnv(t)
	dir := t.TempDir()
	_, id, _ := newIdentity(t, dir, "person")

	r := run(t, "", "from-id", id)
	require.NoError(t, r.err)
	assert.Equal(t, "public", decodeJSON(t, r.stdout)["capability"])

	for _, args := range [][]string{
		{"from-id", "zz"},
		{"from-id", "01c403010203"}, // truncated / short key
		{"verify", "data", "01", "00", "00"},
		{"info", "deadbeef"},
	} {
		r := run(t, "", args...)
		assert.Error(t, r.err, "%v", args)
	}

	r = run(t, "", "-o", "text", "did", id)
	require.NoError(t, r.err)
	assert.True(t, strings.HasPrefix(strings.TrimSpace(r.stdout), "did:vaultys:"))
}
