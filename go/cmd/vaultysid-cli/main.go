package main

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vaultys/vaultysid/go/pkg/idmanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
	"golang.org/x/term"
)

// Environment variables that may carry secret material. Secrets are never
// accepted as positional arguments (argv is visible to other local users
// via ps and ends up in shell history).
const (
	envSecret   = "VAULTYSID_SECRET"
	envPassword = "VAULTYSID_PASSWORD"
	envEntropy  = "VAULTYSID_ENTROPY"
)

// cli holds the flag values of one command tree, so tests can build fresh
// trees without global state.
type cli struct {
	outputFormat string
	encoding     string
	verbose      bool

	secretFile   string
	passwordFile string

	algorithm   string
	entropyFile string
	outFile     string
	force       bool
	inPlace     bool
	challenge   string

	stdin    io.Reader
	isTTY    func() bool
	readPass func() ([]byte, error)
}

func newCLI() *cli {
	return &cli{
		stdin: os.Stdin,
		isTTY: func() bool { return term.IsTerminal(int(os.Stdin.Fd())) },
		readPass: func() ([]byte, error) {
			return term.ReadPassword(int(os.Stdin.Fd()))
		},
	}
}

func main() {
	if err := newRootCmd(newCLI()).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd(c *cli) *cobra.Command {
	root := &cobra.Command{
		Use:   "vaultysid-cli",
		Short: "VaultysID CLI - Decentralized Identity Management",
		Long: `VaultysID CLI provides command-line access to VaultysID and IDManager functionality.

Secrets are never taken from the command line. Provide them with
  --secret-file PATH   (a file, ideally mode 0600)
  --secret-file -      (read from stdin)
  VAULTYSID_SECRET     (environment variable)
Backup passwords come from --password-file, VAULTYSID_PASSWORD, or an
interactive prompt.`,
		SilenceUsage: true,
	}
	pf := root.PersistentFlags()
	pf.StringVarP(&c.outputFormat, "output", "o", "json", "Output format (json, text)")
	pf.StringVarP(&c.encoding, "encoding", "e", "hex", "Encoding format (hex, base64)")
	pf.BoolVarP(&c.verbose, "verbose", "v", false, "Verbose output")
	pf.StringVar(&c.secretFile, "secret-file", "", "File containing the identity secret ('-' for stdin); defaults to $"+envSecret)
	pf.StringVar(&c.passwordFile, "password-file", "", "File containing the backup password; defaults to $"+envPassword+" or a prompt")

	generateCmd := &cobra.Command{
		Use:   "generate [type]",
		Short: "Generate a new VaultysID and write its secret to --out (mode 0600)",
		Args:  cobra.ExactArgs(1),
		RunE:  c.generateIdentity,
	}
	generateCmd.Flags().StringVar(&c.algorithm, "alg", "ed25519", "Signature algorithm (ed25519, dilithium)")
	generateCmd.Flags().StringVar(&c.outFile, "out", "", "File to write the new secret to (required, created 0600)")
	generateCmd.Flags().BoolVar(&c.force, "force", false, "Overwrite an existing --out file")

	fromEntropyCmd := &cobra.Command{
		Use:   "from-entropy [type]",
		Short: "Create a VaultysID from 32 bytes of entropy (--entropy-file or $" + envEntropy + ")",
		Args:  cobra.ExactArgs(1),
		RunE:  c.fromEntropy,
	}
	fromEntropyCmd.Flags().StringVar(&c.algorithm, "alg", "ed25519", "Signature algorithm (ed25519, dilithium)")
	fromEntropyCmd.Flags().StringVar(&c.entropyFile, "entropy-file", "", "File containing hex/base64 entropy ('-' for stdin)")
	fromEntropyCmd.Flags().StringVar(&c.outFile, "out", "", "File to write the secret to (required, created 0600)")
	fromEntropyCmd.Flags().BoolVar(&c.force, "force", false, "Overwrite an existing --out file")

	fromSecretCmd := &cobra.Command{
		Use:   "from-secret",
		Short: "Show the public identity of a secret",
		Args:  cobra.NoArgs,
		RunE:  c.fromSecret,
	}

	fromIDCmd := &cobra.Command{
		Use:   "from-id [id]",
		Short: "Create VaultysID from public ID",
		Args:  cobra.ExactArgs(1),
		RunE:  c.fromID,
	}

	signCmd := &cobra.Command{Use: "sign", Short: "Sign data, challenges or files (secret via --secret-file/$" + envSecret + ")"}
	signCmd.AddCommand(
		&cobra.Command{
			Use:   "data [data]",
			Short: "Sign data (signature over SHA-256(\"VAULTYS_RAW\" || data))",
			Args:  cobra.ExactArgs(1),
			RunE:  c.signData,
		},
		&cobra.Command{
			Use:   "challenge [challenge]",
			Short: "Sign a challenge (signature over SHA-256(\"VAULTYS_SIGN\" || challenge))",
			Args:  cobra.ExactArgs(1),
			RunE:  c.signChallenge,
		},
		&cobra.Command{
			Use:   "file [file-path]",
			Short: "Sign a file",
			Args:  cobra.ExactArgs(1),
			RunE:  c.signFile,
		},
	)

	verifyFileCmd := &cobra.Command{
		Use:   "file [id] [file-path] [signature]",
		Short: "Verify a `sign file` signature (pass the signed challenge with --challenge)",
		Args:  cobra.ExactArgs(3),
		RunE:  c.verifyFile,
	}
	verifyFileCmd.Flags().StringVar(&c.challenge, "challenge", "", "The signed challenge printed by `sign file` (hex/base64)")

	verifyCmd := &cobra.Command{Use: "verify", Short: "Verify signatures"}
	verifyCmd.AddCommand(
		&cobra.Command{
			Use:   "data [id] [data] [signature]",
			Short: "Verify a `sign data` (VAULTYS_RAW) signature",
			Args:  cobra.ExactArgs(3),
			RunE:  c.verifyData,
		},
		&cobra.Command{
			Use:   "challenge [id] [challenge] [signature]",
			Short: "Verify a challenge signature",
			Args:  cobra.ExactArgs(3),
			RunE:  c.verifyChallenge,
		},
		verifyFileCmd,
	)

	infoCmd := &cobra.Command{
		Use:   "info [id]",
		Short: "Display information about a public ID, or about the identity of --secret-file/$" + envSecret,
		Args:  cobra.MaximumNArgs(1),
		RunE:  c.showInfo,
	}
	didCmd := &cobra.Command{
		Use:   "did [id]",
		Short: "Get the DID of a public ID, or of the identity of --secret-file/$" + envSecret,
		Args:  cobra.MaximumNArgs(1),
		RunE:  c.getDID,
	}
	hmacCmd := &cobra.Command{
		Use:   "hmac [input]",
		Short: "Compute HMAC of input",
		Args:  cobra.ExactArgs(1),
		RunE:  c.computeHMAC,
	}

	encryptCmd := &cobra.Command{
		Use:   "encrypt [file-path]",
		Short: "Encrypt a file for yourself (output: --out, default <file>.encrypted)",
		Args:  cobra.ExactArgs(1),
		RunE:  c.encryptFile,
	}
	encryptCmd.Flags().StringVar(&c.outFile, "out", "", "Output file (default <file>.encrypted)")
	encryptCmd.Flags().BoolVar(&c.inPlace, "in-place", false, "Replace the input file with its encryption")
	encryptCmd.Flags().BoolVar(&c.force, "force", false, "Overwrite an existing output file")

	decryptCmd := &cobra.Command{
		Use:   "decrypt [file-path]",
		Short: "Decrypt a file encrypted with `encrypt` (output written with mode 0600)",
		Args:  cobra.ExactArgs(1),
		RunE:  c.decryptFile,
	}
	decryptCmd.Flags().StringVar(&c.outFile, "out", "", "Output file (default: strip .encrypted, else append .decrypted)")
	decryptCmd.Flags().BoolVar(&c.force, "force", false, "Overwrite an existing output file")

	managerCmd := &cobra.Command{Use: "manager", Short: "ID Manager operations (secret via --secret-file/$" + envSecret + ")"}
	managerExportCmd := &cobra.Command{
		Use:   "export [store-path]",
		Short: "Export a password-encrypted manager backup",
		Args:  cobra.ExactArgs(1),
		RunE:  c.managerExport,
	}
	managerExportCmd.Flags().StringVar(&c.outFile, "out", "", "Write the backup to this file (0600) instead of stdout")
	managerCmd.AddCommand(
		&cobra.Command{Use: "init [store-file]", Short: "Initialize a new IDManager", Args: cobra.ExactArgs(1), RunE: c.managerInit},
		managerExportCmd,
		&cobra.Command{Use: "import [store-path] [backup-data|@file]", Short: "Import contacts and apps from a backup", Args: cobra.ExactArgs(2), RunE: c.managerImport},
		&cobra.Command{Use: "contacts [store-file]", Short: "List all contacts", Args: cobra.ExactArgs(1), RunE: c.managerContacts},
		&cobra.Command{Use: "apps [store-file]", Short: "List all apps", Args: cobra.ExactArgs(1), RunE: c.managerApps},
		&cobra.Command{Use: "save-contact [store-file] [contact-id] [key=value...]", Short: "Save a contact with optional metadata", Args: cobra.MinimumNArgs(2), RunE: c.managerSaveContact},
		&cobra.Command{Use: "save-app [store-file] [site] [server-id]", Short: "Save an app", Args: cobra.MinimumNArgs(3), RunE: c.managerSaveApp},
		&cobra.Command{Use: "set-name [store-file] [name]", Short: "Set the user's name", Args: cobra.ExactArgs(2), RunE: c.managerSetName},
		&cobra.Command{Use: "set-email [store-file] [email]", Short: "Set the user's email", Args: cobra.ExactArgs(2), RunE: c.managerSetEmail},
		&cobra.Command{Use: "set-phone [store-file] [phone]", Short: "Set the user's phone number", Args: cobra.ExactArgs(2), RunE: c.managerSetPhone},
	)

	root.AddCommand(generateCmd, fromEntropyCmd, fromSecretCmd, fromIDCmd, signCmd, verifyCmd,
		infoCmd, didCmd, hmacCmd, encryptCmd, decryptCmd, managerCmd)
	return root
}

// ---------------------------------------------------------------------------
// Input / output helpers

func decodeInput(input string) ([]byte, error) {
	if data, err := hex.DecodeString(input); err == nil {
		return data, nil
	}
	if data, err := base64.StdEncoding.DecodeString(input); err == nil {
		return data, nil
	}
	return []byte(input), nil
}

// decodeStrict decodes hex or base64 only (no raw fallback), for key material.
func decodeStrict(input string) ([]byte, error) {
	input = strings.TrimSpace(input)
	if data, err := hex.DecodeString(input); err == nil {
		return data, nil
	}
	if data, err := base64.StdEncoding.DecodeString(input); err == nil {
		return data, nil
	}
	return nil, fmt.Errorf("expected hex or base64")
}

func (c *cli) encodeOutput(data []byte) string {
	if c.encoding == "base64" {
		return base64.StdEncoding.EncodeToString(data)
	}
	return hex.EncodeToString(data)
}

func (c *cli) outputResult(cmd *cobra.Command, result interface{}) {
	if c.outputFormat == "json" {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(jsonData))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%+v\n", result)
	}
}

// readSecretSource reads secret material from a file ('-' = stdin), warning
// when the file is accessible by group or others.
func (c *cli) readSecretSource(cmd *cobra.Command, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(c.stdin, 1<<20))
	}
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Mode().Perm()&0o077 != 0 {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning: %s is accessible by other users (mode %04o); run: chmod 600 %s\n", path, st.Mode().Perm(), path)
	}
	return os.ReadFile(path)
}

// loadSecretBytes returns the identity secret from --secret-file or $VAULTYSID_SECRET.
func (c *cli) loadSecretBytes(cmd *cobra.Command) ([]byte, error) {
	var raw []byte
	switch {
	case c.secretFile != "":
		data, err := c.readSecretSource(cmd, c.secretFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read secret: %w", err)
		}
		raw = data
	case os.Getenv(envSecret) != "":
		raw = []byte(os.Getenv(envSecret))
	default:
		return nil, fmt.Errorf("no secret provided: use --secret-file PATH, --secret-file - (stdin) or $%s", envSecret)
	}
	secret, err := decodeStrict(string(raw))
	if err != nil {
		return nil, fmt.Errorf("failed to decode secret: %w", err)
	}
	return secret, nil
}

func (c *cli) loadIdentity(cmd *cobra.Command) (*vaultysid.VaultysID, error) {
	secret, err := c.loadSecretBytes(cmd)
	if err != nil {
		return nil, err
	}
	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}
	return vid, nil
}

// loadPassword returns a non-empty backup password from --password-file,
// $VAULTYSID_PASSWORD, or an interactive no-echo prompt.
func (c *cli) loadPassword(cmd *cobra.Command, confirm bool) (string, error) {
	var pw string
	switch {
	case c.passwordFile != "":
		data, err := c.readSecretSource(cmd, c.passwordFile)
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		pw = strings.TrimRight(string(data), "\r\n")
	case os.Getenv(envPassword) != "":
		pw = os.Getenv(envPassword)
	case c.secretFile != "-" && c.isTTY():
		fmt.Fprint(cmd.ErrOrStderr(), "Backup password: ")
		p1, err := c.readPass()
		fmt.Fprintln(cmd.ErrOrStderr())
		if err != nil {
			return "", fmt.Errorf("failed to read password: %w", err)
		}
		if confirm {
			fmt.Fprint(cmd.ErrOrStderr(), "Confirm password: ")
			p2, err := c.readPass()
			fmt.Fprintln(cmd.ErrOrStderr())
			if err != nil {
				return "", fmt.Errorf("failed to read password: %w", err)
			}
			if !bytes.Equal(p1, p2) {
				return "", fmt.Errorf("passwords do not match")
			}
		}
		pw = string(p1)
	default:
		return "", fmt.Errorf("a backup password is required: use --password-file, $%s or run interactively", envPassword)
	}
	if pw == "" {
		return "", idmanager.ErrEmptyPassword
	}
	return pw, nil
}

// writeNewSecretFile writes secret material to path with mode 0600,
// refusing to overwrite an existing file unless force is set.
func writeNewSecretFile(path string, data []byte, force bool) error {
	if path == "" {
		return fmt.Errorf("--out is required")
	}
	if !force {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return idmanager.WriteSecretFile(path, data)
}

// publicInfo is what commands print about an identity: never the secret.
func (c *cli) publicInfo(vid *vaultysid.VaultysID) map[string]interface{} {
	id, _ := vid.ToString(c.encoding)
	return map[string]interface{}{
		"type":       vid.GetType(),
		"id":         id,
		"did":        vid.DID(),
		"capability": vid.GetCapability(),
	}
}

func (c *cli) writeSecretAndReport(cmd *cobra.Command, vid *vaultysid.VaultysID) error {
	secret, err := vid.GetSecretString(c.encoding)
	if err != nil {
		return err
	}
	if err := writeNewSecretFile(c.outFile, []byte(secret+"\n"), c.force); err != nil {
		return fmt.Errorf("failed to write secret: %w", err)
	}
	result := c.publicInfo(vid)
	result["secretFile"] = c.outFile
	c.outputResult(cmd, result)
	return nil
}

// ---------------------------------------------------------------------------
// Identity commands

func (c *cli) generateIdentity(cmd *cobra.Command, args []string) error {
	if c.outFile == "" {
		return fmt.Errorf("--out is required: the new secret is written to a 0600 file, never printed")
	}
	var vid *vaultysid.VaultysID
	var err error
	switch strings.ToLower(args[0]) {
	case "machine":
		vid, err = vaultysid.GenerateMachineAlg(c.algorithm)
	case "person":
		vid, err = vaultysid.GeneratePersonAlg(c.algorithm)
	case "organization":
		vid, err = vaultysid.GenerateOrganizationAlg(c.algorithm)
	default:
		return fmt.Errorf("invalid identity type: %s (use machine, person, or organization)", args[0])
	}
	if err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}
	return c.writeSecretAndReport(cmd, vid)
}

func (c *cli) fromEntropy(cmd *cobra.Command, args []string) error {
	if c.outFile == "" {
		return fmt.Errorf("--out is required: the secret is written to a 0600 file, never printed")
	}
	parsedType, err := vaultysid.ParseIdentityType(strings.ToLower(args[0]))
	if err != nil {
		return fmt.Errorf("invalid identity type: %s", args[0])
	}
	var raw []byte
	switch {
	case c.entropyFile != "":
		raw, err = c.readSecretSource(cmd, c.entropyFile)
		if err != nil {
			return fmt.Errorf("failed to read entropy: %w", err)
		}
	case os.Getenv(envEntropy) != "":
		raw = []byte(os.Getenv(envEntropy))
	default:
		return fmt.Errorf("no entropy provided: use --entropy-file PATH, --entropy-file - (stdin) or $%s", envEntropy)
	}
	entropy, err := decodeStrict(string(raw))
	if err != nil {
		return fmt.Errorf("failed to decode entropy: %w", err)
	}
	vid, err := vaultysid.FromEntropyAlg(entropy, parsedType, c.algorithm)
	if err != nil {
		return fmt.Errorf("failed to create identity from entropy: %w", err)
	}
	return c.writeSecretAndReport(cmd, vid)
}

func (c *cli) fromSecret(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	c.outputResult(cmd, c.publicInfo(vid))
	return nil
}

func (c *cli) fromID(cmd *cobra.Command, args []string) error {
	id, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode id: %w", err)
	}
	vid, err := vaultysid.FromID(id, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity from ID: %w", err)
	}
	c.outputResult(cmd, c.publicInfo(vid))
	return nil
}

// ---------------------------------------------------------------------------
// Signing

func (c *cli) signData(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	data, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode data: %w", err)
	}
	signature, err := vid.Sign(data)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}
	c.outputResult(cmd, map[string]interface{}{
		"signature": c.encodeOutput(signature),
		"did":       vid.DID(),
		"scheme":    "VAULTYS_RAW",
	})
	return nil
}

func (c *cli) signChallenge(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	challenge, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}
	signature, err := vid.SignChallenge(challenge)
	if err != nil {
		return fmt.Errorf("failed to sign challenge: %w", err)
	}
	c.outputResult(cmd, map[string]interface{}{
		"signature": c.encodeOutput(signature),
		"did":       vid.DID(),
	})
	return nil
}

func (c *cli) signFile(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	fileData, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	manager := idmanager.NewManager(vid, idmanager.NewMemoryStore())
	signature, err := manager.SignFile(&idmanager.File{Name: filepath.Base(args[0]), ArrayBuffer: fileData})
	if err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}
	c.outputResult(cmd, map[string]interface{}{
		"challenge": c.encodeOutput(signature.Challenge),
		"signature": c.encodeOutput(signature.Signature),
		"file":      args[0],
		"did":       vid.DID(),
	})
	return nil
}

// ---------------------------------------------------------------------------
// Verification

func parsePublicID(s string) (*vaultysid.VaultysID, error) {
	id, err := decodeInput(s)
	if err != nil {
		return nil, fmt.Errorf("failed to decode id: %w", err)
	}
	vid, err := vaultysid.FromID(id, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create identity: %w", err)
	}
	return vid, nil
}

func (c *cli) reportVerification(cmd *cobra.Command, vid *vaultysid.VaultysID, err error) {
	if err != nil {
		c.outputResult(cmd, map[string]interface{}{"valid": false, "error": err.Error()})
		return
	}
	c.outputResult(cmd, map[string]interface{}{"valid": true, "did": vid.DID()})
}

func (c *cli) verifyData(cmd *cobra.Command, args []string) error {
	vid, err := parsePublicID(args[0])
	if err != nil {
		return err
	}
	data, _ := decodeInput(args[1])
	signature, _ := decodeInput(args[2])
	c.reportVerification(cmd, vid, vid.Verify(data, signature))
	return nil
}

func (c *cli) verifyChallenge(cmd *cobra.Command, args []string) error {
	vid, err := parsePublicID(args[0])
	if err != nil {
		return err
	}
	challenge, _ := decodeInput(args[1])
	signature, _ := decodeInput(args[2])
	c.reportVerification(cmd, vid, vid.VerifyChallenge(challenge, signature))
	return nil
}

func (c *cli) verifyFile(cmd *cobra.Command, args []string) error {
	vid, err := parsePublicID(args[0])
	if err != nil {
		return err
	}
	fileData, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	signatureData, _ := decodeInput(args[2])

	// Accept either JSON {"challenge","signature"} (base64 []byte fields)
	// or the raw signature (the challenge then has to be found in the store).
	var fileSignature idmanager.FileSignature
	if err := json.Unmarshal(signatureData, &fileSignature); err != nil {
		fileSignature = idmanager.FileSignature{Signature: signatureData}
	}
	if c.challenge != "" {
		ch, err := decodeStrict(c.challenge)
		if err != nil {
			return fmt.Errorf("failed to decode challenge: %w", err)
		}
		fileSignature.Challenge = ch
	}

	manager := idmanager.NewManager(vid, idmanager.NewMemoryStore())
	err = manager.VerifyFile(&idmanager.File{Name: filepath.Base(args[1]), ArrayBuffer: fileData}, &fileSignature, vid, false)
	c.reportVerification(cmd, vid, err)
	return nil
}

// ---------------------------------------------------------------------------
// Info

func (c *cli) idFromArgsOrSecret(cmd *cobra.Command, args []string) (*vaultysid.VaultysID, error) {
	if len(args) == 1 {
		return parsePublicID(args[0])
	}
	return c.loadIdentity(cmd)
}

func (c *cli) showInfo(cmd *cobra.Command, args []string) error {
	vid, err := c.idFromArgsOrSecret(cmd, args)
	if err != nil {
		return err
	}
	result := c.publicInfo(vid)
	result["version"] = vid.GetVersion()
	result["isPrivate"] = vid.IsPrivate()
	result["isPublic"] = vid.IsPublic()
	result["isHardware"] = vid.IsHardware()
	result["publicKey"] = c.encodeOutput(vid.GetPublicKey())
	result["cypherPublicKey"] = c.encodeOutput(vid.GetCypherPublicKey())
	result["hasCertificate"] = vid.HasCertificate()
	c.outputResult(cmd, result)
	return nil
}

func (c *cli) getDID(cmd *cobra.Command, args []string) error {
	vid, err := c.idFromArgsOrSecret(cmd, args)
	if err != nil {
		return err
	}
	if c.outputFormat == "json" {
		c.outputResult(cmd, map[string]interface{}{"did": vid.DID()})
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), vid.DID())
	}
	return nil
}

func (c *cli) computeHMAC(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	hmacResult, err := vid.HMAC(args[0])
	if err != nil {
		return fmt.Errorf("failed to compute HMAC: %w", err)
	}
	c.outputResult(cmd, map[string]interface{}{
		"hmac": c.encodeOutput(hmacResult),
		"did":  vid.DID(),
	})
	return nil
}

// ---------------------------------------------------------------------------
// File encryption (rfc/ENCRYPTION.md, keyed by the identity itself)

func (c *cli) encryptFile(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	in := args[0]
	out := c.outFile
	switch {
	case c.inPlace && out != "":
		return fmt.Errorf("--in-place and --out are mutually exclusive")
	case c.inPlace:
		out = in
	case out == "":
		out = in + ".encrypted"
	}
	if !c.inPlace && !c.force {
		if _, err := os.Lstat(out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", out)
		}
	}

	fileData, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}
	manager := idmanager.NewManager(vid, idmanager.NewMemoryStore())
	encrypted, err := manager.EncryptFile(&idmanager.File{
		Name:        filepath.Base(in),
		Type:        "application/octet-stream",
		ArrayBuffer: fileData,
	})
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}
	if err := idmanager.WriteSecretFile(out, encrypted.ArrayBuffer); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}
	c.outputResult(cmd, map[string]interface{}{
		"outputPath": out,
		"size":       len(encrypted.ArrayBuffer),
		"did":        vid.DID(),
	})
	return nil
}

func (c *cli) decryptFile(cmd *cobra.Command, args []string) error {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return err
	}
	in := args[0]
	out := c.outFile
	if out == "" {
		out = strings.TrimSuffix(in, ".encrypted")
		if out == in {
			out = in + ".decrypted"
		}
	}
	if !c.force {
		if _, err := os.Lstat(out); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", out)
		}
	}

	encryptedData, err := os.ReadFile(in)
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}
	manager := idmanager.NewManager(vid, idmanager.NewMemoryStore())
	decrypted, err := manager.DecryptFile(&idmanager.File{Name: filepath.Base(in), ArrayBuffer: encryptedData})
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}
	// Plaintext of an encrypted file is sensitive: 0600, atomic.
	if err := idmanager.WriteSecretFile(out, decrypted.ArrayBuffer); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}
	c.outputResult(cmd, map[string]interface{}{
		"outputPath": out,
		"fileName":   decrypted.Name,
		"fileType":   decrypted.Type,
		"size":       len(decrypted.ArrayBuffer),
		"did":        vid.DID(),
	})
	return nil
}

// ---------------------------------------------------------------------------
// Manager

func loadStore(storePath string) (idmanager.Store, error) {
	if storePath == ":memory:" {
		return idmanager.NewMemoryStore(), nil
	}
	store, err := idmanager.NewFileStore(storePath)
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(storePath); errors.Is(err, os.ErrNotExist) {
		if err := store.Save(); err != nil {
			return nil, fmt.Errorf("failed to create store file: %w", err)
		}
	}
	return store, nil
}

func (c *cli) openManager(cmd *cobra.Command, storePath string) (*idmanager.Manager, *vaultysid.VaultysID, error) {
	vid, err := c.loadIdentity(cmd)
	if err != nil {
		return nil, nil, err
	}
	store, err := loadStore(storePath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load store: %w", err)
	}
	return idmanager.NewManager(vid, store), vid, nil
}

func (c *cli) managerInit(cmd *cobra.Command, args []string) error {
	_, vid, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	c.outputResult(cmd, map[string]interface{}{
		"message": "Manager initialized successfully",
		"did":     vid.DID(),
		"store":   args[0],
	})
	return nil
}

func (c *cli) managerExport(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	password, err := c.loadPassword(cmd, true)
	if err != nil {
		return err
	}
	backup, err := manager.ExportBackup(password)
	if err != nil {
		return fmt.Errorf("failed to export data: %w", err)
	}
	if c.outFile != "" {
		if err := idmanager.WriteSecretFile(c.outFile, []byte(backup+"\n")); err != nil {
			return fmt.Errorf("failed to write backup: %w", err)
		}
		c.outputResult(cmd, map[string]interface{}{"backupFile": c.outFile})
		return nil
	}
	fmt.Fprintln(cmd.OutOrStdout(), backup)
	return nil
}

func (c *cli) managerImport(cmd *cobra.Command, args []string) error {
	targetManager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	backup := args[1]
	if strings.HasPrefix(backup, "@") {
		data, err := os.ReadFile(backup[1:])
		if err != nil {
			return fmt.Errorf("failed to read backup: %w", err)
		}
		backup = string(data)
	}
	password, err := c.loadPassword(cmd, false)
	if err != nil {
		return err
	}
	importedManager, err := idmanager.ImportBackup(strings.TrimSpace(backup), password)
	if err != nil {
		return fmt.Errorf("failed to import data: %w", err)
	}

	for _, contact := range importedManager.Contacts() {
		if contactVID, err := vaultysid.FromID(contact.ID, contact.Certificate); err == nil {
			_ = targetManager.SaveContact(contactVID, contact.Metadata)
		}
	}
	for _, app := range importedManager.Apps() {
		serverIDBytes, err := base64.StdEncoding.DecodeString(app.ServerID)
		if err != nil {
			continue
		}
		if appVID, err := vaultysid.FromID(serverIDBytes, app.Certificate); err == nil {
			_ = targetManager.SaveApp(appVID, app.Site)
		}
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Data imported successfully")
	return nil
}

func (c *cli) managerContacts(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	contacts := manager.Contacts()
	if c.outputFormat == "json" {
		list := make([]map[string]interface{}, 0)
		for _, contact := range contacts {
			info := map[string]interface{}{"id": base64.StdEncoding.EncodeToString(contact.ID)}
			if contact.Metadata != nil {
				info["metadata"] = contact.Metadata
			}
			list = append(list, info)
		}
		data, _ := json.MarshalIndent(list, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}
	for _, contact := range contacts {
		fmt.Fprintf(cmd.OutOrStdout(), "Contact ID: %s\n", base64.StdEncoding.EncodeToString(contact.ID))
		for _, k := range []string{"name", "email", "phone"} {
			if v, ok := contact.Metadata[k]; ok {
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %v\n", strings.ToUpper(k[:1])+k[1:], v)
			}
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

func (c *cli) managerApps(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	apps := manager.Apps()
	if c.outputFormat == "json" {
		data, _ := json.MarshalIndent(apps, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(data))
		return nil
	}
	for _, app := range apps {
		fmt.Fprintf(cmd.OutOrStdout(), "App: %s\n", app.Site)
		fmt.Fprintf(cmd.OutOrStdout(), "  Server ID: %s\n", app.ServerID)
		for k, v := range app.Metadata {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s: %v\n", k, v)
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}
	return nil
}

func (c *cli) managerSaveContact(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	contactVID, err := vaultysid.FromIDString(args[1], c.encoding, nil)
	if err != nil {
		return fmt.Errorf("failed to parse contact ID: %w", err)
	}
	metadata := make(map[string]interface{})
	for _, kv := range args[2:] {
		if parts := strings.SplitN(kv, "=", 2); len(parts) == 2 {
			metadata[parts[0]] = parts[1]
		}
	}
	if err := manager.SaveContact(contactVID, metadata); err != nil {
		return fmt.Errorf("failed to save contact: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Contact %s saved successfully\n", contactVID.DID())
	return nil
}

func (c *cli) managerSaveApp(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	site := args[1]
	serverVID, err := vaultysid.FromIDString(args[2], c.encoding, nil)
	if err != nil {
		return fmt.Errorf("failed to parse server ID: %w", err)
	}
	if err := manager.SaveApp(serverVID, site); err != nil {
		return fmt.Errorf("failed to save app: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "App %s saved successfully\n", site)
	return nil
}

func (c *cli) managerSetName(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	if err := manager.SetName(args[1]); err != nil {
		return fmt.Errorf("failed to set name: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Name set to: %s\n", args[1])
	return nil
}

func (c *cli) managerSetEmail(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	if err := manager.SetEmail(args[1]); err != nil {
		return fmt.Errorf("failed to set email: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Email set to: %s\n", args[1])
	return nil
}

func (c *cli) managerSetPhone(cmd *cobra.Command, args []string) error {
	manager, _, err := c.openManager(cmd, args[0])
	if err != nil {
		return err
	}
	if err := manager.SetPhone(args[1]); err != nil {
		return fmt.Errorf("failed to set phone: %w", err)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Phone set to: %s\n", args[1])
	return nil
}
