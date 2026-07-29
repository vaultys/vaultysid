package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vaultys/vaultysid/go/pkg/idmanager"
	"github.com/vaultys/vaultysid/go/pkg/vaultysid"
)

var (
	// Global flags
	outputFormat string
	encoding     string
	verbose      bool

	// generate/from-entropy flag
	algorithm string
)

var rootCmd = &cobra.Command{
	Use:   "vaultysid-cli",
	Short: "VaultysID CLI - Decentralized Identity Management",
	Long: `VaultysID CLI provides command-line access to VaultysID and IDManager functionality.
It allows you to generate, manage, and use decentralized identities for machines, persons, and organizations.`,
}

var generateCmd = &cobra.Command{
	Use:   "generate [type]",
	Short: "Generate a new VaultysID",
	Long:  `Generate a new VaultysID of the specified type (machine, person, or organization)`,
	Args:  cobra.ExactArgs(1),
	RunE:  generateIdentity,
}

var fromEntropyCmd = &cobra.Command{
	Use:   "from-entropy [type] [entropy]",
	Short: "Create VaultysID from entropy",
	Long:  `Create a VaultysID from the given entropy (32 bytes hex or base64 encoded)`,
	Args:  cobra.ExactArgs(2),
	RunE:  fromEntropy,
}

var fromSecretCmd = &cobra.Command{
	Use:   "from-secret [secret]",
	Short: "Create VaultysID from secret",
	Long:  `Create a VaultysID from an existing secret key`,
	Args:  cobra.ExactArgs(1),
	RunE:  fromSecret,
}

var fromIDCmd = &cobra.Command{
	Use:   "from-id [id]",
	Short: "Create VaultysID from public ID",
	Long:  `Create a VaultysID from a public identity (only public operations available)`,
	Args:  cobra.ExactArgs(1),
	RunE:  fromID,
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign data or challenges",
}

var signDataCmd = &cobra.Command{
	Use:   "data [secret] [data]",
	Short: "Sign arbitrary data",
	Args:  cobra.ExactArgs(2),
	RunE:  signData,
}

var signChallengeCmd = &cobra.Command{
	Use:   "challenge [secret] [challenge]",
	Short: "Sign a challenge with protocol prefix",
	Args:  cobra.ExactArgs(2),
	RunE:  signChallenge,
}

var signFileCmd = &cobra.Command{
	Use:   "file [secret] [file-path]",
	Short: "Sign a file",
	Args:  cobra.ExactArgs(2),
	RunE:  signFile,
}

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify signatures",
}

var verifyDataCmd = &cobra.Command{
	Use:   "data [id] [data] [signature]",
	Short: "Verify a data signature",
	Args:  cobra.ExactArgs(3),
	RunE:  verifyData,
}

var verifyChallengeCmd = &cobra.Command{
	Use:   "challenge [id] [challenge] [signature]",
	Short: "Verify a challenge signature",
	Args:  cobra.ExactArgs(3),
	RunE:  verifyChallenge,
}

var verifyFileCmd = &cobra.Command{
	Use:   "file [id] [file-path] [signature]",
	Short: "Verify a file signature",
	Args:  cobra.ExactArgs(3),
	RunE:  verifyFile,
}

var infoCmd = &cobra.Command{
	Use:   "info [id-or-secret]",
	Short: "Display information about a VaultysID",
	Args:  cobra.ExactArgs(1),
	RunE:  showInfo,
}

var didCmd = &cobra.Command{
	Use:   "did [id]",
	Short: "Get the DID for a VaultysID",
	Args:  cobra.ExactArgs(1),
	RunE:  getDID,
}

var hmacCmd = &cobra.Command{
	Use:   "hmac [secret] [input]",
	Short: "Compute HMAC of input",
	Args:  cobra.ExactArgs(2),
	RunE:  computeHMAC,
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [secret] [peer-id] [file-path]",
	Short: "Encrypt a file for a peer",
	Args:  cobra.ExactArgs(3),
	RunE:  encryptFile,
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt [secret] [peer-id] [file-path]",
	Short: "Decrypt a file from a peer",
	Args:  cobra.ExactArgs(3),
	RunE:  decryptFile,
}

var managerCmd = &cobra.Command{
	Use:   "manager",
	Short: "ID Manager operations",
}

var managerInitCmd = &cobra.Command{
	Use:   "init [secret] [store-file]",
	Short: "Initialize a new IDManager",
	Args:  cobra.ExactArgs(2),
	RunE:  managerInit,
}

var managerExportCmd = &cobra.Command{
	Use:   "export [secret] [store-path]",
	Short: "Export manager backup",
	Args:  cobra.ExactArgs(2),
	RunE:  managerExport,
}

var managerImportCmd = &cobra.Command{
	Use:   "import [secret] [store-path] [backup-data]",
	Short: "Import manager from backup",
	Args:  cobra.ExactArgs(3),
	RunE:  managerImport,
}

var managerContactsCmd = &cobra.Command{
	Use:   "contacts [secret] [store-file]",
	Short: "List all contacts",
	Args:  cobra.ExactArgs(2),
	RunE:  managerContacts,
}

var managerAppsCmd = &cobra.Command{
	Use:   "apps [secret] [store-file]",
	Short: "List all apps",
	Args:  cobra.ExactArgs(2),
	RunE:  managerApps,
}

var managerSaveContactCmd = &cobra.Command{
	Use:   "save-contact [secret] [store-file] [contact-id] [key=value...]",
	Short: "Save a contact with optional metadata",
	Long:  `Save a contact to the store. Optional metadata can be provided as key=value pairs.`,
	Args:  cobra.MinimumNArgs(3),
	RunE:  managerSaveContact,
}

var managerSaveAppCmd = &cobra.Command{
	Use:   "save-app [secret] [store-file] [site] [server-id] [key=value...]",
	Short: "Save an app with optional metadata",
	Long:  `Save an app to the store. Optional metadata can be provided as key=value pairs.`,
	Args:  cobra.MinimumNArgs(4),
	RunE:  managerSaveApp,
}

var managerSetNameCmd = &cobra.Command{
	Use:   "set-name [secret] [store-file] [name]",
	Short: "Set the user's name in the manager",
	Args:  cobra.ExactArgs(3),
	RunE:  managerSetName,
}

var managerSetEmailCmd = &cobra.Command{
	Use:   "set-email [secret] [store-file] [email]",
	Short: "Set the user's email in the manager",
	Args:  cobra.ExactArgs(3),
	RunE:  managerSetEmail,
}

var managerSetPhoneCmd = &cobra.Command{
	Use:   "set-phone [secret] [store-file] [phone]",
	Short: "Set the user's phone number in the manager",
	Args:  cobra.ExactArgs(3),
	RunE:  managerSetPhone,
}

func init() {
	// Global flags
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "json", "Output format (json, text)")
	rootCmd.PersistentFlags().StringVarP(&encoding, "encoding", "e", "hex", "Encoding format (hex, base64)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// generate/from-entropy flag
	generateCmd.Flags().StringVar(&algorithm, "alg", "ed25519", "Signature algorithm (ed25519, dilithium)")
	fromEntropyCmd.Flags().StringVar(&algorithm, "alg", "ed25519", "Signature algorithm (ed25519, dilithium)")

	// Build command tree
	rootCmd.AddCommand(generateCmd)
	rootCmd.AddCommand(fromEntropyCmd)
	rootCmd.AddCommand(fromSecretCmd)
	rootCmd.AddCommand(fromIDCmd)
	rootCmd.AddCommand(signCmd)
	rootCmd.AddCommand(verifyCmd)
	rootCmd.AddCommand(infoCmd)
	rootCmd.AddCommand(didCmd)
	rootCmd.AddCommand(hmacCmd)
	rootCmd.AddCommand(encryptCmd)
	rootCmd.AddCommand(decryptCmd)
	rootCmd.AddCommand(managerCmd)

	// Sign subcommands
	signCmd.AddCommand(signDataCmd)
	signCmd.AddCommand(signChallengeCmd)
	signCmd.AddCommand(signFileCmd)

	// Verify subcommands
	verifyCmd.AddCommand(verifyDataCmd)
	verifyCmd.AddCommand(verifyChallengeCmd)
	verifyCmd.AddCommand(verifyFileCmd)

	// Manager subcommands
	managerCmd.AddCommand(managerInitCmd)
	managerCmd.AddCommand(managerExportCmd)
	managerCmd.AddCommand(managerImportCmd)
	managerCmd.AddCommand(managerContactsCmd)
	managerCmd.AddCommand(managerAppsCmd)
	managerCmd.AddCommand(managerSaveContactCmd)
	managerCmd.AddCommand(managerSaveAppCmd)
	managerCmd.AddCommand(managerSetNameCmd)
	managerCmd.AddCommand(managerSetEmailCmd)
	managerCmd.AddCommand(managerSetPhoneCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// Helper functions
func decodeInput(input string) ([]byte, error) {
	// Try hex first
	if data, err := hex.DecodeString(input); err == nil {
		return data, nil
	}
	// Try base64
	if data, err := base64.StdEncoding.DecodeString(input); err == nil {
		return data, nil
	}
	// Return as raw bytes
	return []byte(input), nil
}

func encodeOutput(data []byte) string {
	if encoding == "base64" {
		return base64.StdEncoding.EncodeToString(data)
	}
	return hex.EncodeToString(data)
}

func outputResult(cmd *cobra.Command, result interface{}) {
	if outputFormat == "json" {
		jsonData, _ := json.MarshalIndent(result, "", "  ")
		cmd.Println(string(jsonData))
	} else {
		cmd.Printf("%+v\n", result)
	}
}

// Command implementations
func generateIdentity(cmd *cobra.Command, args []string) error {
	idType := strings.ToLower(args[0])
	var vid *vaultysid.VaultysID
	var err error

	switch idType {
	case "machine":
		vid, err = vaultysid.GenerateMachineAlg(algorithm)
	case "person":
		vid, err = vaultysid.GeneratePersonAlg(algorithm)
	case "organization":
		vid, err = vaultysid.GenerateOrganizationAlg(algorithm)
	default:
		return fmt.Errorf("invalid identity type: %s (use machine, person, or organization)", idType)
	}

	if err != nil {
		return fmt.Errorf("failed to generate identity: %w", err)
	}

	id, _ := vid.ToString(encoding)
	secret, _ := vid.GetSecretString(encoding)

	result := map[string]interface{}{
		"type":       vid.GetType(),
		"id":         id,
		"secret":     secret,
		"did":        vid.DID(),
		"capability": vid.GetCapability(),
	}

	outputResult(cmd, result)
	return nil
}

func fromEntropy(cmd *cobra.Command, args []string) error {
	idType := strings.ToLower(args[0])
	entropy, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode entropy: %w", err)
	}

	parsedType, err := vaultysid.ParseIdentityType(idType)
	if err != nil {
		return fmt.Errorf("invalid identity type: %s", idType)
	}

	vid, err := vaultysid.FromEntropyAlg(entropy, parsedType, algorithm)
	if err != nil {
		return fmt.Errorf("failed to create identity from entropy: %w", err)
	}

	id, _ := vid.ToString(encoding)
	secret, _ := vid.GetSecretString(encoding)

	result := map[string]interface{}{
		"type":       vid.GetType(),
		"id":         id,
		"secret":     secret,
		"did":        vid.DID(),
		"capability": vid.GetCapability(),
	}

	outputResult(cmd, result)
	return nil
}

func fromSecret(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity from secret: %w", err)
	}

	id, _ := vid.ToString(encoding)
	secretStr, _ := vid.GetSecretString(encoding)

	result := map[string]interface{}{
		"type":       vid.GetType(),
		"id":         id,
		"secret":     secretStr,
		"did":        vid.DID(),
		"capability": vid.GetCapability(),
	}

	outputResult(cmd, result)
	return nil
}

func fromID(cmd *cobra.Command, args []string) error {
	id, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode id: %w", err)
	}

	vid, err := vaultysid.FromID(id, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity from ID: %w", err)
	}

	idStr, _ := vid.ToString(encoding)

	result := map[string]interface{}{
		"type":       vid.GetType(),
		"id":         idStr,
		"did":        vid.DID(),
		"capability": vid.GetCapability(),
	}

	outputResult(cmd, result)
	return nil
}

func signData(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	data, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode data: %w", err)
	}

	signature, err := vid.Sign(data)
	if err != nil {
		return fmt.Errorf("failed to sign data: %w", err)
	}

	result := map[string]interface{}{
		"signature": encodeOutput(signature),
		"did":       vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func signChallenge(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	challenge, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	signature, err := vid.SignChallenge(challenge)
	if err != nil {
		return fmt.Errorf("failed to sign challenge: %w", err)
	}

	result := map[string]interface{}{
		"signature": encodeOutput(signature),
		"did":       vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func signFile(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	// Read file
	fileData, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create manager for file signing
	store := idmanager.NewMemoryStore()
	manager := idmanager.NewManager(vid, store)

	file := &idmanager.File{
		Name:        filepath.Base(args[1]),
		ArrayBuffer: fileData,
	}

	// Sign the file
	signature, err := manager.SignFile(file)
	if err != nil {
		return fmt.Errorf("failed to sign file: %w", err)
	}

	result := map[string]interface{}{
		"challenge": encodeOutput(signature.Challenge),
		"signature": encodeOutput(signature.Signature),
		"file":      args[1],
		"did":       vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func verifyData(cmd *cobra.Command, args []string) error {
	id, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode id: %w", err)
	}

	vid, err := vaultysid.FromID(id, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	data, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode data: %w", err)
	}

	signature, err := decodeInput(args[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	err = vid.Verify(data, signature)
	if err != nil {
		result := map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		}
		outputResult(cmd, result)
		return nil
	}

	result := map[string]interface{}{
		"valid": true,
		"did":   vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func verifyChallenge(cmd *cobra.Command, args []string) error {
	id, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode id: %w", err)
	}

	vid, err := vaultysid.FromID(id, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	challenge, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode challenge: %w", err)
	}

	signature, err := decodeInput(args[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	err = vid.VerifyChallenge(challenge, signature)
	if err != nil {
		result := map[string]interface{}{
			"valid": false,
			"error": err.Error(),
		}
		outputResult(cmd, result)
		return nil
	}

	result := map[string]interface{}{
		"valid": true,
		"did":   vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func verifyFile(cmd *cobra.Command, args []string) error {
	id, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode id: %w", err)
	}

	vid, err := vaultysid.FromID(id, nil)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	// Read file
	fileData, err := os.ReadFile(args[1])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Decode signature (expecting JSON with challenge and signature)
	var fileSignature idmanager.FileSignature
	signatureData, err := decodeInput(args[2])
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	if err := json.Unmarshal(signatureData, &fileSignature); err != nil {
		// Try as simple signature
		fileSignature.Signature = signatureData
	}

	// Create manager for verification
	store := idmanager.NewMemoryStore()
	manager := idmanager.NewManager(vid, store)

	file := &idmanager.File{
		Name:        filepath.Base(args[1]),
		ArrayBuffer: fileData,
	}

	// VerifyFile returns an error if verification fails
	// The fourth parameter is userVerification (boolean)
	err = manager.VerifyFile(file, &fileSignature, vid, false)
	valid := err == nil

	// Treat verification-related errors as validation failures, not command errors
	if err != nil {
		errStr := err.Error()
		if errStr != "signature verification failed" &&
			errStr != "file hash mismatch" &&
			!strings.Contains(errStr, "verification failed") &&
			!strings.Contains(errStr, "hash mismatch") {
			// Only return error for actual system errors, not verification failures
			return fmt.Errorf("failed to verify file: %w", err)
		}
	}

	result := map[string]interface{}{
		"valid": valid,
		"did":   vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func showInfo(cmd *cobra.Command, args []string) error {
	input, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	// Try as secret first, then as ID
	var vid *vaultysid.VaultysID
	vid, err = vaultysid.FromSecret(input)
	if err != nil {
		vid, err = vaultysid.FromID(input, nil)
		if err != nil {
			return fmt.Errorf("failed to parse identity: %w", err)
		}
	}

	pubKey := vid.GetPublicKey()
	cypherPubKey := vid.GetCypherPublicKey()

	result := map[string]interface{}{
		"type":            vid.GetType(),
		"did":             vid.DID(),
		"capability":      vid.GetCapability(),
		"version":         vid.GetVersion(),
		"isPrivate":       vid.IsPrivate(),
		"isPublic":        vid.IsPublic(),
		"isHardware":      vid.IsHardware(),
		"publicKey":       encodeOutput(pubKey),
		"cypherPublicKey": encodeOutput(cypherPubKey),
		"hasCertificate":  vid.HasCertificate(),
	}

	if vid.IsPrivate() {
		id, _ := vid.ToString(encoding)
		result["id"] = id
	}

	outputResult(cmd, result)
	return nil
}

func getDID(cmd *cobra.Command, args []string) error {
	input, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode input: %w", err)
	}

	// Try as secret first, then as ID
	var vid *vaultysid.VaultysID
	vid, err = vaultysid.FromSecret(input)
	if err != nil {
		vid, err = vaultysid.FromID(input, nil)
		if err != nil {
			return fmt.Errorf("failed to create identity: %w", err)
		}
	}

	if outputFormat == "json" {
		result := map[string]interface{}{
			"did": vid.DID(),
		}
		outputResult(cmd, result)
	} else {
		cmd.Println(vid.DID())
	}

	return nil
}

func computeHMAC(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	hmacResult, err := vid.HMAC(args[1])
	if err != nil {
		return fmt.Errorf("failed to compute HMAC: %w", err)
	}

	result := map[string]interface{}{
		"hmac": encodeOutput(hmacResult),
		"did":  vid.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func encryptFile(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	peerID, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode peer ID: %w", err)
	}

	peerVID, err := vaultysid.FromID(peerID, nil)
	if err != nil {
		return fmt.Errorf("failed to create peer identity: %w", err)
	}

	// Read file
	fileData, err := os.ReadFile(args[2])
	if err != nil {
		return fmt.Errorf("failed to read file: %w", err)
	}

	// Create manager for encryption
	// Create manager
	store := idmanager.NewMemoryStore()
	manager := idmanager.NewManager(vid, store)

	file := &idmanager.File{
		Name:        filepath.Base(args[2]),
		Type:        "application/octet-stream",
		ArrayBuffer: fileData,
	}

	encrypted, err := manager.EncryptFile(file)
	if err != nil {
		return fmt.Errorf("failed to encrypt file: %w", err)
	}

	// Write encrypted file
	if err := os.WriteFile(args[2], encrypted.ArrayBuffer, 0644); err != nil {
		return fmt.Errorf("failed to write encrypted file: %w", err)
	}

	size := len(encrypted.ArrayBuffer)
	result := map[string]interface{}{
		"outputPath": args[2],
		"size":       size,
		"did":        vid.DID(),
		"peerDID":    peerVID.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func decryptFile(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	peerID, err := decodeInput(args[1])
	if err != nil {
		return fmt.Errorf("failed to decode peer ID: %w", err)
	}

	peerVID, err := vaultysid.FromID(peerID, nil)
	if err != nil {
		return fmt.Errorf("failed to create peer identity: %w", err)
	}

	// Read encrypted file
	encryptedData, err := os.ReadFile(args[2])
	if err != nil {
		return fmt.Errorf("failed to read encrypted file: %w", err)
	}

	// Create manager for decryption
	// Create manager
	store := idmanager.NewMemoryStore()
	manager := idmanager.NewManager(vid, store)

	// Create File struct with encrypted data
	encryptedFile := &idmanager.File{
		Name:        filepath.Base(args[2]),
		ArrayBuffer: encryptedData,
	}

	decrypted, err := manager.DecryptFile(encryptedFile)
	if err != nil {
		return fmt.Errorf("failed to decrypt file: %w", err)
	}

	// Save decrypted file
	outputPath := strings.TrimSuffix(args[2], ".encrypted")
	if outputPath == args[2] {
		outputPath = args[2] + ".decrypted"
	}

	if err := os.WriteFile(outputPath, decrypted.ArrayBuffer, 0644); err != nil {
		return fmt.Errorf("failed to write decrypted file: %w", err)
	}

	result := map[string]interface{}{
		"outputPath": outputPath,
		"fileName":   decrypted.Name,
		"fileType":   decrypted.Type,
		"size":       len(decrypted.ArrayBuffer),
		"did":        vid.DID(),
		"peerDID":    peerVID.DID(),
	}

	outputResult(cmd, result)
	return nil
}

func loadStore(storePath string) (idmanager.Store, error) {
	// Check if it's a file or memory store
	if storePath == ":memory:" {
		return idmanager.NewMemoryStore(), nil
	}

	// Try to load existing file store
	store, _ := idmanager.NewFileStore(storePath)

	// Check if store file exists
	if _, err := os.Stat(storePath); os.IsNotExist(err) {
		// Create new store file
		if err := store.Save(); err != nil {
			return nil, fmt.Errorf("failed to create store file: %w", err)
		}
	}

	return store, nil
}

func managerInit(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	_ = idmanager.NewManager(vid, store)

	// Save store if it's file-based
	if fileStore, ok := store.(*idmanager.FileStore); ok {
		if err := fileStore.Save(); err != nil {
			return fmt.Errorf("failed to save store: %w", err)
		}
	}

	result := map[string]interface{}{
		"message": "Manager initialized successfully",
		"did":     vid.DID(),
		"store":   args[1],
	}

	outputResult(cmd, result)
	return nil
}

func managerExport(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	// Export with empty password (no encryption)
	exportData, err := manager.ExportBackup("")
	if err != nil {
		return fmt.Errorf("failed to export data: %w", err)
	}

	// Output the base64 encoded backup
	cmd.Println(exportData)
	return nil
}

func managerImport(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	// Import data is already base64 encoded string
	importData := args[2]

	// Import with empty password (no encryption)
	importedManager, err := idmanager.ImportBackup(importData, "")
	if err != nil {
		return fmt.Errorf("failed to import data: %w", err)
	}

	// Copy contacts from imported manager to target store
	targetManager := idmanager.NewManager(vid, store)
	for _, contact := range importedManager.Contacts() {
		contactVID, err := vaultysid.FromID(contact.ID, contact.Certificate)
		if err == nil {
			targetManager.SaveContact(contactVID, contact.Metadata)
		}
	}

	// Copy apps from imported manager to target store
	for _, app := range importedManager.Apps() {
		// Decode the server ID from base64
		serverIDBytes, err := base64.StdEncoding.DecodeString(app.ServerID)
		if err == nil {
			appVID, err := vaultysid.FromID(serverIDBytes, app.Certificate)
			if err == nil {
				targetManager.SaveApp(appVID, app.Site)
			}
		}
	}

	cmd.Println("Data imported successfully")
	return nil
}

func managerContacts(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	contacts := manager.Contacts()

	if outputFormat == "json" {
		// Convert contacts to JSON-serializable format
		contactsList := make([]map[string]interface{}, 0)
		for _, contact := range contacts {
			contactInfo := map[string]interface{}{
				"id": base64.StdEncoding.EncodeToString(contact.ID),
			}
			if contact.Metadata != nil {
				contactInfo["metadata"] = contact.Metadata
			}
			contactsList = append(contactsList, contactInfo)
		}
		data, _ := json.MarshalIndent(contactsList, "", "  ")
		cmd.Println(string(data))
	} else {
		for _, contact := range contacts {
			cmd.Printf("Contact ID: %s\n", base64.StdEncoding.EncodeToString(contact.ID))
			if contact.Metadata != nil {
				if name, ok := contact.Metadata["name"]; ok {
					cmd.Printf("  Name: %v\n", name)
				}
				if email, ok := contact.Metadata["email"]; ok {
					cmd.Printf("  Email: %v\n", email)
				}
				if phone, ok := contact.Metadata["phone"]; ok {
					cmd.Printf("  Phone: %v\n", phone)
				}
			}
			cmd.Println()
		}
	}
	return nil
}

func managerApps(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	apps := manager.Apps()

	if outputFormat == "json" {
		data, _ := json.MarshalIndent(apps, "", "  ")
		cmd.Println(string(data))
	} else {
		for _, app := range apps {
			cmd.Printf("App: %s\n", app.Site)
			cmd.Printf("  Server ID: %s\n", app.ServerID)
			if app.Metadata != nil {
				for k, v := range app.Metadata {
					cmd.Printf("  %s: %v\n", k, v)
				}
			}
			cmd.Println()
		}
	}
	return nil
}

func managerSaveContact(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	contactID := args[2]

	// Create a VaultysID from the contact ID string
	contactVID, err := vaultysid.FromIDString(contactID, encoding, nil)
	if err != nil {
		return fmt.Errorf("failed to parse contact ID: %w", err)
	}

	// Parse optional metadata (key=value pairs)
	metadata := make(map[string]interface{})
	for i := 3; i < len(args); i++ {
		parts := strings.SplitN(args[i], "=", 2)
		if len(parts) == 2 {
			metadata[parts[0]] = parts[1]
		}
	}

	err = manager.SaveContact(contactVID, metadata)
	if err != nil {
		return fmt.Errorf("failed to save contact: %w", err)
	}

	cmd.Printf("Contact %s saved successfully\n", contactID)
	return nil
}

func managerSaveApp(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	site := args[2]
	serverIDStr := args[3]

	// Create a VaultysID from the server ID string
	serverVID, err := vaultysid.FromIDString(serverIDStr, encoding, nil)
	if err != nil {
		return fmt.Errorf("failed to parse server ID: %w", err)
	}

	// The SaveApp function takes either a VaultysID or StoredApp
	// When passing VaultysID, it uses the site as the first argument
	err = manager.SaveApp(serverVID, site)
	if err != nil {
		return fmt.Errorf("failed to save app: %w", err)
	}

	cmd.Printf("App %s saved successfully\n", site)
	return nil
}

func managerSetName(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	err = manager.SetName(args[2])
	if err != nil {
		return fmt.Errorf("failed to set name: %w", err)
	}

	cmd.Printf("Name set to: %s\n", args[2])
	return nil
}

func managerSetEmail(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	err = manager.SetEmail(args[2])
	if err != nil {
		return fmt.Errorf("failed to set email: %w", err)
	}

	cmd.Printf("Email set to: %s\n", args[2])
	return nil
}

func managerSetPhone(cmd *cobra.Command, args []string) error {
	secret, err := decodeInput(args[0])
	if err != nil {
		return fmt.Errorf("failed to decode secret: %w", err)
	}

	vid, err := vaultysid.FromSecret(secret)
	if err != nil {
		return fmt.Errorf("failed to create identity: %w", err)
	}

	store, err := loadStore(args[1])
	if err != nil {
		return fmt.Errorf("failed to load store: %w", err)
	}

	manager := idmanager.NewManager(vid, store)

	err = manager.SetPhone(args[2])
	if err != nil {
		return fmt.Errorf("failed to set phone: %w", err)
	}

	cmd.Printf("Phone set to: %s\n", args[2])
	return nil
}
