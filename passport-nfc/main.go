package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"

	"github.com/ebfe/scard"
	"github.com/gmrtd/gmrtd/password"
	"github.com/vaultys/vaultysid/passport-nfc/internal/chip"
)

type request struct {
	Operation      string   `json:"operation"`
	Reader         string   `json:"reader,omitempty"`
	MRZ            string   `json:"mrz,omitempty"`
	Challenges     [][]byte `json:"challenges,omitempty"`
	ResponseLength int      `json:"responseLength,omitempty"`
}

type response struct {
	Readers    *[]string `json:"readers,omitempty"`
	Reader     string    `json:"reader,omitempty"`
	DG15       []byte    `json:"dg15,omitempty"`
	DG14       []byte    `json:"dg14,omitempty"`
	Signatures [][]byte  `json:"signatures,omitempty"`
}

func readRequest(input io.Reader) (request, error) {
	var req request
	const maxRequest = 4096
	data, err := io.ReadAll(io.LimitReader(input, maxRequest+1))
	if err != nil || len(data) > maxRequest {
		return req, errors.New("could not read NFC request")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF || len(req.Reader) > 512 || len(req.MRZ) > 256 {
		return req, errors.New("invalid NFC request")
	}
	switch req.Operation {
	case "list":
		if req.MRZ == "" && req.Reader == "" && len(req.Challenges) == 0 && req.ResponseLength == 0 {
			return req, nil
		}
	case "read":
		if req.MRZ != "" && len(req.Challenges) == 0 && req.ResponseLength == 0 {
			return req, nil
		}
	case "sign":
		if req.MRZ != "" {
			return req, chip.ValidateChallenges(req.Challenges, req.ResponseLength)
		}
	}
	return req, errors.New("invalid NFC operation or parameters")
}

func selectReader(readers []string, requested string) (string, error) {
	if len(readers) == 0 {
		return "", errors.New("no PC/SC smart-card reader detected")
	}
	if requested == "" {
		if len(readers) == 1 {
			return readers[0], nil
		}
		return "", errors.New("multiple smart-card readers detected; specify a reader name")
	}
	if !slices.Contains(readers, requested) {
		return "", errors.New("specified smart-card reader was not detected")
	}
	return requested, nil
}

func run(req request) (response, error) {
	var pass *password.Password
	if req.Operation != "list" {
		var err error
		pass, err = chip.Password(req.MRZ)
		if err != nil {
			return response{}, err
		}
	}
	context, err := scard.EstablishContext()
	if err != nil {
		return response{}, fmt.Errorf("PC/SC is unavailable: %w", err)
	}
	defer context.Release()
	readers, err := context.ListReaders()
	if errors.Is(err, scard.ErrNoReadersAvailable) {
		readers = []string{}
	} else if err != nil {
		return response{}, fmt.Errorf("could not list PC/SC readers: %w", err)
	}
	if req.Operation == "list" {
		if readers == nil {
			readers = []string{}
		}
		return response{Readers: &readers}, nil
	}
	reader, err := selectReader(readers, req.Reader)
	if err != nil {
		return response{}, err
	}
	card, err := context.Connect(reader, scard.ShareExclusive, scard.ProtocolAny)
	if err != nil {
		return response{}, fmt.Errorf("could not connect to the passport; place it on the NFC reader: %w", err)
	}
	defer card.Disconnect(scard.ResetCard)
	session, err := chip.Open(pass, card.Transmit)
	if err != nil {
		return response{}, err
	}
	if req.Operation == "read" {
		groups, err := session.Read()
		return response{Reader: reader, DG15: groups.DG15, DG14: groups.DG14}, err
	}
	signatures, err := session.Sign(req.Challenges, req.ResponseLength)
	return response{Signatures: signatures}, err
}

func main() {
	defer func() {
		if recover() != nil {
			fmt.Fprintln(os.Stderr, "could not process the passport chip response")
			os.Exit(1)
		}
	}()
	// Keep passport data, access credentials and APDUs out of process logs.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	req, err := readRequest(os.Stdin)
	if err == nil {
		var result response
		result, err = run(req)
		if err == nil {
			err = json.NewEncoder(os.Stdout).Encode(result)
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
