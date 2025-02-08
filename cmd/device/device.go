package main

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"flag"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/BuriedInTheGround/iot-vault-auth/internal/tui"
	"github.com/BuriedInTheGround/iot-vault-auth/internal/vault"
)

func main() {
	tui.ProgramName = "device"
	flag.Parse()

	if len(flag.Args()) != 1 {
		tui.Errorf("missing vault file path")
	}

	path := flag.Arg(0)
	_, name := filepath.Split(path)
	id := strings.Split(name, ".")[0]

	tui.ProgramName = "device-" + id

	v, err := vault.NewVaultFromFile(path)
	if err != nil {
		tui.Errorf("failed to read initial vault: %v", err)
	}

	dev := NewDevice(id, v)
	for range time.Tick(300 * time.Millisecond) {
		report := time.Now().Local().Format(time.RFC3339)
		if err := dev.SendReport(":8177", report); err != nil {
			tui.Warningf("failed to send report: %v", err)
		} else {
			tui.Infof("sent report: %q", report)
		}
	}
}

type Device struct {
	id    string
	vault vault.Vault

	sessionID   string
	sessionKey  vault.SessionKey
	sessionFrom time.Time
	sessionHist []byte
}

func NewDevice(id string, vault vault.Vault) *Device {
	return &Device{id: id, vault: vault}
}

func (d *Device) SendReport(addr string, report string) error {
	if !d.sessionFrom.IsZero() && time.Since(d.sessionFrom) > vault.SessionDuration {
		if err := d.vault.Rotate(d.sessionHist); err != nil {
			return fmt.Errorf("failed to rotate vault: %w", err)
		}
		d.clearSession()
		tui.Infof("secure vault rotated and session shred")
	}
	if d.sessionID == "" || d.sessionKey == nil {
		if err := d.authenticate(addr); err != nil {
			return fmt.Errorf("failed to authenticate: %w", err)
		}
		tui.Infof("authenticated with %q", addr)
	}
	aad := []byte(d.id + d.sessionID)
	ciphertext, err := d.sessionKey.Encrypt([]byte(report), aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt message: %w", err)
	}
	r := bytes.NewReader(append(ciphertext, aad...))
	body, err := response(http.Post("http://"+addr+"/report", "application/octet-stream", r))
	if err != nil {
		return err
	}
	d.sessionHist = append(d.sessionHist, []byte(report)...)
	d.sessionHist = append(d.sessionHist, body...)
	return nil
}

func (d *Device) authenticate(addr string) error {
	if err := d.refreshSessionID(); err != nil {
		return fmt.Errorf("failed to refresh session id: %w", err)
	}

	aad := []byte(d.id + d.sessionID)

	// Step 1
	m1 := bytes.NewReader(aad)
	body1, err := response(http.Post("http://"+addr+"/auth-request", "application/octet-stream", m1))
	if err != nil {
		return err
	}

	// Step 3
	encodedIndexes := body1[:len(body1)-vault.NonceSize]
	r1 := body1[len(body1)-vault.NonceSize:]
	k1, err := d.vault.ComputeChallengeKey(encodedIndexes)
	if err != nil {
		return fmt.Errorf("failed to compute challenge key k1: %w", err)
	}
	t1, err := vault.GenerateSessionKey()
	if err != nil {
		return fmt.Errorf("failed to generate partial session key t1: %w", err)
	}
	r2, err := vault.GenerateNonce()
	if err != nil {
		return fmt.Errorf("failed to generate nonce r2: %w", err)
	}
	c2, err := d.vault.GenerateChallenge()
	if err != nil {
		return fmt.Errorf("failed to generate challenge c2: %w", err)
	}
	ciphertext, err := k1.Encrypt(slices.Concat[[]byte](r1, t1, c2, r2), aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt message m3: %w", err)
	}
	m3 := bytes.NewReader(append(ciphertext, aad...))
	body3, err := response(http.Post("http://"+addr+"/auth-proceed", "application/octet-stream", m3))
	if err != nil {
		return err
	}

	// Step 5
	k2, err := d.vault.ComputeChallengeKey(c2)
	if err != nil {
		return fmt.Errorf("failed to compute challenge key k2: %w", err)
	}
	k2t1 := make(vault.Key, vault.KeySize)
	subtle.XORBytes(k2t1, k2, t1)
	m4, err := k2t1.Decrypt(body3, nil)
	if err != nil {
		return fmt.Errorf("failed to decrypt message m4: %w", err)
	}
	r2got := m4[:vault.NonceSize]
	if subtle.ConstantTimeCompare(r2got, r2) == 0 {
		return fmt.Errorf("wrong nonce r2 from server")
	}
	t2 := m4[vault.NonceSize:]
	d.sessionKey = make(vault.SessionKey, vault.SessionKeySize)
	subtle.XORBytes(d.sessionKey, t1, t2)

	d.sessionFrom = time.Now()
	return nil
}

func (d *Device) refreshSessionID() error {
	id := make([]byte, 8)
	if _, err := rand.Read(id); err != nil {
		return err
	}
	d.sessionID = fmt.Sprintf("%x", id)
	return nil
}

func (d *Device) clearSession() {
	d.sessionID = ""
	d.sessionKey = nil
	d.sessionFrom = time.Time{}
	d.sessionHist = []byte{}
}

func response(resp *http.Response, err error) ([]byte, error) {
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	if resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("negative response from server, status is %q", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}
	return body, nil
}
