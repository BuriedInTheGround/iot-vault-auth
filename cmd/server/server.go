package main

import (
	"crypto/subtle"
	"flag"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/BuriedInTheGround/iot-vault-auth/internal/tui"
	"github.com/BuriedInTheGround/iot-vault-auth/internal/vault"
)

func main() {
	tui.ProgramName = "server"
	flag.Parse()

	if len(flag.Args()) < 1 {
		tui.Errorf("missing vault file paths")
	}

	srv := NewServer()

	for _, path := range flag.Args() {
		_, name := filepath.Split(path)
		id := strings.Split(name, ".")[0]
		v, err := vault.NewVaultFromFile(path)
		if err != nil {
			tui.Errorf("failed to read initial vault for device %q: %v", id, err)
		}
		srv.vaults.Store(id, v)
	}

	if err := srv.Start(); err != nil {
		tui.Errorf("failed to start server: %v", err)
	}
}

type Session struct {
	id   []byte
	r1   vault.Nonce
	k1   vault.Key
	key  vault.SessionKey
	from time.Time
	hist []byte
}

type Server struct {
	vaults   sync.Map // map[string]vault.Vault
	sessions sync.Map // map[string]Session
}

func NewServer() *Server {
	return &Server{}
}

func (s *Server) Start() error {
	http.HandleFunc("/auth-request", s.AuthRequestHandler)
	http.HandleFunc("/auth-proceed", s.AuthProceedHandler)
	http.HandleFunc("/report", s.ReportHandler)
	return http.ListenAndServe(":8177", nil)
}

func (s *Server) ReportHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		w.WriteHeader(http.StatusNotImplemented)
	case http.MethodPost:
		x, err := io.ReadAll(r.Body)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		m1 := x[len(x)-3-16:]
		deviceID := string(m1[:3])
		session, ok := s.sessions.Load(deviceID)
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			tui.Warningf("report: session not found for %q", deviceID)
			return
		}
		u, err := session.(Session).key.Decrypt(x[:len(x)-3-16], m1)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			tui.Warningf("report: failed to decrypt message from %q: %v", deviceID, err)
			return
		}
		sessionID := m1[3:]
		if subtle.ConstantTimeCompare(sessionID, session.(Session).id) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			tui.Warningf("report: wrong session id from %q", deviceID)
			return
		}
		if time.Since(session.(Session).from) > vault.SessionDuration {
			deviceVault, ok := s.vaults.Load(deviceID)
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				tui.Warningf("report: vault not found for %q", deviceID)
				return
			}
			hist := session.(Session).hist
			if err := deviceVault.(vault.Vault).Rotate(hist); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				tui.Warningf("report: failed to rotate vault for %q: %v", deviceID, err)
				return
			}
			s.vaults.Store(deviceID, deviceVault.(vault.Vault))
			s.sessions.Delete(deviceID)
			tui.Infof("report: secure vault rotated and session shred for %q", deviceID)
			w.WriteHeader(http.StatusBadRequest)
			tui.Warningf("report: session is expired for %q", deviceID)
			return
		}
		tui.Infof("report: received report from %q: %q", deviceID, u)
		hist := append(session.(Session).hist, u...)
		s.sessions.Store(deviceID, Session{
			id:   sessionID,
			key:  session.(Session).key,
			from: session.(Session).from,
			hist: hist,
		})
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusBadRequest)
	}
}

func (s *Server) AuthRequestHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Step 2
	m1, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	deviceID := string(m1[:3])
	sessionID := m1[3:]
	deviceVault, ok := s.vaults.Load(deviceID)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-request: failed to verify device id %q", deviceID)
		return
	}
	if session, ok := s.sessions.Load(deviceID); ok {
		if time.Since(session.(Session).from) > vault.SessionDuration {
			hist := session.(Session).hist
			if err := deviceVault.(vault.Vault).Rotate(hist); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				tui.Warningf("auth-request: failed to rotate vault for %q: %v", deviceID, err)
				return
			}
			s.vaults.Store(deviceID, deviceVault.(vault.Vault))
			s.sessions.Delete(deviceID)
			tui.Infof("auth-request: secure vault rotated and session shred for %q", deviceID)
		}
	}
	r1, err := vault.GenerateNonce()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-request: failed to generate nonce r1 for %q: %v", deviceID, err)
		return
	}
	c1, err := deviceVault.(vault.Vault).GenerateChallenge()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-request: failed to generate challenge c1 for %q: %v", deviceID, err)
		return
	}
	m2 := append(c1, r1...)
	w.Header().Add("Content-Type", "application/octet-stream")
	if _, err := w.Write(m2); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-request: failed to write message m2 for %q: %v", deviceID, err)
		return
	}

	// Precompute k1 to relieve AuthRequestHandler
	k1, err := deviceVault.(vault.Vault).ComputeChallengeKey(c1)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-request: failed to compute challenge key k1 for %q: %v", deviceID, err)
		return
	}

	// Device session binding
	s.sessions.Store(deviceID, Session{
		id: sessionID,
		r1: r1,
		k1: k1,
	})
}

func (s *Server) AuthProceedHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Step 4
	m3, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	m1 := m3[len(m3)-3-16:]
	deviceID := string(m1[:3])
	session, ok := s.sessions.Load(deviceID)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-proceed: session not found for %q", deviceID)
		return
	}
	if !session.(Session).from.IsZero() {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-proceed: session already ongoing for %q", deviceID)
		return
	}
	k1 := session.(Session).k1
	plaintext, err := k1.Decrypt(m3[:len(m3)-3-16], m1)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-proceed: failed to decrypt message m3 from %q: %v", deviceID, err)
		return
	}
	sessionID := m1[3:]
	if subtle.ConstantTimeCompare(sessionID, session.(Session).id) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-proceed: wrong session id from %q", deviceID)
		return
	}
	r1got := plaintext[:vault.NonceSize]
	if subtle.ConstantTimeCompare(r1got, session.(Session).r1) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-proceed: wrong nonce r1 from %q", deviceID)
		return
	}
	t1 := plaintext[vault.NonceSize : vault.NonceSize+vault.SessionKeySize]
	c2 := plaintext[vault.NonceSize+vault.SessionKeySize : len(plaintext)-vault.NonceSize]
	r2 := plaintext[len(plaintext)-vault.NonceSize:]
	deviceVault, ok := s.vaults.Load(deviceID)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		tui.Warningf("auth-proceed: vault not found for %q", deviceID)
		return
	}
	k2, err := deviceVault.(vault.Vault).ComputeChallengeKey(c2)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-proceed: failed to compute challenge key k2 for %q: %v", deviceID, err)
		return
	}
	t2, err := vault.GenerateSessionKey()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-proceed: failed to generate partial session key t2 for %q: %v", deviceID, err)
		return
	}
	t := make(vault.SessionKey, vault.SessionKeySize)
	subtle.XORBytes(t, t1, t2)
	k2t1 := make(vault.Key, vault.KeySize)
	subtle.XORBytes(k2t1, k2, t1)
	m4, err := k2t1.Encrypt(append(r2, t2...), nil)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-proceed: failed to encrypt message m4 for %q: %v", deviceID, err)
		return
	}
	if _, err := w.Write(m4); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		tui.Warningf("auth-proceed: failed to write message m4 for %q: %v", deviceID, err)
		return
	}

	// Finalize session
	s.sessions.Store(deviceID, Session{
		id:   sessionID,
		key:  t,
		from: time.Now(),
	})
	tui.Infof("auth-proceed: authenticated with %q", deviceID)
}
