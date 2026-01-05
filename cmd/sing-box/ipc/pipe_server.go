package ipc

import (
	"context"
	"errors"
	"io"
	"net"
	"runtime"
	"sync"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

// PipeServer manages the Named Pipe IPC server
type PipeServer struct {
	ctx      context.Context
	cancel   context.CancelFunc
	listener net.Listener
	logger   log.ContextLogger

	boxMutex     sync.RWMutex
	box          *box.Box
	boxCancel    context.CancelFunc
	statsTracker *StatsTracker

	crypto        *KeyExchange
	authenticated bool
	connMutex     sync.Mutex
	activeConn    net.Conn
}

// NewPipeServer creates a new pipe server instance
func NewPipeServer(ctx context.Context, logger log.ContextLogger) (*PipeServer, error) {
	if !isPipeSupported() {
		return nil, errors.New("Named Pipe IPC is not supported on this platform")
	}

	serverCtx, cancel := context.WithCancel(ctx)
	return &PipeServer{
		ctx:    serverCtx,
		cancel: cancel,
		logger: logger,
	}, nil
}

// Start starts the pipe server and blocks until shutdown
func (s *PipeServer) Start() error {
	listener, err := createPipeListener()
	if err != nil {
		return err
	}
	s.listener = listener

	s.logger.Info("IPC pipe server started on ", PipeName)

	// Accept connections in a loop
	for {
		select {
		case <-s.ctx.Done():
			s.logger.Info("IPC pipe server shutting down")
			return nil
		default:
		}

		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				s.logger.Error("failed to accept connection: ", err)
				continue
			}
		}

		// Handle one connection at a time
		s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (s *PipeServer) handleConnection(conn net.Conn) {
	s.connMutex.Lock()
	// Close previous connection if exists
	if s.activeConn != nil {
		s.activeConn.Close()
	}
	s.activeConn = conn
	s.authenticated = false
	s.connMutex.Unlock()

	defer func() {
		conn.Close()
		s.connMutex.Lock()
		if s.activeConn == conn {
			s.activeConn = nil
		}
		s.connMutex.Unlock()
	}()

	s.logger.Info("client connected")

	// Perform handshake first
	if err := s.performHandshake(conn); err != nil {
		s.logger.Error("handshake failed: ", err)
		return
	}

	s.logger.Info("client authenticated successfully")
	s.authenticated = true

	// Main message loop
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		msg, err := ReadMessage(conn)
		if err != nil {
			if err == io.EOF {
				s.logger.Info("client disconnected")
			} else {
				s.logger.Error("failed to read message: ", err)
			}
			return
		}

		s.logger.Debug("received message: ", MessageTypeName(msg.Type))

		response, err := s.handleCommand(conn, msg)
		if err != nil {
			s.logger.Error("failed to handle command: ", err)
			errMsg := NewErrorMessage(1, err.Error())
			WriteMessage(conn, errMsg)
			continue
		}

		if response != nil {
			if err := WriteMessage(conn, response); err != nil {
				s.logger.Error("failed to send response: ", err)
				return
			}
		}
	}
}

// performHandshake performs DH key exchange and mutual authentication
func (s *PipeServer) performHandshake(conn net.Conn) error {
	// Step 1: Wait for HANDSHAKE_INIT from client
	msg, err := ReadMessage(conn)
	if err != nil {
		return err
	}

	if msg.Type != MsgHandshakeInit {
		return errors.New("expected HANDSHAKE_INIT message")
	}

	clientPublicKey := msg.Payload
	if len(clientPublicKey) != DHPublicKeySize {
		return errors.New("invalid client public key size")
	}

	// Step 2: Generate our keypair and compute shared secret
	s.crypto, err = NewKeyExchange()
	if err != nil {
		return err
	}

	if err := s.crypto.ComputeSharedSecret(clientPublicKey); err != nil {
		return err
	}

	if err := s.crypto.DeriveKeys(); err != nil {
		return err
	}

	// Step 3: Send HANDSHAKE_RESPONSE with our public key
	responseMsg := NewHandshakeResponseMessage(s.crypto.GetPublicKey())
	if err := WriteMessage(conn, responseMsg); err != nil {
		return err
	}

	// Step 4: Generate and send AUTH_CHALLENGE
	serverNonce, err := GenerateNonce()
	if err != nil {
		return err
	}

	challengeMsg := NewAuthChallengeMessage(serverNonce)
	if err := WriteMessage(conn, challengeMsg); err != nil {
		return err
	}

	// Step 5: Wait for AUTH_RESPONSE + AUTH_CHALLENGE from client
	msg, err = ReadMessage(conn)
	if err != nil {
		return err
	}

	if msg.Type != MsgAuthResponse {
		return errors.New("expected AUTH_RESPONSE message")
	}

	// Payload should be: HMAC (32 bytes) + client nonce (32 bytes)
	if len(msg.Payload) != HMACKeySize+NonceSize {
		return errors.New("invalid AUTH_RESPONSE payload size")
	}

	clientHMAC := msg.Payload[:HMACKeySize]
	clientNonce := msg.Payload[HMACKeySize:]

	// Verify client's HMAC
	if !s.crypto.VerifyHMAC(serverNonce, clientHMAC) {
		return errors.New("client authentication failed: invalid HMAC")
	}

	// Step 6: Send our AUTH_RESPONSE
	serverHMAC := s.crypto.ComputeHMAC(clientNonce)
	authResponseMsg := NewAuthResponseMessage(serverHMAC)
	if err := WriteMessage(conn, authResponseMsg); err != nil {
		return err
	}

	return nil
}

// handleCommand handles an incoming command message
func (s *PipeServer) handleCommand(conn net.Conn, msg *Message) (*Message, error) {
	switch msg.Type {
	case MsgSendConfig:
		return s.handleSendConfig(msg.Payload)
	case MsgGetStats:
		return s.handleGetStats()
	case MsgStop:
		return s.handleStop()
	default:
		return NewErrorMessage(2, "unknown command"), nil
	}
}

// handleSendConfig handles the SEND_CONFIG command
func (s *PipeServer) handleSendConfig(payload []byte) (*Message, error) {
	// Decrypt the config
	configJSON, err := s.crypto.Decrypt(payload)
	if err != nil {
		return NewConfigAckMessage(false, "decryption failed: "+err.Error()), nil
	}

	// Parse the config with context (required for DNS transport registry)
	options, err := json.UnmarshalExtendedContext[option.Options](s.ctx, configJSON)
	if err != nil {
		return NewConfigAckMessage(false, "invalid config JSON: "+err.Error()), nil
	}

	// Stop existing box if running
	s.boxMutex.Lock()
	if s.box != nil {
		s.logger.Info("stopping existing VPN instance")
		s.box.Close()
		if s.boxCancel != nil {
			s.boxCancel()
		}
		s.box = nil
		s.boxCancel = nil
		s.statsTracker = nil
	}
	s.boxMutex.Unlock()

	// Create new box
	boxCtx, boxCancel := context.WithCancel(s.ctx)
	instance, err := box.New(box.Options{
		Context: boxCtx,
		Options: options,
	})
	if err != nil {
		boxCancel()
		return NewConfigAckMessage(false, "failed to create service: "+err.Error()), nil
	}

	// Create and register stats tracker before starting
	statsTracker := NewStatsTracker()
	instance.Router().AppendTracker(statsTracker)

	// Start the box
	if err := instance.Start(); err != nil {
		boxCancel()
		instance.Close()
		return NewConfigAckMessage(false, "failed to start service: "+err.Error()), nil
	}

	s.boxMutex.Lock()
	s.box = instance
	s.boxCancel = boxCancel
	s.statsTracker = statsTracker
	s.boxMutex.Unlock()

	s.logger.Info("VPN service started successfully")
	return NewConfigAckMessage(true, ""), nil
}

// handleGetStats handles the GET_STATS command
func (s *PipeServer) handleGetStats() (*Message, error) {
	s.boxMutex.RLock()
	defer s.boxMutex.RUnlock()

	stats := &StatsResponse{
		Memory:        0,
		UploadTotal:   0,
		DownloadTotal: 0,
	}

	// Get memory stats
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	stats.Memory = m.Alloc

	// Get traffic stats from our tracker
	if s.statsTracker != nil {
		upload, download := s.statsTracker.Total()
		stats.UploadTotal = uint64(upload)
		stats.DownloadTotal = uint64(download)
	}

	// Encrypt the response
	responseJSON, err := json.Marshal(stats)
	if err != nil {
		return nil, err
	}

	encryptedResponse, err := s.crypto.Encrypt(responseJSON)
	if err != nil {
		return nil, err
	}

	return &Message{
		Type:    MsgStatsResponse,
		Payload: encryptedResponse,
	}, nil
}

// handleStop handles the STOP command
func (s *PipeServer) handleStop() (*Message, error) {
	s.boxMutex.Lock()
	if s.box != nil {
		s.logger.Info("stopping VPN service")
		s.box.Close()
		if s.boxCancel != nil {
			s.boxCancel()
		}
		s.box = nil
		s.boxCancel = nil
		s.statsTracker = nil
	}
	s.boxMutex.Unlock()

	// Schedule server shutdown
	go func() {
		s.cancel()
	}()

	return NewStopAckMessage(), nil
}

// Stop gracefully stops the pipe server
func (s *PipeServer) Stop() error {
	s.cancel()

	if s.listener != nil {
		s.listener.Close()
	}

	s.boxMutex.Lock()
	if s.box != nil {
		s.box.Close()
		if s.boxCancel != nil {
			s.boxCancel()
		}
		s.statsTracker = nil
	}
	s.boxMutex.Unlock()

	return nil
}

// IsRunning returns true if the VPN box is running
func (s *PipeServer) IsRunning() bool {
	s.boxMutex.RLock()
	defer s.boxMutex.RUnlock()
	return s.box != nil
}
