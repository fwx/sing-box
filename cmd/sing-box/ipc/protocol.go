package ipc

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
)

// Message types for Named Pipe protocol
const (
	MsgHandshakeInit     uint32 = 0x01
	MsgHandshakeResponse uint32 = 0x02
	MsgAuthChallenge     uint32 = 0x03
	MsgAuthResponse      uint32 = 0x04
	MsgSendConfig        uint32 = 0x10
	MsgConfigAck         uint32 = 0x11
	MsgGetStats          uint32 = 0x20
	MsgStatsResponse     uint32 = 0x21
	MsgStop              uint32 = 0x30
	MsgStopAck           uint32 = 0x31
	MsgError             uint32 = 0xFF
)

const (
	// MaxMessageSize is the maximum allowed message size (1 MB)
	MaxMessageSize = 1024 * 1024
	// HeaderSize is the size of message header (length + type)
	HeaderSize = 8
)

// Message represents a protocol message
type Message struct {
	Type    uint32
	Payload []byte
}

// StatsResponse represents the statistics response payload
type StatsResponse struct {
	Memory        uint64 `json:"memory"`
	UploadTotal   uint64 `json:"uploadTotal"`
	DownloadTotal uint64 `json:"downloadTotal"`
}

// ErrorResponse represents an error response payload
type ErrorResponse struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ConfigAckResponse represents the config acknowledgment payload
type ConfigAckResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

// WriteMessage writes a message to the writer
// Wire format: [Length: 4 bytes LE][Type: 4 bytes LE][Payload: N bytes]
func WriteMessage(w io.Writer, msg *Message) error {
	// Length = type (4 bytes) + payload length
	length := uint32(4 + len(msg.Payload))

	// Write length (little-endian)
	if err := binary.Write(w, binary.LittleEndian, length); err != nil {
		return err
	}

	// Write type (little-endian)
	if err := binary.Write(w, binary.LittleEndian, msg.Type); err != nil {
		return err
	}

	// Write payload
	if len(msg.Payload) > 0 {
		if _, err := w.Write(msg.Payload); err != nil {
			return err
		}
	}

	return nil
}

// ReadMessage reads a message from the reader
func ReadMessage(r io.Reader) (*Message, error) {
	// Read length
	var length uint32
	if err := binary.Read(r, binary.LittleEndian, &length); err != nil {
		return nil, err
	}

	// Validate length
	if length < 4 {
		return nil, errors.New("message too short")
	}
	if length > MaxMessageSize {
		return nil, errors.New("message too large")
	}

	// Read type
	var msgType uint32
	if err := binary.Read(r, binary.LittleEndian, &msgType); err != nil {
		return nil, err
	}

	// Read payload
	payloadLen := length - 4
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, err
		}
	}

	return &Message{
		Type:    msgType,
		Payload: payload,
	}, nil
}

// NewHandshakeInitMessage creates a HANDSHAKE_INIT message with DH public key
func NewHandshakeInitMessage(publicKey []byte) *Message {
	return &Message{
		Type:    MsgHandshakeInit,
		Payload: publicKey,
	}
}

// NewHandshakeResponseMessage creates a HANDSHAKE_RESPONSE message with DH public key
func NewHandshakeResponseMessage(publicKey []byte) *Message {
	return &Message{
		Type:    MsgHandshakeResponse,
		Payload: publicKey,
	}
}

// NewAuthChallengeMessage creates an AUTH_CHALLENGE message with nonce
func NewAuthChallengeMessage(nonce []byte) *Message {
	return &Message{
		Type:    MsgAuthChallenge,
		Payload: nonce,
	}
}

// NewAuthResponseMessage creates an AUTH_RESPONSE message with HMAC
func NewAuthResponseMessage(hmacResponse []byte) *Message {
	return &Message{
		Type:    MsgAuthResponse,
		Payload: hmacResponse,
	}
}

// NewAuthResponseWithChallengeMessage creates an AUTH_RESPONSE message with HMAC + new challenge nonce
func NewAuthResponseWithChallengeMessage(hmacResponse, challengeNonce []byte) *Message {
	payload := make([]byte, len(hmacResponse)+len(challengeNonce))
	copy(payload[:len(hmacResponse)], hmacResponse)
	copy(payload[len(hmacResponse):], challengeNonce)
	return &Message{
		Type:    MsgAuthResponse,
		Payload: payload,
	}
}

// NewSendConfigMessage creates a SEND_CONFIG message with encrypted config
func NewSendConfigMessage(encryptedConfig []byte) *Message {
	return &Message{
		Type:    MsgSendConfig,
		Payload: encryptedConfig,
	}
}

// NewConfigAckMessage creates a CONFIG_ACK message
func NewConfigAckMessage(success bool, errorMsg string) *Message {
	ack := ConfigAckResponse{
		Success: success,
		Error:   errorMsg,
	}
	payload, _ := json.Marshal(ack)
	return &Message{
		Type:    MsgConfigAck,
		Payload: payload,
	}
}

// NewGetStatsMessage creates a GET_STATS message
func NewGetStatsMessage() *Message {
	return &Message{
		Type:    MsgGetStats,
		Payload: nil,
	}
}

// NewStatsResponseMessage creates a STATS_RESPONSE message
func NewStatsResponseMessage(stats *StatsResponse) *Message {
	payload, _ := json.Marshal(stats)
	return &Message{
		Type:    MsgStatsResponse,
		Payload: payload,
	}
}

// NewStopMessage creates a STOP message
func NewStopMessage() *Message {
	return &Message{
		Type:    MsgStop,
		Payload: nil,
	}
}

// NewStopAckMessage creates a STOP_ACK message
func NewStopAckMessage() *Message {
	return &Message{
		Type:    MsgStopAck,
		Payload: nil,
	}
}

// NewErrorMessage creates an ERROR message
func NewErrorMessage(code int, message string) *Message {
	errResp := ErrorResponse{
		Code:    code,
		Message: message,
	}
	payload, _ := json.Marshal(errResp)
	return &Message{
		Type:    MsgError,
		Payload: payload,
	}
}

// ParseStatsResponse parses a STATS_RESPONSE payload
func ParseStatsResponse(payload []byte) (*StatsResponse, error) {
	var stats StatsResponse
	if err := json.Unmarshal(payload, &stats); err != nil {
		return nil, err
	}
	return &stats, nil
}

// ParseConfigAckResponse parses a CONFIG_ACK payload
func ParseConfigAckResponse(payload []byte) (*ConfigAckResponse, error) {
	var ack ConfigAckResponse
	if err := json.Unmarshal(payload, &ack); err != nil {
		return nil, err
	}
	return &ack, nil
}

// ParseErrorResponse parses an ERROR payload
func ParseErrorResponse(payload []byte) (*ErrorResponse, error) {
	var errResp ErrorResponse
	if err := json.Unmarshal(payload, &errResp); err != nil {
		return nil, err
	}
	return &errResp, nil
}

// MessageTypeName returns a human-readable name for the message type
func MessageTypeName(msgType uint32) string {
	switch msgType {
	case MsgHandshakeInit:
		return "HANDSHAKE_INIT"
	case MsgHandshakeResponse:
		return "HANDSHAKE_RESPONSE"
	case MsgAuthChallenge:
		return "AUTH_CHALLENGE"
	case MsgAuthResponse:
		return "AUTH_RESPONSE"
	case MsgSendConfig:
		return "SEND_CONFIG"
	case MsgConfigAck:
		return "CONFIG_ACK"
	case MsgGetStats:
		return "GET_STATS"
	case MsgStatsResponse:
		return "STATS_RESPONSE"
	case MsgStop:
		return "STOP"
	case MsgStopAck:
		return "STOP_ACK"
	case MsgError:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}
