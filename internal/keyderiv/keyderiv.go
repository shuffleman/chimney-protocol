// Package keyderiv 实现基于 HKDF 的密钥派生（Part II §8 和 §9）。
//
// 认证密钥：
//
//	K_auth = HKDF(PSK, label="chimney-auth", info = ServerRandom)
//
// 会话密钥：
//
//	K_sess = HKDF(PSK, label="chimney-sess", info = ServerRandom || ClientRandom)
//
// 当前认证标签：
//
//	tag = HMAC(K_auth, ServerRandom || ClientRandom)[:TAG_LEN]
//
// 底层辅助函数中参数仍名为 recordBytes 是为了兼容旧测试和原始设计，
// 但当前客户端和中继路径都将 ClientRandom 作为 HMAC 的第二个输入。
package keyderiv

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	// LabelAuth 是认证密钥的 HKDF 标签。
	LabelAuth = "chimney-auth"

	// LabelSess 是会话密钥的 HKDF 标签。
	LabelSess = "chimney-sess"

	// DefaultTagLen 是默认认证标签长度（字节）。
	// 规范建议 8-16 字节；我们用 16 以确保强安全性。
	DefaultTagLen = 16

	// DefaultKeyLen 是默认派生密钥长度（32 字节 = 256 位）。
	DefaultKeyLen = 32

	// DefaultNonceBaseLen 是默认 nonce 基长度（GCM/ChaCha20 为 12 字节）。
	DefaultNonceBaseLen = 12
)

// Deriver 持有 PSK 并提供密钥派生方法。
type Deriver struct {
	psk []byte
}

// NewDeriver 从 PSK 创建一个新的密钥派生器。
func NewDeriver(psk []byte) *Deriver {
	pskCopy := make([]byte, len(psk))
	copy(pskCopy, psk)
	return &Deriver{psk: pskCopy}
}

// NewDeriverFromHex 从 hex 编码的 PSK 字符串创建密钥派生器。
func NewDeriverFromHex(pskHex string) (*Deriver, error) {
	psk, err := hex.DecodeString(pskHex)
	if err != nil {
		return nil, fmt.Errorf("keyderiv: invalid PSK hex: %w", err)
	}
	if len(psk) != DefaultKeyLen {
		return nil, fmt.Errorf("keyderiv: invalid PSK length: got %d bytes, want %d", len(psk), DefaultKeyLen)
	}
	return NewDeriver(psk), nil
}

// GeneratePSK 生成指定长度的随机 PSK。
func GeneratePSK(length int) ([]byte, error) {
	psk := make([]byte, length)
	if _, err := io.ReadFull(rand.Reader, psk); err != nil {
		return nil, fmt.Errorf("keyderiv: failed to generate PSK: %w", err)
	}
	return psk, nil
}

// deriveKey 使用 HKDF-SHA256 派生密钥。
func (d *Deriver) deriveKey(label string, info []byte, keyLen int) ([]byte, error) {
	hkdfReader := hkdf.New(sha256.New, d.psk, []byte(label), info)
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, fmt.Errorf("keyderiv: HKDF extract failed for label %q: %w", label, err)
	}
	return key, nil
}

// DeriveAuthKey 派生 K_auth = HKDF(PSK, label="chimney-auth", info=ServerRandom)。
//
// ServerRandom 来自 TLS ServerHello.random 字段，32 字节。
func (d *Deriver) DeriveAuthKey(serverRandom []byte) ([]byte, error) {
	if len(serverRandom) != 32 {
		return nil, fmt.Errorf("keyderiv: ServerRandom must be 32 bytes, got %d", len(serverRandom))
	}
	return d.deriveKey(LabelAuth, serverRandom, DefaultKeyLen)
}

// DeriveSessionKey 派生 K_sess = HKDF(PSK, label="chimney-sess", info=ServerRandom||ClientRandom)。
//
// ServerRandom 和 ClientRandom 各 32 字节。
func (d *Deriver) DeriveSessionKey(serverRandom, clientRandom []byte) ([]byte, error) {
	if len(serverRandom) != 32 {
		return nil, fmt.Errorf("keyderiv: ServerRandom must be 32 bytes, got %d", len(serverRandom))
	}
	if len(clientRandom) != 32 {
		return nil, fmt.Errorf("keyderiv: ClientRandom must be 32 bytes, got %d", len(clientRandom))
	}
	info := make([]byte, 64)
	copy(info, serverRandom)
	copy(info[32:], clientRandom)
	return d.deriveKey(LabelSess, info, DefaultKeyLen)
}

// DeriveNonceBase 从会话密钥材料派生 AEAD 的 nonce 基。
// 使用 HKDF 加独立标签以确保与加密密钥分离。
func (d *Deriver) DeriveNonceBase(serverRandom, clientRandom []byte) ([]byte, error) {
	info := make([]byte, 64)
	copy(info, serverRandom)
	copy(info[32:], clientRandom)
	return d.deriveKey("chimney-nonce", info, DefaultNonceBaseLen)
}

// DeriveDirectionalKeys 为客户端-中继通信派生独立的发送和接收密钥。
//
// 客户端→中继：label="chimney-sess-send"
// 中继→客户端：label="chimney-sess-recv"
func (d *Deriver) DeriveDirectionalKeys(serverRandom, clientRandom []byte) (sendKey, recvKey []byte, err error) {
	if len(serverRandom) != 32 || len(clientRandom) != 32 {
		return nil, nil, fmt.Errorf("keyderiv: randoms must be 32 bytes each")
	}
	info := make([]byte, 64)
	copy(info, serverRandom)
	copy(info[32:], clientRandom)

	sendKey, err = d.deriveKey("chimney-sess-send", info, DefaultKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("keyderiv: failed to derive send key: %w", err)
	}

	recvKey, err = d.deriveKey("chimney-sess-recv", info, DefaultKeyLen)
	if err != nil {
		return nil, nil, fmt.Errorf("keyderiv: failed to derive recv key: %w", err)
	}

	return sendKey, recvKey, nil
}

// AuthTag 计算调用者提供的上下文字节的认证标签：
//
//	tag = HMAC-SHA256(K_auth, ServerRandom || recordBytes)[:tagLen]
//
// K_auth 从 PSK 和 ServerRandom 内部派生。
// 在当前协议实现中，recordBytes 是 ClientRandom。旧测试和
// 辅助函数仍使用这个通用名称，因为最初的设计使用可观测的
// TLS 记录字节作为 HMAC 的第二个输入。
func (d *Deriver) AuthTag(serverRandom, recordBytes []byte, tagLen int) ([]byte, error) {
	kAuth, err := d.DeriveAuthKey(serverRandom)
	if err != nil {
		return nil, fmt.Errorf("keyderiv: failed to derive auth key: %w", err)
	}

	mac := hmac.New(sha256.New, kAuth)
	mac.Write(serverRandom)
	mac.Write(recordBytes)
	tag := mac.Sum(nil)

	if tagLen > len(tag) {
		tagLen = len(tag)
	}
	return tag[:tagLen], nil
}

// VerifyAuthTag 验证认证标签是否与期望值匹配。
// 使用常量时间比较以防止时序攻击。
func (d *Deriver) VerifyAuthTag(serverRandom, recordBytes, tag []byte) (bool, error) {
	expected, err := d.AuthTag(serverRandom, recordBytes, len(tag))
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, tag), nil
}

// ComputeKeyHint 返回从用户标识符派生的 4 字节提示。
// 提示为 SHA256(userID)[:4]，中继用它来查找
// 多用户认证的正确 PSK。
func ComputeKeyHint(userID string) [4]byte {
	h := sha256.Sum256([]byte(userID))
	var hint [4]byte
	copy(hint[:], h[:4])
	return hint
}
