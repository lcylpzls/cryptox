package cryptox

import (
	"hash"
	"io"

	"github.com/lcylpzls/cryptox/internal/core"
	"github.com/lcylpzls/logx"
)

const (
	Ed25519PublicKeySize  = core.Ed25519PublicKeySize
	Ed25519PrivateKeySize = core.Ed25519PrivateKeySize
	Ed25519SeedSize       = core.Ed25519SeedSize
	Ed25519SignatureSize  = core.Ed25519SignatureSize
)

const (
	OperationSeal          = core.OperationSeal
	OperationOpen          = core.OperationOpen
	OperationEncryptStream = core.OperationEncryptStream
	OperationDecryptStream = core.OperationDecryptStream
	OperationSignHMAC      = core.OperationSignHMAC
	OperationVerifyHMAC    = core.OperationVerifyHMAC
	OperationSignEd25519   = core.OperationSignEd25519
	OperationVerifyEd25519 = core.OperationVerifyEd25519
	OperationDeriveKey     = core.OperationDeriveKey
	OperationRotateKEK     = core.OperationRotateKEK
)

const (
	CodeInvalidKey = core.CodeInvalidKey
)

func EncryptStream(kek []byte, dst io.Writer, src io.Reader) error {
	return core.EncryptStream(kek, dst, src)
}
func EncryptStreamWithAAD(kek []byte, dst io.Writer, src io.Reader, aad []byte) error {
	return core.EncryptStreamWithAAD(kek, dst, src, aad)
}
func DecryptStream(kek []byte, dst io.Writer, src io.Reader) error {
	return core.DecryptStream(kek, dst, src)
}
func DecryptStreamWithAAD(kek []byte, dst io.Writer, src io.Reader, aad []byte) error {
	return core.DecryptStreamWithAAD(kek, dst, src, aad)
}
func AuditFields(operation, algorithm string, size int, err error) logx.FieldGroup {
	return core.AuditFields(operation, algorithm, size, err)
}
func GenerateEd25519Key() (priv, pub []byte, err error) { return core.GenerateEd25519Key() }
func SignEd25519(priv, msg []byte) ([]byte, error)      { return core.SignEd25519(priv, msg) }
func VerifyEd25519(pub, msg, sig []byte) bool           { return core.VerifyEd25519(pub, msg, sig) }
func Ed25519PublicKey(priv []byte) ([]byte, error)      { return core.Ed25519PublicKey(priv) }
func ParseEd25519PublicKeyHex(s string) ([]byte, error) { return core.ParseEd25519PublicKeyHex(s) }
func ParseEd25519PrivateKeyHex(s string) ([]byte, error) {
	return core.ParseEd25519PrivateKeyHex(s)
}
func Argon2ID(password, salt []byte, memory, iterations uint32, parallelism uint8, keyLen uint32) ([]byte, error) {
	return core.Argon2ID(password, salt, memory, iterations, parallelism, keyLen)
}
func HKDF(secret, salt, info []byte, length int) ([]byte, error) {
	return core.HKDF(secret, salt, info, length)
}
func PBKDF2(password, salt []byte, iterations, keyLen int) ([]byte, error) {
	return core.PBKDF2(password, salt, iterations, keyLen)
}
func RandomBytes(n int) ([]byte, error) { return core.RandomBytes(n) }
func Wipe(b []byte)                     { core.Wipe(b) }
func RotateKEK(oldKEK, newKEK, envelope []byte) ([]byte, error) {
	return core.RotateKEK(oldKEK, newKEK, envelope)
}
func NewSHA256() hash.Hash                       { return core.NewSHA256() }
func SHA256(data []byte) []byte                  { return core.SHA256(data) }
func SHA256Hex(r io.Reader) (string, error)      { return core.SHA256Hex(r) }
func Seal(kek, plaintext []byte) ([]byte, error) { return core.Seal(kek, plaintext) }
func SealWithAAD(kek, plaintext, aad []byte) ([]byte, error) {
	return core.SealWithAAD(kek, plaintext, aad)
}
func Open(kek, envelope []byte) ([]byte, error) { return core.Open(kek, envelope) }
func OpenWithAAD(kek, envelope, aad []byte) ([]byte, error) {
	return core.OpenWithAAD(kek, envelope, aad)
}
func SignHMAC(key, msg []byte) ([]byte, error) { return core.SignHMAC(key, msg) }
func VerifyHMAC(key, msg, sig []byte) bool     { return core.VerifyHMAC(key, msg, sig) }
func SignHMACWithHash(hashName string, key, msg []byte) ([]byte, error) {
	return core.SignHMACWithHash(hashName, key, msg)
}
func VerifyHMACWithHash(hashName string, key, msg, sig []byte) bool {
	return core.VerifyHMACWithHash(hashName, key, msg, sig)
}
func ConstantTimeEquals(a, b []byte) bool { return core.ConstantTimeEquals(a, b) }
