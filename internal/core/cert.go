package core

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"time"

	"github.com/lcylpzls/errx"
)

// CertAlgorithm 是自签证书使用的非对称算法。
type CertAlgorithm uint8

const (
	// CertAlgorithmEd25519 使用 Ed25519 签名（默认）。
	CertAlgorithmEd25519 CertAlgorithm = iota
	// CertAlgorithmECDSA 使用 ECDSA P-256 签名。
	CertAlgorithmECDSA
)

// CertOption 修改自签证书生成配置。
type CertOption func(*certOptions)

type certOptions struct {
	algorithm CertAlgorithm
	now       func() time.Time
}

// WithCertAlgorithm 设置自签证书签名算法。
func WithCertAlgorithm(alg CertAlgorithm) CertOption {
	return func(o *certOptions) { o.algorithm = alg }
}

// WithCertClock 注入时间源（测试用）。
func WithCertClock(now func() time.Time) CertOption {
	return func(o *certOptions) {
		if now != nil {
			o.now = now
		}
	}
}

// SelfSignedCert 生成自签 TLS 证书（默认 Ed25519）。
// cn 为证书通用名，dnsNames / ips 为 SAN，days 为有效天数。
func SelfSignedCert(cn string, dnsNames []string, ips []net.IP, days int) (certPEM, keyPEM []byte, err error) {
	return SelfSignedCertWithOptions(cn, dnsNames, ips, days)
}

// SelfSignedCertWithOptions 生成自签 TLS 证书，支持算法与时间源选项。
func SelfSignedCertWithOptions(cn string, dnsNames []string, ips []net.IP, days int, opts ...CertOption) (certPEM, keyPEM []byte, err error) {
	o := &certOptions{algorithm: CertAlgorithmEd25519, now: time.Now}
	for _, opt := range opts {
		if opt != nil {
			opt(o)
		}
	}
	if cn == "" {
		return nil, nil, errx.NewCode(CodeInvalidArgument, "证书通用名不能为空")
	}
	if days <= 0 {
		return nil, nil, errx.NewCode(CodeInvalidArgument, "证书有效天数必须为正数")
	}
	for _, ip := range ips {
		if ip == nil {
			return nil, nil, errx.NewCode(CodeInvalidArgument, "证书 SAN IP 不能为 nil")
		}
	}

	serial := make([]byte, 16)
	if _, err := io.ReadFull(randomReader, serial); err != nil {
		return nil, nil, errx.WrapCode(err, CodeRandomFailed, "生成证书序列号失败")
	}
	now := o.now()
	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetBytes(serial),
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              append([]string(nil), dnsNames...),
		IPAddresses:           append([]net.IP(nil), ips...),
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, days),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	switch o.algorithm {
	case CertAlgorithmECDSA:
		// Go 1.26 起 GenerateKey 忽略注入 reader，恒使用安全随机源；不会失败。
		key, _ := ecdsa.GenerateKey(elliptic.P256(), randomReader)
		template.SignatureAlgorithm = x509.ECDSAWithSHA256
		// 模板与密钥组合已校验，证书创建不会失败。
		der, _ := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		return encodeCertAndKey(der, key)
	case CertAlgorithmEd25519:
		pub, priv, err := ed25519.GenerateKey(randomReader)
		if err != nil {
			return nil, nil, errx.WrapCode(err, CodeRandomFailed, "生成 Ed25519 密钥失败")
		}
		template.SignatureAlgorithm = x509.PureEd25519
		// 模板与密钥组合已校验，证书创建不会失败。
		der, _ := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
		return encodeCertAndKey(der, priv)
	default:
		return nil, nil, errx.NewCode(CodeInvalidArgument, "不支持的证书算法")
	}
}

// encodeCertAndKey 将证书 DER 与私钥编码为 PEM。
func encodeCertAndKey(der []byte, priv any) ([]byte, []byte, error) {
	// 私钥类型已限定为 Ed25519 / ECDSA，PKCS8 编码不会失败。
	keyDER, _ := x509.MarshalPKCS8PrivateKey(priv)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}
