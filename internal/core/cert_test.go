package core

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"

	"github.com/lcylpzls/testx"
)

// TestSelfSignedCertEd25519 覆盖默认 Ed25519 自签证书。
func TestSelfSignedCertEd25519(t *testing.T) {
	now := time.Unix(1700000000, 0)
	certPEM, keyPEM, err := SelfSignedCertWithOptions("localhost",
		[]string{"localhost", "example.com"},
		[]net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		30,
		WithCertClock(func() time.Time { return now }),
	)
	testx.RequireNoError(t, err)
	assertCertAndKey(t, certPEM, keyPEM, x509.PureEd25519, now, 30)

	// 快捷入口与 WithOptions 一致。
	certPEM2, keyPEM2, err := SelfSignedCert("localhost", []string{"localhost"}, nil, 1)
	testx.RequireNoError(t, err)
	assertCertAndKey(t, certPEM2, keyPEM2, x509.PureEd25519, time.Time{}, 1)
}

// TestSelfSignedCertECDSA 覆盖 ECDSA P-256 自签证书。
func TestSelfSignedCertECDSA(t *testing.T) {
	now := time.Unix(1700000000, 0)
	certPEM, keyPEM, err := SelfSignedCertWithOptions("localhost",
		[]string{"localhost"},
		[]net.IP{net.ParseIP("127.0.0.1")},
		365,
		WithCertAlgorithm(CertAlgorithmECDSA),
		WithCertClock(func() time.Time { return now }),
	)
	testx.RequireNoError(t, err)
	assertCertAndKey(t, certPEM, keyPEM, x509.ECDSAWithSHA256, now, 365)
}

// TestSelfSignedCertErrors 覆盖参数与随机源错误分支。
func TestSelfSignedCertErrors(t *testing.T) {
	if _, _, err := SelfSignedCert("", nil, nil, 1); err == nil {
		t.Fatal("空 CN 应报错")
	}
	if _, _, err := SelfSignedCert("x", nil, nil, 0); err == nil {
		t.Fatal("零天数应报错")
	}
	if _, _, err := SelfSignedCert("x", nil, []net.IP{nil}, 1); err == nil {
		t.Fatal("nil IP 应报错")
	}
	if _, _, err := SelfSignedCertWithOptions("x", nil, nil, 1,
		WithCertAlgorithm(CertAlgorithm(99))); err == nil {
		t.Fatal("非法算法应报错")
	}

	t.Run("随机源完全失败", func(t *testing.T) {
		old := randomReader
		randomReader = failingReader{}
		_, _, err := SelfSignedCert("x", nil, nil, 1)
		randomReader = old
		testx.RequireError(t, err)
	})
	t.Run("Ed25519 密钥生成失败", func(t *testing.T) {
		old := randomReader
		randomReader = &seqFailReader{left: 16}
		_, _, err := SelfSignedCert("x", nil, nil, 1)
		randomReader = old
		testx.RequireError(t, err)
	})
}

// assertCertAndKey 校验证书/私钥可加载且字段符合预期。
func assertCertAndKey(t *testing.T, certPEM, keyPEM []byte, sigAlgo x509.SignatureAlgorithm, notBefore time.Time, days int) {
	t.Helper()
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		t.Fatal("证书或私钥为空")
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		t.Fatalf("X509KeyPair 加载失败：%v", err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	testx.RequireNoError(t, err)
	testx.RequireEqual(t, cert.SignatureAlgorithm, sigAlgo)
	testx.RequireTrue(t, cert.IsCA)
	testx.RequireEqual(t, cert.Subject.CommonName, "localhost")
	if !notBefore.IsZero() {
		testx.RequireTrue(t, cert.NotAfter.Sub(cert.NotBefore) == time.Duration(days)*24*time.Hour)
	}
	if len(cert.DNSNames) > 0 && cert.DNSNames[0] != "localhost" {
		t.Fatalf("DNS SAN 不符：%v", cert.DNSNames)
	}
	if len(cert.IPAddresses) > 0 && !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IP SAN 不符：%v", cert.IPAddresses)
	}
}

// seqFailReader 先返回指定字节数的零值，之后返回错误。
type seqFailReader struct {
	left int
}

func (r *seqFailReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, errReaderFail
	}
	n := len(p)
	if n > r.left {
		n = r.left
	}
	for i := 0; i < n; i++ {
		p[i] = 0
	}
	r.left -= n
	return n, nil
}

// errReaderFail 是测试用读取错误。
var errReaderFail = bytes.ErrTooLarge
