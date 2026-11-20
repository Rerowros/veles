package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/metacubex/tls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// freshChainVeles returns a leaf, intermediate and root valid now, because GetTLSConfig
// verifies with ntp.Now and the fixture certificates of fingerprint_test.go are from 2023.
func freshChainVeles(t *testing.T, leafName string) (leaf, intermediate, root *x509.Certificate) {
	t.Helper()
	now := time.Now()
	issue := func(tmpl *x509.Certificate, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl.NotBefore = now.Add(-time.Hour)
		tmpl.NotAfter = now.Add(time.Hour)
		if parent == nil {
			parent, parentKey = tmpl, key
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, parentKey)
		require.NoError(t, err)
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert, key
	}
	root, rootKey := issue(&x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Veles test root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	intermediate, intermediateKey := issue(&x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Veles test intermediate"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}, root, rootKey)
	leaf, _ = issue(&x509.Certificate{
		SerialNumber: big.NewInt(3), Subject: pkix.Name{CommonName: leafName}, DNSNames: []string{leafName},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, intermediate, intermediateKey)
	return leaf, intermediate, root
}

// P33: pinning an intermediate (pcs) together with a name-cert-verify list (vcn):
// the chain is checked against each name, any one may match.
func TestVelesGetTLSConfigFingerprintWithNameList(t *testing.T) {
	const leafName = "leaf.test.example"
	leaf, intermediate, root := freshChainVeles(t, leafName)
	state := tls.ConnectionState{
		ServerName:       "sni.test.example",
		PeerCertificates: []*x509.Certificate{leaf, intermediate, root},
	}

	cfg, err := GetTLSConfig(Option{
		Fingerprint:    CalculateFingerprint(intermediate.Raw),
		NameCertVerify: "wrong.example.com," + leafName,
	})
	require.NoError(t, err)
	require.NotNil(t, cfg.VerifyConnection)
	assert.NoError(t, cfg.VerifyConnection(state))

	cfg, err = GetTLSConfig(Option{
		Fingerprint:    CalculateFingerprint(intermediate.Raw),
		NameCertVerify: "wrong.example.com,other.example.com",
	})
	require.NoError(t, err)
	assert.Error(t, cfg.VerifyConnection(state))
}
