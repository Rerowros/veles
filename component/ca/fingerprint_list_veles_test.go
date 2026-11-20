package ca

import (
	"crypto/x509"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// P33: Xray pcs (pinned hashes) and vcn (verify names) are comma-separated lists.
func TestFingerprintVerifierHashList(t *testing.T) {
	zeroHash := strings.Repeat("0", 64)
	leaf := CalculateFingerprint(leafCert.Raw)
	intermediate := CalculateFingerprint(intermediateCert.Raw)
	certs := []*x509.Certificate{leafCert, intermediateCert, rootCert}

	// the second hash is the leaf
	verifier, err := NewFingerprintVerifier(zeroHash+","+leaf, certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(certs, ""))
	assert.NoError(t, verifier(certs, wrongLeafServerName))

	// the second hash is the intermediate: chain is checked against the name
	verifier, err = NewFingerprintVerifier(zeroHash+", "+intermediate, certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(certs, leafServerName))
	assert.Error(t, verifier(certs, wrongLeafServerName))

	// colons and spaces are ignored inside each element
	colon := func(s string) string {
		var parts []string
		for i := 0; i < len(s); i += 2 {
			parts = append(parts, s[i:i+2])
		}
		return strings.Join(parts, ":")
	}
	verifier, err = NewFingerprintVerifier(zeroHash+" , "+colon(leaf), certTime)
	require.NoError(t, err)
	assert.NoError(t, verifier(certs, ""))

	// no hash matches
	verifier, err = NewFingerprintVerifier(zeroHash+","+strings.Repeat("1", 64), certTime)
	require.NoError(t, err)
	assert.ErrorIs(t, verifier(certs, ""), errNotMatch)

	// an invalid element fails the whole list
	for _, fp := range []string{leaf + ",zz", leaf + ",abcd", leaf + ",chrome", ",", ""} {
		_, err := NewFingerprintVerifier(fp, certTime)
		assert.Error(t, err, "fingerprint=%q", fp)
	}
}

// P33: a name-cert-verify list passes if any name matches.
func TestNameCertVerifierNameList(t *testing.T) {
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)
	certs := []*x509.Certificate{leafCert, intermediateCert}

	verify := NewNameCertVerifier("wrong.example.com, "+leafServerName, roots, certTime)
	assert.NoError(t, verify(certs))

	verify = NewNameCertVerifier(wrongLeafServerName+",other.example.com", roots, certTime)
	assert.Error(t, verify(certs))

	verify = NewNameCertVerifier(" , ", roots, certTime)
	assert.Error(t, verify(certs))
}

func TestVerifyAnyName(t *testing.T) {
	var tried []string
	check := func(name string) error {
		tried = append(tried, name)
		if name == "b" {
			return nil
		}
		return errors.New("no match")
	}

	assert.NoError(t, VerifyAnyName("a, b ,c", check))
	assert.Equal(t, []string{"a", "b"}, tried, "stops at the first match")

	tried = nil
	assert.Error(t, VerifyAnyName("a,c", check))
	assert.Equal(t, []string{"a", "c"}, tried)

	tried = nil
	assert.Error(t, VerifyAnyName(" , ", check), "empty list must fail closed")
	assert.Empty(t, tried)
}
