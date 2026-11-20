package ca

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"time"
)

// NewFingerprintVerifier returns a function that verifies whether a certificate's SHA-256 fingerprint matches one of the given ones.
// P33: fingerprint may be several comma-separated hashes (Xray pcs); the certificate matches if any of them does.
func NewFingerprintVerifier(fingerprint string, time func() time.Time) (func(certs []*x509.Certificate, serverName string) error, error) {
	var fpBytes [][]byte
	for _, item := range strings.Split(fingerprint, ",") {
		item = strings.TrimSpace(item)
		switch item {
		case "chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized": // WTF???
			return nil, fmt.Errorf("`fingerprint` is used for TLS certificate pinning. If you need to specify the browser fingerprint, use `client-fingerprint`")
		}
		item = strings.TrimSpace(strings.Replace(item, ":", "", -1))
		if item == "" {
			continue
		}
		fpByte, err := hex.DecodeString(item)
		if err != nil {
			return nil, fmt.Errorf("fingerprint string decode error: %w", err)
		}

		if len(fpByte) != 32 {
			return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
		}
		fpBytes = append(fpBytes, fpByte)
	}
	if len(fpBytes) == 0 {
		return nil, fmt.Errorf("fingerprint string length error,need sha256 fingerprint")
	}

	return func(certs []*x509.Certificate, serverName string) error {
		// ssl pining
		for i, cert := range certs {
			hash := sha256.Sum256(cert.Raw)
			if slices.ContainsFunc(fpBytes, func(fpByte []byte) bool { return bytes.Equal(fpByte, hash[:]) }) {
				if i > 0 {
					// When the fingerprint matches a non-leaf certificate,
					// the certificate chain validity is verified using the certificate as the trusted root certificate.
					opts := x509.VerifyOptions{
						Roots:         x509.NewCertPool(),
						Intermediates: x509.NewCertPool(),
						DNSName:       serverName,
					}
					if time != nil {
						opts.CurrentTime = time()
					}
					opts.Roots.AddCert(certs[i])
					for _, cert := range certs[1 : i+1] { // stop at i
						opts.Intermediates.AddCert(cert)
					}
					_, err := certs[0].Verify(opts)
					return err
				}
				return nil
			}
		}
		return errNotMatch
	}, nil
}

// CalculateFingerprint computes the SHA-256 fingerprint of the given DER-encoded certificate and returns it as a hex string.
func CalculateFingerprint(certDER []byte) string {
	hash := sha256.Sum256(certDER)
	return hex.EncodeToString(hash[:])
}
