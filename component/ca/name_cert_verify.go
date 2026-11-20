package ca

import (
	"crypto/x509"
	"errors"
	"strings"
	"time"
)

// NewNameCertVerifier returns a verifier for a certificate chain and an explicit DNSName.
// P33: dnsName may be several comma-separated names (Xray vcn); the chain matches if any of them does.
func NewNameCertVerifier(dnsName string, roots *x509.CertPool, now func() time.Time) func([]*x509.Certificate) error {
	return func(certificates []*x509.Certificate) error {
		if len(certificates) == 0 {
			return errors.New("tls: no peer certificates")
		}

		intermediates := x509.NewCertPool()
		for _, certificate := range certificates[1:] {
			intermediates.AddCert(certificate)
		}
		verifyOptions := x509.VerifyOptions{
			Roots:         roots,
			Intermediates: intermediates,
		}
		if now != nil {
			verifyOptions.CurrentTime = now()
		}
		return VerifyAnyName(dnsName, func(name string) error {
			verifyOptions.DNSName = name
			_, err := certificates[0].Verify(verifyOptions)
			return err
		})
	}
}

// VerifyAnyName calls verify for each name in the comma-separated list until one passes.
// An empty list fails.
// P33: helper for name-cert-verify lists (Xray vcn).
func VerifyAnyName(names string, verify func(name string) error) error {
	err := errors.New("name-cert-verify: no names")
	for _, name := range strings.Split(names, ",") {
		if name = strings.TrimSpace(name); name == "" {
			continue
		}
		if err = verify(name); err == nil {
			return nil
		}
	}
	return err
}
