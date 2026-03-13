package node

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	panel "github.com/wyx2685/v2node/api/v2board"
	"github.com/wyx2685/v2node/common/file"
)

func (c *Controller) renewCertTask() error {
	for _, cert := range c.certInfosForTLS() {
		if !isAutoRenewCertMode(cert.CertMode) {
			continue
		}
		l, err := NewLego(cert)
		if err != nil {
			log.WithField("tag", c.tag).Info("new lego error: ", err)
			continue
		}
		err = l.RenewCert()
		if err != nil {
			log.WithField("tag", c.tag).Info("renew cert error: ", err)
			continue
		}
		log.WithField("tag", c.tag).Infof("renew cert success: mode=%s domain=%s cert=%s", cert.CertMode, cert.CertDomain, cert.CertFile)
	}
	return nil
}

func (c *Controller) requestCert() error {
	for _, cert := range c.certInfosForTLS() {
		if err := c.requestSingleCert(cert); err != nil {
			return err
		}
	}
	return nil
}

func (c *Controller) requestSingleCert(cert *panel.CertInfo) error {
	if cert == nil {
		return nil
	}
	switch cert.CertMode {
	case "none", "":
	case "file":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
	case "dns", "http", "tls":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		l, err := NewLego(cert)
		if err != nil {
			return fmt.Errorf("create lego object error: %s", err)
		}
		err = l.CreateCert()
		if err != nil {
			return fmt.Errorf("create lego cert error: %s", err)
		}
	case "self":
		if cert.CertFile == "" || cert.KeyFile == "" {
			return fmt.Errorf("cert file path or key file path not exist")
		}
		if file.IsExist(cert.CertFile) && file.IsExist(cert.KeyFile) {
			return nil
		}
		err := generateSelfSslCertificate(
			cert.CertDomain,
			cert.CertFile,
			cert.KeyFile)
		if err != nil {
			return fmt.Errorf("generate self cert error: %s", err)
		}
	default:
		return fmt.Errorf("unsupported certmode: %s", cert.CertMode)
	}
	return nil
}

func (c *Controller) certInfosForTLS() []*panel.CertInfo {
	if c.info == nil || c.info.Common == nil {
		return nil
	}
	out := make([]*panel.CertInfo, 0, 1+len(c.info.Common.ExtraCertInfos))
	seen := map[string]struct{}{}
	appendCert := func(cert *panel.CertInfo) {
		if cert == nil {
			return
		}
		uniq := strings.ToLower(strings.TrimSpace(cert.CertMode)) + "\x00" +
			strings.TrimSpace(cert.CertFile) + "\x00" +
			strings.TrimSpace(cert.KeyFile) + "\x00" +
			strings.TrimSpace(cert.CertDomain)
		if _, ok := seen[uniq]; ok {
			return
		}
		seen[uniq] = struct{}{}
		out = append(out, cert)
	}
	appendCert(c.info.Common.CertInfo)
	for _, cert := range c.info.Common.ExtraCertInfos {
		appendCert(cert)
	}
	return out
}

func (c *Controller) needRenewCertTask() bool {
	for _, cert := range c.certInfosForTLS() {
		if isAutoRenewCertMode(cert.CertMode) {
			return true
		}
	}
	return false
}

func isAutoRenewCertMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "dns", "http", "tls":
		return true
	default:
		return false
	}
}

func generateSelfSslCertificate(domain, certPath, keyPath string) error {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		Version:      3,
		SerialNumber: big.NewInt(time.Now().Unix()),
		Subject: pkix.Name{
			CommonName: domain,
		},
		DNSNames:              []string{domain},
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(30, 0, 0),
	}
	cert, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(certPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})
	if err != nil {
		return err
	}
	f, err = os.OpenFile(keyPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return err
	}
	err = pem.Encode(f, &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	if err != nil {
		return err
	}
	return nil
}
