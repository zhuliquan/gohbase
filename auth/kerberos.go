package auth

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"net"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/jcmturner/gokrb5/v8/asn1tools"
	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/gssapi"
	"github.com/jcmturner/gokrb5/v8/iana/chksumtype"
	"github.com/jcmturner/gokrb5/v8/iana/keyusage"
	krb5keytab "github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	log "github.com/sirupsen/logrus"
)

const (
	TOK_ID_KRB_AP_REQ  = 256
	GSSAPI_GENERIC_TAG = 0x60
	GSSAPI_INITIAL     = 1
	GSSAPI_VERIFY      = 2
	GSSAPI_FINISH      = 3
)

// newKerberosClient creates kerberos client used to obtain TGT and TGS tokens.
// It uses pure go Kerberos 5 solution (RFC-4121 and RFC-4120).
// uses gokrb5 library underlying which is a pure go kerberos client with some GSS-API capabilities.
func newKerberosClient(c *KerberosConfig) (*krb5client.Client, error) {
	krb5cfg, err := krb5config.Load(c.KrbCfgPath)
	if err != nil {
		return nil, err
	}

	if c.KeytabPath != "" {
		if keytab, err := krb5keytab.Load(c.KeytabPath); err != nil {
			return nil, err
		} else {
			return krb5client.NewWithKeytab(c.Username, c.Realm, keytab, krb5cfg), nil
		}
	} else {
		return krb5client.NewWithPassword(c.Username, c.Realm, c.Password, krb5cfg), nil
	}
}

type KerberosAuth struct {
	Config *KerberosConfig
	SPN    string

	ticket messages.Ticket
	encKey types.EncryptionKey
	step   int
}

func (krbAuth *KerberosAuth) writePackage(conn net.Conn, payload []byte) error {
	if len(payload)+4 > math.MaxInt32 {
		return fmt.Errorf("payload too large, will overflow int32")
	}

	length := make([]byte, 4)
	binary.BigEndian.PutUint32(length, uint32(len(payload)))
	// write length header
	if _, err := conn.Write(length); err != nil {
		return fmt.Errorf("failed to write length header, err: %s", err)
	}

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("failed to write payload, err: %s", err)
	} else {
		return nil
	}
}

func (krbAuth *KerberosAuth) readPackage(conn net.Conn) ([]byte, error) {
	// read status
	status := make([]byte, 4)
	if _, err := io.ReadFull(conn, status); err != nil {
		return nil, fmt.Errorf("failed to read status, err: %s", err)
	}

	// read payload size
	length := make([]byte, 4)
	if _, err := io.ReadFull(conn, length); err != nil {
		return nil, fmt.Errorf("failed to read length, err: %s", err)
	}

	// read real result
	result := make([]byte, binary.BigEndian.Uint32(length))
	if _, err := io.ReadFull(conn, result); err != nil {
		return nil, fmt.Errorf("failed to read payload, err: %s", err)
	} else {
		return result, nil
	}
}

func (krbAuth *KerberosAuth) newAuthenticatorChecksum() []byte {
	a := make([]byte, 24)
	flags := []int{gssapi.ContextFlagInteg, gssapi.ContextFlagConf}
	binary.LittleEndian.PutUint32(a[:4], 16)
	for _, i := range flags {
		f := binary.LittleEndian.Uint32(a[20:24])
		f |= uint32(i)
		binary.LittleEndian.PutUint32(a[20:24], f)
	}
	return a
}

/*
*
* Construct Kerberos AP_REQ package, conforming to RFC-4120
* https://tools.ietf.org/html/rfc4120#page-84
*
 */
func (krbAuth *KerberosAuth) createKrb5Token(
	domain string, cname types.PrincipalName,
	ticket messages.Ticket,
	sessionKey types.EncryptionKey) ([]byte, error) {
	auth, err := types.NewAuthenticator(domain, cname)
	if err != nil {
		return nil, err
	}
	auth.Cksum = types.Checksum{
		CksumType: chksumtype.GSSAPI,
		Checksum:  krbAuth.newAuthenticatorChecksum(),
	}
	APReq, err := messages.NewAPReq(
		ticket,
		sessionKey,
		auth,
	)
	if err != nil {
		return nil, err
	}
	aprBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(aprBytes, TOK_ID_KRB_AP_REQ)
	tb, err := APReq.Marshal()
	if err != nil {
		return nil, err
	}
	aprBytes = append(aprBytes, tb...)
	return aprBytes, nil
}

/*
*
*	Append the GSS-API header to the payload, conforming to RFC-2743
*	Section 3.1, Mechanism-Independent Token Format
*
*	https://tools.ietf.org/html/rfc2743#page-81
*
*	GSSAPIHeader + <specific mechanism payload>
*
 */
func (krbAuth *KerberosAuth) appendGSSAPIHeader(payload []byte) ([]byte, error) {
	oidBytes, err := asn1.Marshal(gssapi.OIDKRB5.OID())
	if err != nil {
		return nil, err
	}
	tkoLengthBytes := asn1tools.MarshalLengthBytes(len(oidBytes) + len(payload))
	GSSHeader := append([]byte{GSSAPI_GENERIC_TAG}, tkoLengthBytes...)
	GSSHeader = append(GSSHeader, oidBytes...)
	GSSPackage := append(GSSHeader, payload...)
	return GSSPackage, nil
}

func (krbAuth *KerberosAuth) initSecContext(bytes []byte, krbCli *krb5client.Client) ([]byte, error) {
	switch krbAuth.step {
	case GSSAPI_INITIAL:
		aprBytes, err := krbAuth.createKrb5Token(
			krbCli.Credentials.Domain(),
			krbCli.Credentials.CName(),
			krbAuth.ticket, krbAuth.encKey)
		if err != nil {
			return nil, err
		}
		krbAuth.step = GSSAPI_VERIFY
		return krbAuth.appendGSSAPIHeader(aprBytes)
	case GSSAPI_VERIFY:
		wrapTokenReq := gssapi.WrapToken{}
		if err := wrapTokenReq.Unmarshal(bytes, true); err != nil {
			return nil, err
		}
		// Validate response.
		isValid, err := wrapTokenReq.Verify(krbAuth.encKey, keyusage.GSSAPI_ACCEPTOR_SEAL)
		if !isValid {
			return nil, err
		}

		wrapTokenResponse, err := gssapi.NewInitiatorWrapToken(wrapTokenReq.Payload, krbAuth.encKey)
		if err != nil {
			return nil, err
		}
		krbAuth.step = GSSAPI_FINISH
		return wrapTokenResponse.Marshal()
	}
	return nil, nil
}

/* This does the handshake for authorization */
func (krbAuth *KerberosAuth) Authorize(conn net.Conn) error {
	var krbCli, err = newKerberosClient(krbAuth.Config)
	if err != nil {
		log.Errorf("failed to create kerberos client, err: %s", err)
		return fmt.Errorf("failed to create kerberos client, err: %s", err)
	}
	if err = krbCli.Login(); err != nil {
		log.Errorf("kerberos client failed to login, err: %s", err)
		return fmt.Errorf("kerberos client failed to login, err: %s", err)
	}
	defer krbCli.Destroy()

	if krbAuth.ticket, krbAuth.encKey, err = krbCli.GetServiceTicket(krbAuth.SPN); err != nil {
		log.Errorf("faild to get kerberos service ticket (TGS), err: %s", err)
		return fmt.Errorf("faild to get kerberos service ticket (TGS), err: %s", err)
	}
	krbAuth.step = GSSAPI_INITIAL
	var recvBytes []byte = nil
	var packBytes []byte = nil
	for {
		if packBytes, err = krbAuth.initSecContext(recvBytes, krbCli); err != nil {
			log.Errorf("failed to init context while handshaking gssapi kerberos authentication, krbAuth: %+v, err: %s", krbAuth, err)
			return fmt.Errorf("failed to init context while handshaking gssapi kerberos authentication, err: %s", err)
		}
		if err = krbAuth.writePackage(conn, packBytes); err != nil {
			log.Errorf("failed to write package while handshaking gssapi kerberos authentication, krbAuth: %+v, err: %s", krbAuth, err)
			return fmt.Errorf("failed to write package while handshaking gssapi kerberos authentication, err: %s", err)
		}
		if krbAuth.step == GSSAPI_VERIFY {
			if recvBytes, err = krbAuth.readPackage(conn); err != nil {
				log.Errorf("failed to read package while handshaking gssapi kerberos authentication, krbAuth: %+v, err: %s", krbAuth, err)
				return fmt.Errorf("failed to read package while handshaking gssapi kerberos authentication, err: %s", err)
			}
		} else if krbAuth.step == GSSAPI_FINISH {
			return nil
		}
	}
}
