package auth

type SASLType uint8

const (
	NO_SASL SASLType = iota
	KERBEROS
)

type KerberosConfig struct {
	Password   string
	Username   string
	KeytabPath string // user's keytab file path
	KrbCfgPath string // krb5 config file path
	Realm      string // krb5 env realm
}

type SASLConfig struct {
	SASLType       SASLType
	KerberosConfig *KerberosConfig
}
