//+build gssapi,windows

package sspi

// #include "sspi_windows.h"
import "C"
import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

// New creates a new SaslSaslClient.
func New(target string, username, password string, passwordSet bool, props map[string]string) (*SaslClient, error) {

	var err error
	serviceName := "mongodb"
	serviceRealm := ""
	canonicalizeHostName := false

	for key, value := range props {
		switch strings.ToUpper(key) {
		case "CANONICALIZE_HOST_NAME":
			canonicalizeHostName, err = strconv.ParseBool(value)
			if err != nil {
				return nil, fmt.Errorf("%s must be a boolean (true, false, 0, 1) but got '%s'", key, value)
			}

		case "SERVICE_REALM":
			serviceRealm = value
		case "SERVICE_NAME":
			serviceName = value
		}
	}

	return &SaslClient{
		target:               target,
		serviceName:          serviceName,
		canonicalizeHostName: canonicalizeHostName,
		serviceRealm:         serviceRealm,
		username:             username,
		password:             password,
		passwordSet:          passwordSet,
	}, nil
}

type SaslClient struct {
	target               string
	serviceName          string
	serviceRealm         string
	canonicalizeHostName bool
	username             string
	password             string
	passwordSet          bool

	// state
	servicePrincipalName string
	credHandle           C.CredHandle
	context              C.CtxtHandle
	hasContext           C.int
	contextComplete      bool
	done                 bool
}

func (sc *SaslClient) Close() {
	if sc.hasContext > 0 {
		C.sspi_delete_security_context(&sc.context)
	}

	C.sspi_free_credentials_handle(&sc.credHandle)
}

func (sc *SaslClient) init() error {
	initOnce.Do(initSSPI)
	if initError != nil {
		return initError
	}

	hostname, _, err := net.SplitHostPort(string(sc.target))
	if err != nil {
		return fmt.Errorf("invalid target (%s) specified: %s", sc.target, err)
	}
	if sc.canonicalizeHostName {
		names, err := net.LookupAddr(hostname)
		if err != nil || len(names) == 0 {
			return fmt.Errorf("unable to canonicalize host name: %s", err)
		}
		hostname = names[0]
		if hostname[len(hostname)-1] == '.' {
			hostname = hostname[:len(hostname)-1]
		}
	}

	sc.servicePrincipalName = fmt.Sprintf("%s/%s", sc.serviceName, hostname)
	if sc.serviceRealm != "" {
		sc.servicePrincipalName += "@" + sc.serviceRealm
	}

	return nil
}

func (sc *SaslClient) Start() ([]byte, error) {

	err := sc.init()
	if err != nil {
		return nil, err
	}

	var status C.SECURITY_STATUS
	if sc.passwordSet {
		cusername := C.CString(sc.username)
		defer C.free(unsafe.Pointer(cusername))
		cpassword := C.CString(sc.password)
		defer C.free(unsafe.Pointer(cpassword))
		status = C.sspi_acquire_credentials_handle(&sc.credHandle, cusername, cpassword)
	} else {
		status = C.sspi_acquire_default_credentials_handle(&sc.credHandle)
	}

	if status != C.SEC_E_OK {
		return nil, fmt.Errorf("failed to acquire credentials handle: %s", statusMessage(status))
	}

	if sc.username == "" {
		var outName *C.char
		status = C.sspi_get_cred_name(&sc.credHandle, &outName)
		if status != C.SEC_E_OK {
			return nil, fmt.Errorf("failed to query credential attributes for name: %s", statusMessage(status))
		}
		defer C.free(unsafe.Pointer(outName))

		sc.username = C.GoString((*C.char)(unsafe.Pointer(outName)))
	}

	return []byte{}, nil
}

func (sc *SaslClient) Next(challenge []byte) ([]byte, error) {

	var outBuf C.PVOID
	var outBufLen C.ULONG

	var status C.SECURITY_STATUS
	if sc.contextComplete {
		cusername := C.CString(sc.username)
		defer C.free(unsafe.Pointer(cusername))
		status = C.sspi_send_client_authz_id(&sc.context, &outBuf, &outBufLen, cusername)
		if status != C.SEC_E_OK {
			return nil, fmt.Errorf("failed to send SaslClient authz id: %s", statusMessage(status))
		}

		sc.done = true
	} else {
		var buf C.PVOID
		var bufLen C.ULONG
		if len(challenge) > 0 {
			buf = (C.PVOID)(unsafe.Pointer(&challenge[0]))
			bufLen = C.ULONG(len(challenge))
		}
		cservicePrincipalName := C.CString(sc.servicePrincipalName)
		defer C.free(unsafe.Pointer(cservicePrincipalName))
		status = C.sspi_initialize_security_context(&sc.credHandle, sc.hasContext, &sc.context, buf, bufLen, &outBuf, &outBufLen, cservicePrincipalName)
		sc.hasContext = 1
		switch status {
		case C.SEC_E_OK:
			sc.contextComplete = true
		case C.SEC_I_CONTINUE_NEEDED, C.SEC_I_COMPLETE_AND_CONTINUE:
		default:
			return nil, fmt.Errorf("failed to initialize security context: %s", statusMessage(status))
		}
	}

	if outBuf != C.PVOID(nil) {
		defer C.free(unsafe.Pointer(outBuf))
	}

	return C.GoBytes(unsafe.Pointer(outBuf), C.int(outBufLen)), nil
}

func (sc *SaslClient) Completed() bool {
	return sc.done
}

var initOnce sync.Once
var initError error

func initSSPI() {
	rc := C.load_secur32_dll()
	if rc != 0 {
		initError = fmt.Errorf("error loading libraries: %v", rc)
	}
}

func statusMessage(status C.SECURITY_STATUS) string {
	var s string
	switch status {
	case C.SEC_E_ALGORITHM_MISMATCH:
		s = "The SaslClient and server cannot communicate because they do not possess a common algorithm."
	case C.SEC_E_BAD_BINDINGS:
		s = "The SSPI channel bindings supplied by the SaslClient are incorrect."
	case C.SEC_E_BAD_PKGID:
		s = "The requested package identifier does not exist."
	case C.SEC_E_BUFFER_TOO_SMALL:
		s = "The buffers supplied to the function are not large enough to contain the information."
	case C.SEC_E_CANNOT_INSTALL:
		s = "The security package cannot initialize successfully and should not be installed."
	case C.SEC_E_CANNOT_PACK:
		s = "The package is unable to pack the context."
	case C.SEC_E_CERT_EXPIRED:
		s = "The received certificate has expired."
	case C.SEC_E_CERT_UNKNOWN:
		s = "An unknown error occurred while processing the certificate."
	case C.SEC_E_CERT_WRONG_USAGE:
		s = "The certificate is not valid for the requested usage."
	case C.SEC_E_CONTEXT_EXPIRED:
		s = "The application is referencing a context that has already been closed. A properly written application should not receive this error."
	case C.SEC_E_CROSSREALM_DELEGATION_FAILURE:
		s = "The server attempted to make a Kerberos-constrained delegation request for a target outside the server's realm."
	case C.SEC_E_CRYPTO_SYSTEM_INVALID:
		s = "The cryptographic system or checksum function is not valid because a required function is unavailable."
	case C.SEC_E_DECRYPT_FAILURE:
		s = "The specified data could not be decrypted."
	case C.SEC_E_DELEGATION_REQUIRED:
		s = "The requested operation cannot be completed. The computer must be trusted for delegation"
	case C.SEC_E_DOWNGRADE_DETECTED:
		s = "The system detected a possible attempt to compromise security. Verify that the server that authenticated you can be contacted."
	case C.SEC_E_ENCRYPT_FAILURE:
		s = "The specified data could not be encrypted."
	case C.SEC_E_ILLEGAL_MESSAGE:
		s = "The message received was unexpected or badly formatted."
	case C.SEC_E_INCOMPLETE_CREDENTIALS:
		s = "The credentials supplied were not complete and could not be verified. The context could not be initialized."
	case C.SEC_E_INCOMPLETE_MESSAGE:
		s = "The message supplied was incomplete. The signature was not verified."
	case C.SEC_E_INSUFFICIENT_MEMORY:
		s = "Not enough memory is available to complete the request."
	case C.SEC_E_INTERNAL_ERROR:
		s = "An error occurred that did not map to an SSPI error code."
	case C.SEC_E_INVALID_HANDLE:
		s = "The handle passed to the function is not valid."
	case C.SEC_E_INVALID_TOKEN:
		s = "The token passed to the function is not valid."
	case C.SEC_E_ISSUING_CA_UNTRUSTED:
		s = "An untrusted certification authority (CA) was detected while processing the smart card certificate used for authentication."
	case C.SEC_E_ISSUING_CA_UNTRUSTED_KDC:
		s = "An untrusted CA was detected while processing the domain controller certificate used for authentication. The system event log contains additional information."
	case C.SEC_E_KDC_CERT_EXPIRED:
		s = "The domain controller certificate used for smart card logon has expired."
	case C.SEC_E_KDC_CERT_REVOKED:
		s = "The domain controller certificate used for smart card logon has been revoked."
	case C.SEC_E_KDC_INVALID_REQUEST:
		s = "A request that is not valid was sent to the KDC."
	case C.SEC_E_KDC_UNABLE_TO_REFER:
		s = "The KDC was unable to generate a referral for the service requested."
	case C.SEC_E_KDC_UNKNOWN_ETYPE:
		s = "The requested encryption type is not supported by the KDC."
	case C.SEC_E_LOGON_DENIED:
		s = "The logon has been denied"
	case C.SEC_E_MAX_REFERRALS_EXCEEDED:
		s = "The number of maximum ticket referrals has been exceeded."
	case C.SEC_E_MESSAGE_ALTERED:
		s = "The message supplied for verification has been altered."
	case C.SEC_E_MULTIPLE_ACCOUNTS:
		s = "The received certificate was mapped to multiple accounts."
	case C.SEC_E_MUST_BE_KDC:
		s = "The local computer must be a Kerberos domain controller (KDC)"
	case C.SEC_E_NO_AUTHENTICATING_AUTHORITY:
		s = "No authority could be contacted for authentication."
	case C.SEC_E_NO_CREDENTIALS:
		s = "No credentials are available."
	case C.SEC_E_NO_IMPERSONATION:
		s = "No impersonation is allowed for this context."
	case C.SEC_E_NO_IP_ADDRESSES:
		s = "Unable to accomplish the requested task because the local computer does not have any IP addresses."
	case C.SEC_E_NO_KERB_KEY:
		s = "No Kerberos key was found."
	case C.SEC_E_NO_PA_DATA:
		s = "Policy administrator (PA) data is needed to determine the encryption type"
	case C.SEC_E_NO_S4U_PROT_SUPPORT:
		s = "The Kerberos subsystem encountered an error. A service for user protocol request was made against a domain controller which does not support service for a user."
	case C.SEC_E_NO_TGT_REPLY:
		s = "The SaslClient is trying to negotiate a context and the server requires a user-to-user connection"
	case C.SEC_E_NOT_OWNER:
		s = "The caller of the function does not own the credentials."
	case C.SEC_E_OK:
		s = "The operation completed successfully."
	case C.SEC_E_OUT_OF_SEQUENCE:
		s = "The message supplied for verification is out of sequence."
	case C.SEC_E_PKINIT_CLIENT_FAILURE:
		s = "The smart card certificate used for authentication is not trusted."
	case C.SEC_E_PKINIT_NAME_MISMATCH:
		s = "The SaslClient certificate does not contain a valid UPN or does not match the SaslClient name in the logon request."
	case C.SEC_E_QOP_NOT_SUPPORTED:
		s = "The quality of protection attribute is not supported by this package."
	case C.SEC_E_REVOCATION_OFFLINE_C:
		s = "The revocation status of the smart card certificate used for authentication could not be determined."
	case C.SEC_E_REVOCATION_OFFLINE_KDC:
		s = "The revocation status of the domain controller certificate used for smart card authentication could not be determined. The system event log contains additional information."
	case C.SEC_E_SECPKG_NOT_FOUND:
		s = "The security package was not recognized."
	case C.SEC_E_SECURITY_QOS_FAILED:
		s = "The security context could not be established due to a failure in the requested quality of service (for example"
	case C.SEC_E_SHUTDOWN_IN_PROGRESS:
		s = "A system shutdown is in progress."
	case C.SEC_E_SMARTCARD_CERT_EXPIRED:
		s = "The smart card certificate used for authentication has expired."
	case C.SEC_E_SMARTCARD_CERT_REVOKED:
		s = "The smart card certificate used for authentication has been revoked. Additional information may exist in the event log."
	case C.SEC_E_SMARTCARD_LOGON_REQUIRED:
		s = "Smart card logon is required and was not used."
	case C.SEC_E_STRONG_CRYPTO_NOT_SUPPORTED:
		s = "The other end of the security negotiation requires strong cryptography"
	case C.SEC_E_TARGET_UNKNOWN:
		s = "The target was not recognized."
	case C.SEC_E_TIME_SKEW:
		s = "The clocks on the SaslClient and server computers do not match."
	case C.SEC_E_TOO_MANY_PRINCIPALS:
		s = "The KDC reply contained more than one principal name."
	case C.SEC_E_UNFINISHED_CONTEXT_DELETED:
		s = "A security context was deleted before the context was completed. This is considered a logon failure."
	case C.SEC_E_UNKNOWN_CREDENTIALS:
		s = "The credentials provided were not recognized."
	case C.SEC_E_UNSUPPORTED_FUNCTION:
		s = "The requested function is not supported."
	case C.SEC_E_UNSUPPORTED_PREAUTH:
		s = "An unsupported preauthentication mechanism was presented to the Kerberos package."
	case C.SEC_E_UNTRUSTED_ROOT:
		s = "The certificate chain was issued by an authority that is not trusted."
	case C.SEC_E_WRONG_CREDENTIAL_HANDLE:
		s = "The supplied credential handle does not match the credential associated with the security context."
	case C.SEC_E_WRONG_PRINCIPAL:
		s = "The target principal name is incorrect."
	case C.SEC_I_COMPLETE_AND_CONTINUE:
		s = "The function completed successfully"
	case C.SEC_I_COMPLETE_NEEDED:
		s = "The function completed successfully"
	case C.SEC_I_CONTEXT_EXPIRED:
		s = "The message sender has finished using the connection and has initiated a shutdown. For information about initiating or recognizing a shutdown"
	case C.SEC_I_CONTINUE_NEEDED:
		s = "The function completed successfully"
	case C.SEC_I_INCOMPLETE_CREDENTIALS:
		s = "The credentials supplied were not complete and could not be verified. Additional information can be returned from the context."
	case C.SEC_I_LOCAL_LOGON:
		s = "The logon was completed"
	case C.SEC_I_NO_LSA_CONTEXT:
		s = "There is no LSA mode context associated with this context."
	case C.SEC_I_RENEGOTIATE:
		s = "The context data must be renegotiated with the peer."
	default:
		return fmt.Sprintf("status code 0x%x", uint32(status))
	}

	return fmt.Sprintf("status code 0x%x: %s", uint32(status), s)
}