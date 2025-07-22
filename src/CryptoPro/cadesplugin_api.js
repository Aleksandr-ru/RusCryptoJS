﻿; (function () {
    //already loaded
    if (window.cadesplugin && window.cadesplugin.LOG_LEVEL_DEBUG) {
        return;
    }
    var pluginObject;
    var plugin_resolved = 0;
    var plugin_reject;
    var plugin_resolve;
    var isOpera = 0;
    var isFireFox = 0;
    var isSafari = 0;
    var isYandex = 0;
    var canPromise = !!window.Promise;
    var cadesplugin_loaded_event_recieved = false;
    var isFireFoxExtensionLoaded = false;
    var cadesplugin = {};

    if (canPromise) {
        cadesplugin = new window.Promise(function (resolve, reject) {
            plugin_resolve = resolve;
            plugin_reject = reject;
        });
    }

    function check_browser() {
        var ua = window.navigator.userAgent,
            tem,
            M = ua.match(/(opera|yabrowser|chrome|safari|firefox|msie|trident(?=\/))\/?\s*(\d+)/i) || [];
        if (/trident/i.test(M[1])) {
            tem = /\brv[ :]+(\d+)/g.exec(ua) || [];
            return { name: 'IE', version: (tem[1] || '') };
        }
        if (M[1] === "Chrome") {
            tem = ua.match(/\b(OPR|Edg|YaBrowser)\/(\d+)/);
            if (tem != null && (tem.length > 2)) {
                return { name: tem[1].replace('OPR', 'Opera'), version: tem[2] };
            }
        }
        M = M[2] ? [M[1], M[2]] : [window.navigator.appName, window.navigator.appVersion, '-?'];
        if ((tem = ua.match(/version\/(\d+)/i)) != null) {
            M.splice(1, 1, tem[1]);
        }
        return { name: M[0], version: M[1] };
    }

    var browserSpecs = check_browser();

    function cpcsp_console_log(level, msg) {
        //IE9 не может писать в консоль если не открыта вкладка developer tools
        if (typeof console === 'undefined') {
            return;
        }
        if (level <= cadesplugin.current_log_level) {
            if (level === cadesplugin.LOG_LEVEL_DEBUG) {
                console.log("DEBUG: %s", msg);
            }
            if (level === cadesplugin.LOG_LEVEL_INFO) {
                console.info("INFO: %s", msg);
            }
            if (level === cadesplugin.LOG_LEVEL_ERROR) {
                console.error("ERROR: %s", msg);
            }
        }
    }

    function get_extension_version(callback) {
        window.postMessage("cadesplugin_extension_version_request", "*");
        window.addEventListener("message", function (event) {
            var resp_prefix = "cadesplugin_extension_version_response:";
            if (typeof (event.data) !== "string" || event.data.indexOf(resp_prefix) !== 0) {
                return;
            }
            var ext_version = event.data.substring(resp_prefix.length);
            callback(ext_version);
        }, false);
    }

    function get_extension_id(callback) {
        window.postMessage("cadesplugin_extension_id_request", "*");
        window.addEventListener("message", function (event) {
            var resp_prefix = "cadesplugin_extension_id_response:";
            if (typeof (event.data) !== "string" || event.data.indexOf(resp_prefix) !== 0) {
                return;
            }
            var ext_id = event.data.substring(resp_prefix.length);
            callback(ext_id);
        }, false);
    }

    function set_log_level(level) {
        if (!((level === cadesplugin.LOG_LEVEL_DEBUG) ||
            (level === cadesplugin.LOG_LEVEL_INFO) ||
            (level === cadesplugin.LOG_LEVEL_ERROR))) {
            cpcsp_console_log(cadesplugin.LOG_LEVEL_ERROR, "cadesplugin_api.js: Incorrect log_level: " + level);
            return;
        }
        cadesplugin.current_log_level = level;
        if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_DEBUG) {
            cpcsp_console_log(cadesplugin.LOG_LEVEL_INFO, "cadesplugin_api.js: log_level = DEBUG");
        }
        if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_INFO) {
            cpcsp_console_log(cadesplugin.LOG_LEVEL_INFO, "cadesplugin_api.js: log_level = INFO");
        }
        if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_ERROR) {
            cpcsp_console_log(cadesplugin.LOG_LEVEL_INFO, "cadesplugin_api.js: log_level = ERROR");
        }
        if (isNativeMessageSupported()) {
            if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_DEBUG) {
                window.postMessage("set_log_level=debug", "*");
            }
            if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_INFO) {
                window.postMessage("set_log_level=info", "*");
            }
            if (cadesplugin.current_log_level === cadesplugin.LOG_LEVEL_ERROR) {
                window.postMessage("set_log_level=error", "*");
            }
        }
    }

    function set_constantValues() {
        cadesplugin.CAPICOM_MEMORY_STORE = 0;
        cadesplugin.CAPICOM_LOCAL_MACHINE_STORE = 1;
        cadesplugin.CAPICOM_CURRENT_USER_STORE = 2;
        cadesplugin.CAPICOM_SMART_CARD_USER_STORE = 4;
        cadesplugin.CADESCOM_MEMORY_STORE = 0;
        cadesplugin.CADESCOM_LOCAL_MACHINE_STORE = 1;
        cadesplugin.CADESCOM_CURRENT_USER_STORE = 2;
        cadesplugin.CADESCOM_SMART_CARD_USER_STORE = 4;
        cadesplugin.CADESCOM_CONTAINER_STORE = 100;

        cadesplugin.CAPICOM_ROOT_STORE = "Root";
        cadesplugin.CAPICOM_CA_STORE = "CA";
        cadesplugin.CAPICOM_MY_STORE = "My";
        cadesplugin.CAPICOM_ADDRESSBOOK_STORE = "AddressBook";

        cadesplugin.CAPICOM_STORE_OPEN_READ_WRITE = 1;
        cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;
        cadesplugin.CAPICOM_STORE_OPEN_INCLUDE_ARCHIVED = 256;

        cadesplugin.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;

        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0;
        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING = 1;
        cadesplugin.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE = 2;

        cadesplugin.CADESCOM_XADES_DEFAULT = 0x00000010;
        cadesplugin.CADESCOM_XADES_BES = 0x00000020;
        cadesplugin.CADESCOM_XADES_T = 0x00000050;
        cadesplugin.CADESCOM_XADES_X_LONG_TYPE_1 = 0x000005d0;
        cadesplugin.CADESCOM_XMLDSIG_TYPE = 0x00000000;

        cadesplugin.XmlDsigGost3410UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr34102001-gostr3411";
        cadesplugin.XmlDsigGost3411UrlObsolete = "http://www.w3.org/2001/04/xmldsig-more#gostr3411";
        cadesplugin.XmlDsigGost3410Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
        cadesplugin.XmlDsigGost3411Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

        cadesplugin.XmlDsigGost3411Url2012256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256";
        cadesplugin.XmlDsigGost3410Url2012256 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";
        cadesplugin.XmlDsigGost3411Url2012512 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-512";
        cadesplugin.XmlDsigGost3410Url2012512 = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

        cadesplugin.CADESCOM_CADES_DEFAULT = 0;
        cadesplugin.CADESCOM_CADES_BES = 1;
        cadesplugin.CADESCOM_CADES_T = 0x5;
        cadesplugin.CADESCOM_CADES_X_LONG_TYPE_1 = 0x5d;
        cadesplugin.CADESCOM_CADES_A = 0xdd;
        cadesplugin.CADESCOM_PKCS7_TYPE = 0xffff;

        cadesplugin.CADESCOM_ENCODE_BASE64 = 0;
        cadesplugin.CADESCOM_ENCODE_BINARY = 1;
        cadesplugin.CADESCOM_ENCODE_ANY = -1;

        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_CHAIN_EXCEPT_ROOT = 0;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN = 1;
        cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY = 2;

        cadesplugin.CAPICOM_CERT_INFO_SUBJECT_SIMPLE_NAME = 0;
        cadesplugin.CAPICOM_CERT_INFO_ISSUER_SIMPLE_NAME = 1;

        cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_SUBJECT_NAME = 1;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_ISSUER_NAME = 2;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_ROOT_NAME = 3;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TEMPLATE_NAME = 4;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENSION = 5;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_EXTENDED_PROPERTY = 6;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_APPLICATION_POLICY = 7;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_CERTIFICATE_POLICY = 8;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_VALID = 9;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_NOT_YET_VALID = 10;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_TIME_EXPIRED = 11;
        cadesplugin.CAPICOM_CERTIFICATE_FIND_KEY_USAGE = 12;

        cadesplugin.CAPICOM_DIGITAL_SIGNATURE_KEY_USAGE = 128;

        cadesplugin.CAPICOM_PROPID_ENHKEY_USAGE = 9;

        cadesplugin.CAPICOM_OID_OTHER = 0;
        cadesplugin.CAPICOM_OID_KEY_USAGE_EXTENSION = 10;

        cadesplugin.CAPICOM_EKU_CLIENT_AUTH = 2;
        cadesplugin.CAPICOM_EKU_SMARTCARD_LOGON = 5;
        cadesplugin.CAPICOM_EKU_OTHER = 0;

        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
        cadesplugin.CAPICOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_SIGNING_TIME = 0;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_NAME = 1;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_DOCUMENT_DESCRIPTION = 2;
        cadesplugin.CADESCOM_AUTHENTICATED_ATTRIBUTE_MACHINE_INFO = 0x100;
        cadesplugin.CADESCOM_ATTRIBUTE_OTHER = -1;

        cadesplugin.CADESCOM_STRING_TO_UCS2LE = 0;
        cadesplugin.CADESCOM_BASE64_TO_BINARY = 1;

        cadesplugin.CADESCOM_DISPLAY_DATA_NONE = 0;
        cadesplugin.CADESCOM_DISPLAY_DATA_CONTENT = 1;
        cadesplugin.CADESCOM_DISPLAY_DATA_ATTRIBUTE = 2;

        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_RC2 = 0;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_RC4 = 1;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_DES = 2;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_3DES = 3;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_AES = 4;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_28147_89 = 25;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA = 35;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_MAGMA_OMAC = 36;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK = 45;
        cadesplugin.CADESCOM_ENCRYPTION_ALGORITHM_GOST_KUZNYECHIK_OMAC = 46;

        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA1 = 0;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD2 = 1;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD4 = 2;
        cadesplugin.CADESCOM_HASH_ALGORITHM_MD5 = 3;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_256 = 4;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_384 = 5;
        cadesplugin.CADESCOM_HASH_ALGORITHM_SHA_512 = 6;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411 = 100;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256 = 101;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512 = 102;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_HMAC = 110;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_256_HMAC = 111;
        cadesplugin.CADESCOM_HASH_ALGORITHM_CP_GOST_3411_2012_512_HMAC = 112;

        cadesplugin.CADESCOM_CERT_INFO_ROLE = 100;
        cadesplugin.CADESCOM_ROLE_ROOT = "ROOT";
        cadesplugin.CADESCOM_ROLE_CA = "CA";
        cadesplugin.CADESCOM_ROLE_LEAF = "LEAF";

        cadesplugin.LOG_LEVEL_DEBUG = 4;
        cadesplugin.LOG_LEVEL_INFO = 2;
        cadesplugin.LOG_LEVEL_ERROR = 1;

        cadesplugin.CADESCOM_AllowNone = 0;
        cadesplugin.CADESCOM_AllowNoOutstandingRequest = 0x1;
        cadesplugin.CADESCOM_AllowUntrustedCertificate = 0x2;
        cadesplugin.CADESCOM_AllowUntrustedRoot = 0x4;
        cadesplugin.CADESCOM_SkipInstallToStore = 0x10000000;
        cadesplugin.CADESCOM_InstallCertChainToContainer = 0x20000000;
        cadesplugin.CADESCOM_UseContainerStore = 0x40000000;

        cadesplugin.ContextNone = 0;
        cadesplugin.ContextUser = 0x1;
        cadesplugin.ContextMachine = 0x2;
        cadesplugin.ContextAdministratorForceMachine = 0x3;

        cadesplugin.ENABLE_CARRIER_TYPE_CSP = 0x01;
        cadesplugin.ENABLE_CARRIER_TYPE_FKC_NO_SM = 0x02;
        cadesplugin.ENABLE_CARRIER_TYPE_FKC_SM = 0x04;
        cadesplugin.ENABLE_ANY_CARRIER_TYPE = 0x07;

        cadesplugin.DISABLE_EVERY_CARRIER_OPERATION = 0x00;
        cadesplugin.ENABLE_CARRIER_OPEN_ENUM = 0x01;
        cadesplugin.ENABLE_CARRIER_CREATE = 0x02;
        cadesplugin.ENABLE_ANY_OPERATION = 0x03;

        cadesplugin.CADESCOM_PRODUCT_CSP = 0;
        cadesplugin.CADESCOM_PRODUCT_OCSP = 1;
        cadesplugin.CADESCOM_PRODUCT_TSP = 2;

        cadesplugin.MEDIA_TYPE_DEFAULT = 0x00000000;
        cadesplugin.MEDIA_TYPE_REGISTRY = 0x00000001;
        cadesplugin.MEDIA_TYPE_HDIMAGE = 0x00000002;
        cadesplugin.MEDIA_TYPE_CLOUD = 0x00000004;
        cadesplugin.MEDIA_TYPE_SCARD = 0x00000008;

        cadesplugin.XCN_CRYPT_STRING_BASE64HEADER = 0;
        cadesplugin.XCN_CRYPT_STRING_BASE64 = 0x1;
        cadesplugin.XCN_CRYPT_STRING_BINARY = 0x2;
        cadesplugin.XCN_CRYPT_STRING_BASE64REQUESTHEADER = 0x3;
        cadesplugin.XCN_CRYPT_STRING_HEX = 0x4;
        cadesplugin.XCN_CRYPT_STRING_HEXASCII = 0x5;
        cadesplugin.XCN_CRYPT_STRING_BASE64_ANY = 0x6;
        cadesplugin.XCN_CRYPT_STRING_ANY = 0x7;
        cadesplugin.XCN_CRYPT_STRING_HEX_ANY = 0x8;
        cadesplugin.XCN_CRYPT_STRING_BASE64X509CRLHEADER = 0x9;
        cadesplugin.XCN_CRYPT_STRING_HEXADDR = 0xa;
        cadesplugin.XCN_CRYPT_STRING_HEXASCIIADDR = 0xb;
        cadesplugin.XCN_CRYPT_STRING_HEXRAW = 0xc;
        cadesplugin.XCN_CRYPT_STRING_BASE64URI = 0xd;
        cadesplugin.XCN_CRYPT_STRING_ENCODEMASK = 0xff;
        cadesplugin.XCN_CRYPT_STRING_CHAIN = 0x100;
        cadesplugin.XCN_CRYPT_STRING_TEXT = 0x200;
        cadesplugin.XCN_CRYPT_STRING_PERCENTESCAPE = 0x8000000;
        cadesplugin.XCN_CRYPT_STRING_HASHDATA = 0x10000000;
        cadesplugin.XCN_CRYPT_STRING_STRICT = 0x20000000;
        cadesplugin.XCN_CRYPT_STRING_NOCRLF = 0x40000000;
        cadesplugin.XCN_CRYPT_STRING_NOCR = 0x80000000;

        cadesplugin.XCN_CERT_NAME_STR_NONE = 0;
        cadesplugin.XCN_AT_NONE = 0;
        cadesplugin.XCN_AT_KEYEXCHANGE = 1;
        cadesplugin.XCN_AT_SIGNATURE = 2;

        cadesplugin.AT_KEYEXCHANGE = 1;
        cadesplugin.AT_SIGNATURE = 2;

        cadesplugin.CARRIER_FLAG_REMOVABLE = 1;
        cadesplugin.CARRIER_FLAG_UNIQUE = 2;
        cadesplugin.CARRIER_FLAG_PROTECTED = 4;
        cadesplugin.CARRIER_FLAG_FUNCTIONAL_CARRIER = 8;
        cadesplugin.CARRIER_FLAG_SECURE_MESSAGING = 16;
        cadesplugin.CARRIER_FLAG_ABLE_SET_KEY = 32;
        cadesplugin.CARRIER_FLAG_ABLE_VISUALISE_SIGNATURE = 64;
        cadesplugin.CARRIER_FLAG_VIRTUAL = 128;

        cadesplugin.CRYPT_MODE_CBCSTRICT = 1;
        cadesplugin.CRYPT_MODE_CNT = 3;
        cadesplugin.CRYPT_MODE_CBCRFC4357 = 31;
        cadesplugin.CRYPT_MODE_CTR = 32;
        cadesplugin.CRYPT_MODE_MGM = 33;
        cadesplugin.CRYPT_MODE_GCM = 34;
        cadesplugin.CRYPT_MODE_OMAC_CTR = 35;
        cadesplugin.CRYPT_MODE_WRAP = 36;
        cadesplugin.CRYPT_MODE_WRAP_PAD = 37;

        cadesplugin.PKCS5_PADDING = 1;
        cadesplugin.RANDOM_PADDING = 2;
        cadesplugin.ZERO_PADDING = 3;
        cadesplugin.ISO10126_PADDING = 4;
        cadesplugin.ANSI_X923_PADDING = 5;
        cadesplugin.TLS_1_0_PADDING = 6;
        cadesplugin.ISO_IEC_7816_4_PADDING = 7;

        cadesplugin.CAPICOM_STORE_SAVE_AS_SERIALIZED = 0;
        cadesplugin.CAPICOM_STORE_SAVE_AS_PKCS7 = 1;

        cadesplugin.CERT_TRUST_NO_ERROR = 0x00000000;
        cadesplugin.CERT_TRUST_IS_NOT_TIME_VALID = 0x00000001;
        cadesplugin.CERT_TRUST_IS_REVOKED = 0x00000004;
        cadesplugin.CERT_TRUST_IS_NOT_SIGNATURE_VALID = 0x00000008;
        cadesplugin.CERT_TRUST_IS_NOT_VALID_FOR_USAGE = 0x00000010;
        cadesplugin.CERT_TRUST_IS_UNTRUSTED_ROOT = 0x00000020;
        cadesplugin.CERT_TRUST_REVOCATION_STATUS_UNKNOWN = 0x00000040;
        cadesplugin.CERT_TRUST_IS_CYCLIC = 0x00000080;
        cadesplugin.CERT_TRUST_INVALID_EXTENSION = 0x00000100;
        cadesplugin.CERT_TRUST_INVALID_POLICY_CONSTRAINTS = 0x00000200;
        cadesplugin.CERT_TRUST_INVALID_BASIC_CONSTRAINTS = 0x00000400;
        cadesplugin.CERT_TRUST_INVALID_NAME_CONSTRAINTS = 0x00000800;
        cadesplugin.CERT_TRUST_HAS_NOT_SUPPORTED_NAME_CONSTRAINT = 0x00001000;
        cadesplugin.CERT_TRUST_HAS_NOT_DEFINED_NAME_CONSTRAINT = 0x00002000;
        cadesplugin.CERT_TRUST_HAS_NOT_PERMITTED_NAME_CONSTRAINT = 0x00004000;
        cadesplugin.CERT_TRUST_HAS_EXCLUDED_NAME_CONSTRAINT = 0x00008000;
        cadesplugin.CERT_TRUST_IS_OFFLINE_REVOCATION = 0x01000000;
        cadesplugin.CERT_TRUST_NO_ISSUANCE_CHAIN_POLICY = 0x02000000;
        cadesplugin.CERT_TRUST_IS_EXPLICIT_DISTRUST = 0x04000000;
        cadesplugin.CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT = 0x08000000;
        cadesplugin.CERT_TRUST_HAS_WEAK_SIGNATURE = 0x00100000;

        cadesplugin.XCN_CERT_NO_KEY_USAGE = 0;
        cadesplugin.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE = 0x80;
        cadesplugin.XCN_CERT_NON_REPUDIATION_KEY_USAGE = 0x40;
        cadesplugin.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE = 0x20;
        cadesplugin.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE = 0x10;
        cadesplugin.XCN_CERT_KEY_AGREEMENT_KEY_USAGE = 0x8;
        cadesplugin.XCN_CERT_KEY_CERT_SIGN_KEY_USAGE = 0x4;
        cadesplugin.XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE = 0x2;
        cadesplugin.XCN_CERT_CRL_SIGN_KEY_USAGE = 0x2;
        cadesplugin.XCN_CERT_ENCIPHER_ONLY_KEY_USAGE = 0x1;
        cadesplugin.XCN_CERT_DECIPHER_ONLY_KEY_USAGE = 0x8000;

        cadesplugin.CADESCOM_XADES_ACCEPT_ANY_ID_ATTR_NAMESPACE = 1;
        cadesplugin.CADES_USE_OCSP_AUTHORIZED_POLICY = 0x00020000;

        cadesplugin.XCN_NCRYPT_NO_OPERATION = 0;
        cadesplugin.XCN_NCRYPT_CIPHER_OPERATION = 0x1;
        cadesplugin.XCN_NCRYPT_HASH_OPERATION = 0x2;
        cadesplugin.XCN_NCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION = 0x4;
        cadesplugin.XCN_NCRYPT_SECRET_AGREEMENT_OPERATION = 0x8;
        cadesplugin.XCN_NCRYPT_SIGNATURE_OPERATION = 0x10;
        cadesplugin.XCN_NCRYPT_RNG_OPERATION = 0x20;

        cadesplugin.XCN_CRYPT_ANY_GROUP_ID = 0;
        cadesplugin.XCN_CRYPT_HASH_ALG_OID_GROUP_ID = 1;
        cadesplugin.XCN_CRYPT_ENCRYPT_ALG_OID_GROUP_ID = 2;
        cadesplugin.XCN_CRYPT_PUBKEY_ALG_OID_GROUP_ID = 3;
        cadesplugin.XCN_CRYPT_SIGN_ALG_OID_GROUP_ID = 4;
        cadesplugin.XCN_CRYPT_RDN_ATTR_OID_GROUP_ID = 5;
        cadesplugin.XCN_CRYPT_EXT_OR_ATTR_OID_GROUP_ID = 6;
        cadesplugin.XCN_CRYPT_ENHKEY_USAGE_OID_GROUP_ID = 7;
        cadesplugin.XCN_CRYPT_POLICY_OID_GROUP_ID = 8;
        cadesplugin.XCN_CRYPT_TEMPLATE_OID_GROUP_ID = 9;

        cadesplugin.XCN_CRYPT_OID_INFO_PUBKEY_ANY = 0;
        cadesplugin.XCN_CRYPT_OID_INFO_PUBKEY_SIGN_KEY_FLAG = 0x80000000;
        cadesplugin.XCN_CRYPT_OID_INFO_PUBKEY_ENCRYPT_KEY_FLAG = 0x40000000;

        cadesplugin.CONTROL_KEY_TIME_VALIDITY_DISABLED = 0;
        cadesplugin.CONTROL_KEY_TIME_VALIDITY_ENABLED = 1;
        cadesplugin.CONTROL_KEY_TIME_VALIDITY_STRICT = 2;

        cadesplugin.AlgorithmFlagsNone = 0;
        cadesplugin.AlgorithmFlagsWrap = 0x1;
    }

    function async_spawn(generatorFunc) {
        function continuer(verb, arg) {
            var result;
            try {
                result = generator[verb](arg);
            } catch (err) {
                return window.Promise.reject(err);
            }
            if (result.done) {
                return result.value;
            } else {
                return window.Promise.resolve(result.value).then(onFulfilled, onRejected);
            }
        }
        var generator = generatorFunc(Array.prototype.slice.call(arguments, 1));
        var onFulfilled = continuer.bind(continuer, "next");
        var onRejected = continuer.bind(continuer, "throw");
        return onFulfilled();
    }

    function isIE() {
        // var retVal = (("Microsoft Internet Explorer" == navigator.appName) || // IE < 11
        //     navigator.userAgent.match(/Trident\/./i)); // IE 11
        return (browserSpecs.name === 'IE' || browserSpecs.name === 'MSIE');
    }

    function isIOS() {
        return (window.navigator.userAgent.match(/ipod/i) ||
            window.navigator.userAgent.match(/ipad/i) ||
            window.navigator.userAgent.match(/iphone/i));
    }

    function isNativeMessageSupported() {
        // В IE работаем через NPAPI
        if (isIE()) {
            return false;
        }
        // В Edge работаем через NativeMessage
        if (browserSpecs.name === 'Edg') {
            return true;
        }
        if (browserSpecs.name === 'YaBrowser') {
            isYandex = true;
            return true;
        }
        // В Chrome, Firefox, Safari и Opera работаем через асинхронную версию в зависимости от версии
        if (browserSpecs.name === 'Opera') {
            isOpera = true;
            return (browserSpecs.version >= 33);
        }
        if (browserSpecs.name === 'Firefox') {
            isFireFox = true;
            return (browserSpecs.version >= 52);
        }
        if (browserSpecs.name === 'Chrome') {
            return (browserSpecs.version >= 42);
        }
        //В Сафари начиная с 12 версии нет NPAPI
        if (browserSpecs.name === 'Safari') {
            isSafari = true;
            return (browserSpecs.version >= 12);
        }
    }

    // Функция активации объектов КриптоПро ЭЦП Browser plug-in
    function CreateObject(name) {
        if (isIOS()) {
            // На iOS для создания объектов используется функция
            // call_ru_cryptopro_npcades_10_native_bridge, определенная в IOS_npcades_supp.js
            return call_ru_cryptopro_npcades_10_native_bridge("CreateObject", [name]);
        }
        var objWebClassFactory;
        if (isIE()) {
            // В Internet Explorer создаются COM-объекты
            if (name.match(/X509Enrollment/i)) {
                try {
                    // Объекты CertEnroll пробуем создавать через нашу фабрику,
                    // если не получилось то через CX509EnrollmentWebClassFactory
                    objWebClassFactory = document.getElementById("webClassFactory");
                    return objWebClassFactory.CreateObject(name);
                }
                catch (e) {
                    try {
                        var objCertEnrollClassFactory = document.getElementById("certEnrollClassFactory");
                        return objCertEnrollClassFactory.CreateObject(name);
                    }
                    catch (err) {
                        throw ("Для создания обьектов X509Enrollment следует настроить веб-узел на использование проверки подлинности по протоколу HTTPS");
                    }
                }
            }
            // Объекты CAPICOM и CAdESCOM создаются через CAdESCOM.WebClassFactory
            try {
                objWebClassFactory = document.getElementById("webClassFactory");
                return objWebClassFactory.CreateObject(name);
            } catch (e) {
                // Для версий плагина ниже 2.0.12538
                return new window.ActiveXObject(name);
            }
        }
        // создаются объекты NPAPI
        return pluginObject.CreateObject(name);
    }

    function decimalToHexString(number) {
        if (number < 0) {
            number = 0xFFFFFFFF + number + 1;
        }

        return number.toString(16).toUpperCase();
    }

    function GetMessageFromException(e) {
        var err = e.message;
        if (!err) {
            err = e;
        } else if (e.number) {
            err += " (0x" + decimalToHexString(e.number) + ")";
        }
        return err;
    }

    function getLastError(exception) {
        if (isNativeMessageSupported() || isIE() || isIOS()) {
            return GetMessageFromException(exception);
        }

        try {
            return pluginObject.getLastError();
        } catch (e) {
            return GetMessageFromException(exception);
        }
    }

    // Функция для удаления созданных объектов
    function ReleasePluginObjects() {
        // noinspection JSUnresolvedVariable
        return cpcsp_chrome_nmcades.ReleasePluginObjects();
    }

    // Функция активации асинхронных объектов КриптоПро ЭЦП Browser plug-in
    function CreateObjectAsync(name) {
        return pluginObject.CreateObjectAsync(name);
    }

    // Функции для IOS
    // noinspection JSUnusedGlobalSymbols
    var ru_cryptopro_npcades_10_native_bridge = {
        callbacksCount: 1,
        callbacks: {},

        // Automatically called by native layer when a result is available
        resultForCallback: function resultForCallback(callbackId, resultArray) {
            var callback = ru_cryptopro_npcades_10_native_bridge.callbacks[callbackId];
            if (!callback) {
                return;
            }
            callback.apply(null, resultArray);
        },

        // Use this in javascript to request native objective-c code
        // functionName : string (I think the name is explicit :p)
        // args : array of arguments
        // callback : function with n-arguments that is going to be called when the native code returned
        call: function call(functionName, args, callback) {
            var hasCallback = callback && typeof callback === "function";
            var callbackId = hasCallback ? ru_cryptopro_npcades_10_native_bridge.callbacksCount++ : 0;

            if (hasCallback) {
                ru_cryptopro_npcades_10_native_bridge.callbacks[callbackId] = callback;
            }

            var iframe = document.createElement("IFRAME");
            var arrObjs = new Array("_CPNP_handle");
            try {
                iframe.setAttribute("src", "cpnp-js-call:" + functionName + ":" + callbackId + ":" + encodeURIComponent(window.JSON.stringify(args, arrObjs)));
            } catch (e) {
                window.alert(e);
            }
            document.documentElement.appendChild(iframe);
            iframe.parentNode.removeChild(iframe);
            iframe = null;
        }
    };

    function call_ru_cryptopro_npcades_10_native_bridge(functionName, array) {
        var tmpobj;
        var ex;
        ru_cryptopro_npcades_10_native_bridge.call(functionName, array, function (e, response) {
            ex = e;
            var tmpobj = "";
            try {
                tmpobj = window.JSON.parse(response);
            }
            catch (err) {
                tmpobj = response;
            }
            if (typeof tmpobj === "string") {
                tmpobj = tmpobj.replace(/\\\n/gm, "\n");
                tmpobj = tmpobj.replace(/\\\r/gm, "\r");
            }
        });
        if (ex) {
            throw ex;
        }
        return tmpobj;
    }

    function show_firefox_missing_extension_dialog() {
        if (!window.cadesplugin_skip_extension_install) {
            var ovr = document.createElement('div');
            ovr.id = "cadesplugin_ovr";
            ovr.style = "visibility: hidden; position: fixed; left: 0; top: 0; width:100%; height:100%; background-color: rgba(0,0,0,0.7)";
            ovr.innerHTML = "<div id='cadesplugin_ovr_item' style='position:relative; max-width:400px; margin:100px auto; background-color:#fff; border:2px solid #000; padding:10px; text-align:center; opacity: 1; z-index: 1500'>" +
                "<button id='cadesplugin_close_install' style='float: right; font-size: 10px; background: transparent; border: 1; margin: -5px'>X</button>" +
                "<p>Для работы КриптоПро ЭЦП Browser plugin на данном сайте необходимо расширение для браузера. Убедитесь, что оно у Вас включено или установите его." +
                "<p><a href='https://www.cryptopro.ru/sites/default/files/products/cades/extensions/firefox_cryptopro_extension_latest.xpi'>Скачать расширение</a></p>" +
                "</div>";
            document.getElementsByTagName("Body")[0].appendChild(ovr);
            document.getElementById("cadesplugin_close_install").addEventListener('click', function () {
                plugin_loaded_error("Плагин недоступен");
                document.getElementById("cadesplugin_ovr").style.visibility = 'hidden';
            });

            ovr.addEventListener('click', function () {
                plugin_loaded_error("Плагин недоступен");
                document.getElementById("cadesplugin_ovr").style.visibility = 'hidden';
            });
            ovr.style.visibility = "visible";
        }
    }

    function firefox_or_safari_nmcades_onload() {
        // noinspection JSUnresolvedVariable
        if (window.cadesplugin_extension_loaded_callback) {
            window.cadesplugin_extension_loaded_callback();
        }
        isFireFoxExtensionLoaded = true;
        // noinspection JSUnresolvedVariable,JSUnresolvedFunction
        cpcsp_chrome_nmcades.check_chrome_plugin(plugin_loaded, plugin_loaded_error);
    }

    function load_js_script(url, successFunc, errorFunc) {
        var script = document.createElement("script");
        script.setAttribute("type", "text/javascript");
        script.setAttribute("src", url);
        script.onerror = errorFunc;
        script.onload = successFunc;
        document.getElementsByTagName("head")[0].appendChild(script);
    }

    function nmcades_api_onload() {
        if (!isIE() && !isFireFox && !isSafari) {
            // noinspection JSUnresolvedVariable
            if (window.cadesplugin_extension_loaded_callback) {
                window.cadesplugin_extension_loaded_callback();
            }
        }
        window.postMessage("cadesplugin_echo_request", "*");
        window.addEventListener("message", function (event) {
            if (typeof (event.data) !== "string" || !event.data.match("cadesplugin_loaded")) {
                return;
            }
            if (cadesplugin_loaded_event_recieved) {
                return;
            }
            if (isFireFox || isSafari) {
                // Для Firefox, Сафари вместе с сообщением cadesplugin_loaded прилетает url для загрузки nmcades_plugin_api.js
                var url = event.data.substring(event.data.indexOf("url:") + 4);
                if (!url.match("^(moz|safari)-extension://[a-zA-Z0-9/_-]+/nmcades_plugin_api.js$")) {
                    cpcsp_console_log(cadesplugin.LOG_LEVEL_ERROR, "Bad url \"" + url + "\" for load CryptoPro Extension for CAdES Browser plug-in");
                    plugin_loaded_error();
                    return;
                }
                load_js_script(url, firefox_or_safari_nmcades_onload, plugin_loaded_error);
            } else {
                // noinspection JSUnresolvedVariable,JSUnresolvedFunction
                cpcsp_chrome_nmcades.check_chrome_plugin(plugin_loaded, plugin_loaded_error);
            }
            cadesplugin_loaded_event_recieved = true;
        }, false);
    }

    // Загружаем расширения для Chrome, Opera, YaBrowser, FireFox, Edge, Safari
    function load_extension() {
        if (isFireFox || isSafari) {
            // вызываем callback руками т.к. нам нужно узнать ID расширения. Он уникальный для браузера.
            nmcades_api_onload();
            return;
        }
        var operaUrl = "chrome-extension://epebfcehmdedogndhlcacafjaacknbcm/nmcades_plugin_api.js";
        var manifestv2Url = "chrome-extension://iifchhfnnmpdbibifmljnfjhpififfog/nmcades_plugin_api.js";
        var manifestv3Url = "chrome-extension://pfhgbfnnjiafkhfdkmpiflachepdcjod/nmcades_plugin_api.js";
        if (isYandex) {
            // в асинхронном варианте для Yandex пробуем подключить расширения по очереди
            load_js_script(operaUrl, nmcades_api_onload, function () {
                load_js_script(manifestv2Url, nmcades_api_onload, function () {
                    load_js_script(manifestv3Url, nmcades_api_onload, plugin_loaded_error);
                });
            });
            return;
        }
        if (isOpera) {
            // в асинхронном варианте для Opera подключаем расширение из Opera Store.
            load_js_script(operaUrl, nmcades_api_onload, plugin_loaded_error);
            return;
        }
        // для Chrome, Chromium, Chromium Edge расширение из Chrome store
        load_js_script(manifestv2Url, nmcades_api_onload, function () {
            load_js_script(manifestv3Url, nmcades_api_onload, plugin_loaded_error);
        });
    }

    //Загружаем плагин для NPAPI
    function load_npapi_plugin() {
        var elem = document.createElement('object');
        elem.setAttribute("id", "cadesplugin_object");
        elem.setAttribute("type", "application/x-cades");
        elem.setAttribute("style", "visibility: hidden");
        document.getElementsByTagName("body")[0].appendChild(elem);
        pluginObject = document.getElementById("cadesplugin_object");
        if (isIE()) {
            var elem1 = document.createElement('object');
            elem1.setAttribute("id", "certEnrollClassFactory");
            elem1.setAttribute("classid", "clsid:884e2049-217d-11da-b2a4-000e7bbb2b09");
            elem1.setAttribute("style", "visibility: hidden");
            document.getElementsByTagName("body")[0].appendChild(elem1);
            var elem2 = document.createElement('object');
            elem2.setAttribute("id", "webClassFactory");
            elem2.setAttribute("classid", "clsid:B04C8637-10BD-484E-B0DA-B8A039F60024");
            elem2.setAttribute("style", "visibility: hidden");
            document.getElementsByTagName("body")[0].appendChild(elem2);
        }
    }

    //Отправляем событие что все ок.
    function plugin_loaded() {
        plugin_resolved = 1;
        if (canPromise) {
            plugin_resolve();
        } else {
            window.postMessage("cadesplugin_loaded", "*");
        }
    }

    //Отправляем событие что сломались.
    function plugin_loaded_error(msg) {
        if (typeof (msg) === 'undefined' || typeof (msg) === 'object') {
            msg = "Плагин недоступен";
        }
        plugin_resolved = 1;
        if (canPromise) {
            plugin_reject(msg);
        } else {
            window.postMessage("cadesplugin_load_error", "*");
        }
    }

    //проверяем что у нас хоть какое то событие ушло, и если не уходило кидаем еще раз ошибку
    function check_load_timeout() {
        if (plugin_resolved === 1) {
            return;
        }
        if (isFireFox && !isFireFoxExtensionLoaded) {
            show_firefox_missing_extension_dialog();
        }
        plugin_resolved = 1;
        if (canPromise) {
            plugin_reject("Истекло время ожидания загрузки плагина");
        } else {
            window.postMessage("cadesplugin_load_error", "*");
        }
    }

    function check_npapi_plugin() {
        try {
            CreateObject("CAdESCOM.About");
            plugin_loaded();
        } catch (err) {
            document.getElementById("cadesplugin_object").style.display = 'none';
            // Объект создать не удалось, проверим, установлен ли
            // вообще плагин. Такая возможность есть не во всех браузерах
            // noinspection JSDeprecatedSymbols
            var mimetype = window.navigator.mimeTypes["application/x-cades"];
            if (mimetype) {
                // noinspection JSDeprecatedSymbols
                var plugin = mimetype.enabledPlugin;
                if (plugin) {
                    plugin_loaded_error("Плагин загружен, но не создаются обьекты");
                } else {
                    plugin_loaded_error("Ошибка при загрузке плагина");
                }
            } else {
                plugin_loaded_error("Плагин недоступен");
            }
        }
    }

    // Проверяем работает ли плагин
    function check_plugin_working() {
        var div = document.createElement("div");
        div.innerHTML = "<!--[if lt IE 9]><i></i><![endif]-->";
        var isIeLessThan9 = (div.getElementsByTagName("i").length === 1);
        if (isIeLessThan9) {
            plugin_loaded_error("Internet Explorer версии 8 и ниже не поддерживается");
            return;
        }

        if (isNativeMessageSupported()) {
            load_extension();
        } else if (!canPromise) {
            window.addEventListener("message", function (event) {
                if (event.data !== "cadesplugin_echo_request") {
                    return;
                }
                load_npapi_plugin();
                check_npapi_plugin();
            }, false);
        } else {
            if (document.readyState === "complete") {
                load_npapi_plugin();
                check_npapi_plugin();
            } else {
                window.addEventListener("load", function (event) {
                    load_npapi_plugin();
                    check_npapi_plugin();
                }, false);
            }
        }
    }

    function set_pluginObject(obj) {
        pluginObject = obj;
    }

    function is_capilite_enabled() {
        // noinspection JSUnresolvedVariable
        return ((typeof (cadesplugin.EnableInternalCSP) !== 'undefined') && cadesplugin.EnableInternalCSP);
    }

    function set_load_timeout() {
        // noinspection JSUnresolvedVariable
        if (window.cadesplugin_load_timeout) {
            window.setTimeout(check_load_timeout, window.cadesplugin_load_timeout);
        } else {
            window.setTimeout(check_load_timeout, 20000);
        }
    }

    // noinspection JSUnusedLocalSymbols
    var onVisibilityChange = function (event) {
        if (document.hidden === false) {
            document.removeEventListener("visibilitychange", onVisibilityChange);
            set_load_timeout();
            check_plugin_working();
        }
    };

    //Export
    cadesplugin.JSModuleVersion = "2.4.1";
    cadesplugin.async_spawn = async_spawn;
    cadesplugin.set = set_pluginObject;
    cadesplugin.set_log_level = set_log_level;
    cadesplugin.get_extension_version = get_extension_version;
    cadesplugin.get_extension_id = get_extension_id;
    cadesplugin.getLastError = getLastError;
    cadesplugin.is_capilite_enabled = is_capilite_enabled;

    if (isNativeMessageSupported()) {
        cadesplugin.CreateObjectAsync = CreateObjectAsync;
        cadesplugin.ReleasePluginObjects = ReleasePluginObjects;
    }

    if (!isNativeMessageSupported()) {
        cadesplugin.CreateObject = CreateObject;
    }

    set_constantValues();

    cadesplugin.current_log_level = cadesplugin.LOG_LEVEL_ERROR;
    window.cadesplugin = cadesplugin;
    if (isSafari && document.hidden) {
        document.addEventListener("visibilitychange", onVisibilityChange);
        return;
    }
    set_load_timeout();
    check_plugin_working();
}());
