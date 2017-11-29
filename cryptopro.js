/**
 * CryptoPRO simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */

function DN(){};
DN.prototype.toString = function(){
	var ret = '';
	for(var i in this) if(this.hasOwnProperty(i)) ret += i + '="' + this[i].replace(/"/g, '') + '", ';
	return ret;
};

function CryptoPro() {
	var X509KeySpec = {
		XCN_AT_NONE        : 0x0,
		XCN_AT_KEYEXCHANGE : 0x1,
		XCN_AT_SIGNATURE   : 0x2
	};
	var X509PrivateKeyExportFlags =  {
		XCN_NCRYPT_ALLOW_EXPORT_NONE               : 0,
		XCN_NCRYPT_ALLOW_EXPORT_FLAG               : 0x1,
		XCN_NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG     : 0x2,
		XCN_NCRYPT_ALLOW_ARCHIVING_FLAG            : 0x4,
		XCN_NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG  : 0x8
	};
	var X509CertificateEnrollmentContext = {
		ContextUser                      : 0x1,
		ContextMachine                   : 0x2,
		ContextAdministratorForceMachine : 0x3
	};
	var X509KeyUsageFlags = {
		XCN_CERT_NO_KEY_USAGE                 : 0,
		XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE  : 0x80,
		XCN_CERT_NON_REPUDIATION_KEY_USAGE    : 0x40,
		XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE   : 0x20,
		XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE  : 0x10,
		XCN_CERT_KEY_AGREEMENT_KEY_USAGE      : 0x8,
		XCN_CERT_KEY_CERT_SIGN_KEY_USAGE      : 0x4,
		XCN_CERT_OFFLINE_CRL_SIGN_KEY_USAGE   : 0x2,
		XCN_CERT_CRL_SIGN_KEY_USAGE           : 0x2,
		XCN_CERT_ENCIPHER_ONLY_KEY_USAGE      : 0x1,
		XCN_CERT_DECIPHER_ONLY_KEY_USAGE      : ( 0x80 << 8 )
	};
	var X500NameFlags = {
		XCN_CERT_NAME_STR_NONE                       : 0,
		XCN_CERT_SIMPLE_NAME_STR                     : 1,
		XCN_CERT_OID_NAME_STR                        : 2,
		XCN_CERT_X500_NAME_STR                       : 3,
		XCN_CERT_XML_NAME_STR                        : 4,
		XCN_CERT_NAME_STR_SEMICOLON_FLAG             : 0x40000000,
		XCN_CERT_NAME_STR_NO_PLUS_FLAG               : 0x20000000,
		XCN_CERT_NAME_STR_NO_QUOTING_FLAG            : 0x10000000,
		XCN_CERT_NAME_STR_CRLF_FLAG                  : 0x8000000,
		XCN_CERT_NAME_STR_COMMA_FLAG                 : 0x4000000,
		XCN_CERT_NAME_STR_REVERSE_FLAG               : 0x2000000,
		XCN_CERT_NAME_STR_FORWARD_FLAG               : 0x1000000,
		XCN_CERT_NAME_STR_DISABLE_IE4_UTF8_FLAG      : 0x10000,
		XCN_CERT_NAME_STR_ENABLE_T61_UNICODE_FLAG    : 0x20000,
		XCN_CERT_NAME_STR_ENABLE_UTF8_UNICODE_FLAG   : 0x40000,
		XCN_CERT_NAME_STR_FORCE_UTF8_DIR_STR_FLAG    : 0x80000,
		XCN_CERT_NAME_STR_DISABLE_UTF8_DIR_STR_FLAG  : 0x100000
	};
	var EncodingType = {
		XCN_CRYPT_STRING_BASE64HEADER         : 0,
		XCN_CRYPT_STRING_BASE64               : 0x1,
		XCN_CRYPT_STRING_BINARY               : 0x2,
		XCN_CRYPT_STRING_BASE64REQUESTHEADER  : 0x3,
		XCN_CRYPT_STRING_HEX                  : 0x4,
		XCN_CRYPT_STRING_HEXASCII             : 0x5,
		XCN_CRYPT_STRING_BASE64_ANY           : 0x6,
		XCN_CRYPT_STRING_ANY                  : 0x7,
		XCN_CRYPT_STRING_HEX_ANY              : 0x8,
		XCN_CRYPT_STRING_BASE64X509CRLHEADER  : 0x9,
		XCN_CRYPT_STRING_HEXADDR              : 0xa,
		XCN_CRYPT_STRING_HEXASCIIADDR         : 0xb,
		XCN_CRYPT_STRING_HEXRAW               : 0xc,
		XCN_CRYPT_STRING_NOCRLF               : 0x40000000,
		XCN_CRYPT_STRING_NOCR                 : 0x80000000
	};
	var InstallResponseRestrictionFlags = {
		AllowNone                  : 0x00000000,
		AllowNoOutstandingRequest  : 0x00000001,
		AllowUntrustedCertificate  : 0x00000002,
		AllowUntrustedRoot         : 0x00000004
	};

	var maxLengthCSPName = 127;
	//If the string contains fewer than 128 bytes, the Length field of the TLV triplet requires only one byte to specify the content length.
	//If the string is more than 127 bytes, bit 7 of the Length field is set to 1 and bits 6 through 0 specify the number of additional bytes used to identify the content length.

	var asn1UTF8StringTag = 0x0c; // 12, UTF8String
	// https://www.cryptopro.ru/forum2/default.aspx?g=posts&m=38467#post38467

	var cadesErrorMesages = {
		'0x800B010A': 'Не удается построить цепочку сертификатов для доверенного корневого центра'
	};

	var canAsync = !!cadesplugin.CreateObjectAsync;

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {promise}
	 */
	this.init = function(){
		var defer = $.Deferred();

		if(typeof(Uint8Array) != 'function') {
			defer.reject('Upgrade your browser to something supports Uint8Array!');
		}
		if(!window.btoa) {
			defer.reject('Upgrade your browser to something supports native base64 encoding!');
		}
		else if(window.cadesplugin) {
			if(canAsync) {
				cadesplugin.then(function(){
					return cadesplugin.CreateObjectAsync("CAdESCOM.About");
				}).then(function(oAbout){
					return oAbout.Version;
				}).then(function(CurrentPluginVersion){
					defer.resolve(CurrentPluginVersion);
				}, function(e) {
					defer.reject(e.message || e); // 'Плагин не загружен'
				});
			}
			else {
				 try {
					var oAbout = cadesplugin.CreateObject("CAdESCOM.About");
					var CurrentPluginVersion = oAbout.Version;
					defer.resolve(CurrentPluginVersion);
				}
				catch(e) {
					defer.reject(e.message || e); // 'Плагин не загружен'
				}
			}
		}
		else {
			defer.reject('КриптоПро ЭЦП Browser plug-in не обнаружен');
		}
		return defer.promise();
	};

	/**
	 * Создание CSR.
	 * @param {DN} dn
	 * @param {string} pin
	 * @param {array} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @returns {promise}
	 * @see DN
	 */
	this.generateCSR = function(dn, pin, ekuOids){
		if(!ekuOids || !ekuOids.length) {
			ekuOids = [
				'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
				'1.3.6.1.5.5.7.3.4' // Защищенная электронная почта
			];
		}
		var defer = $.Deferred();
		if(canAsync) {
			var oEnroll, oRequest, oPrivateKey, oExtensions, oKeyUsage, oEnhancedKeyUsage, oEnhancedKeyUsageOIDs, aOIDs, oSstOID, oDn, oCspInformations, sCSPName, oSubjectSignTool;
			cadesplugin.then(function(){
				return Promise.all([
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509Enrollment'), // 0
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509CertificateRequestPkcs10'), // 1
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509PrivateKey'), // 2
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509ExtensionKeyUsage'), // 3
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509ExtensionEnhancedKeyUsage'), // 4
					cadesplugin.CreateObjectAsync('X509Enrollment.CObjectIds'), // 5
					cadesplugin.CreateObjectAsync('X509Enrollment.CX500DistinguishedName'), // 6
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509Extensions'), // 7
					cadesplugin.CreateObjectAsync('X509Enrollment.CCspInformations'), // 8
					cadesplugin.CreateObjectAsync('X509Enrollment.CX509Extension') //9
				]);
			}).then(function(objects){
				oEnroll = objects[0];
				oRequest = objects[1];
				oPrivateKey = objects[2];
				oKeyUsage = objects[3];
				oEnhancedKeyUsage = objects[4];
				oEnhancedKeyUsageOIDs = objects[5];
				oDn = objects[6];
				oExtensions = objects[7];
				oCspInformations = objects[8];
				oSubjectSignTool = objects[9];

				return oCspInformations.AddAvailableCsps();
			}).then(function(){
				return oCspInformations.Count;
			}).then(function(cnt){
				if(!cnt) throw new Error('No CSP informations!');
				var aPromises = [];
				for(var i=0; i<cnt; i++) aPromises.push(oCspInformations.ItemByIndex(i));
				return Promise.all(aPromises);
			}).then(function(aCspInformation){
				var aPromises = [];
				for(var i in aCspInformation) {
					var a = aCspInformation[i];
					aPromises.push(a.LegacyCsp);
					aPromises.push(a.Type);
					aPromises.push(a.Name);
				}
				return Promise.all(aPromises);
			}).then(function(aCspInfo){
				for(var i=0; i<aCspInfo.length; i+=3) {
					var bLegacyCsp = aCspInfo[i];
					var nType = aCspInfo[i+1];
					var sName = sCSPName = aCspInfo[i+2];

					if(bLegacyCsp && nType == 75) {
						var aPromises = [
							//oPrivateKey.propset_Length(512),
							oPrivateKey.propset_KeySpec(X509KeySpec.XCN_AT_SIGNATURE),
							oPrivateKey.propset_Existing(false),
							oPrivateKey.propset_ExportPolicy(X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG),
							oPrivateKey.propset_ProviderType(nType),
							oPrivateKey.propset_ProviderName(sName)
						];
						if(pin) aPromises.push(oPrivateKey.propset_Pin(pin));
						return Promise.all(aPromises);
					}
				}
				throw new Error('No suitable CSP found!');
			}).then(function(){
				return oRequest.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser, oPrivateKey, '');
			}).then(function(){
				return oKeyUsage.InitializeEncode(
					X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
					X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
					X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
					X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE
				);
			}).then(function(){
				var promises = [];
				for(var i=0; i<ekuOids.length; i++) {
					promises.push(cadesplugin.CreateObjectAsync('X509Enrollment.CObjectId'));
				}
				return Promise.all(promises);
			}).then(function(objects){				
				aOIDs = objects;
				var promises = [];
				for(var i=0; i<ekuOids.length; i++) {
					aOIDs[i].InitializeFromValue(ekuOids[i]);
				}
				return Promise.all(promises);
			}).then(function(){
				var promises = [];
				for(var i=0; i<ekuOids.length; i++) {
					oEnhancedKeyUsageOIDs.Add(aOIDs[i]);
				}
				return Promise.all(promises);
			}).then(function(){
				return cadesplugin.CreateObjectAsync('X509Enrollment.CObjectId');
			}).then(function(oid){
				oSstOID = oid;
				return oSstOID.InitializeFromValue('1.2.643.100.111'); // Subject Sign Tool
			}).then(function(){
				var shortName = sCSPName.slice(0, maxLengthCSPName);
				var utf8arr = stringToUtf8ByteArray(shortName);
				utf8arr.unshift(asn1UTF8StringTag, utf8arr.length); 
				var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(utf8arr)));				
				//return oSubjectSignTool.Initialize(oSstOID, EncodingType.XCN_CRYPT_STRING_BINARY, utf8string); // не работает на винде
				return oSubjectSignTool.Initialize(oSstOID, EncodingType.XCN_CRYPT_STRING_BASE64, base64String);
			}).then(function(){
				return oEnhancedKeyUsage.InitializeEncode(oEnhancedKeyUsageOIDs);
			}).then(function(){
				return oRequest.X509Extensions;
			}).then(function(ext){
				oExtensions = ext;
				return Promise.all([
					oExtensions.Add(oKeyUsage),
					oExtensions.Add(oEnhancedKeyUsage),
					oExtensions.Add(oSubjectSignTool)
				]);
			}).then(function(){
				var strName = dn.toString();
				return oDn.Encode(strName, X500NameFlags.XCN_CERT_X500_NAME_STR);
			}).then(function(){
				return oRequest.propset_Subject(oDn);
			}).then(function(){
				return oEnroll.InitializeFromRequest(oRequest);
			}).then(function(){
				return oEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
			}).then(function(csr){
				defer.resolve(csr);
			}, function(e){
				console.log(arguments);				
				defer.reject(e.message || e);
			});
		}
		else {
			try {
				var oCspInformations = cadesplugin.CreateObject('X509Enrollment.CCspInformations');
				var oEnroll = cadesplugin.CreateObject('X509Enrollment.CX509Enrollment');
				var oRequest = cadesplugin.CreateObject('X509Enrollment.CX509CertificateRequestPkcs10');
				var oPrivateKey = cadesplugin.CreateObject('X509Enrollment.CX509PrivateKey');
				var oKeyUsage = cadesplugin.CreateObject('X509Enrollment.CX509ExtensionKeyUsage');
				var oEnhancedKeyUsage = cadesplugin.CreateObject('X509Enrollment.CX509ExtensionEnhancedKeyUsage');
				var oEnhancedKeyUsageOIDs = cadesplugin.CreateObject('X509Enrollment.CObjectIds');
				var oDn = cadesplugin.CreateObject('X509Enrollment.CX500DistinguishedName');
				var oExtensions = cadesplugin.CreateObject('X509Enrollment.CX509Extensions');

				var cspType, cspName;
				oCspInformations.AddAvailableCsps();
				for(var i=0; i<oCspInformations.Count; i++) {
					var oCspInfo = oCspInformations.ItemByIndex(i);
					if(oCspInfo.LegacyCsp && oCspInfo.Type == 75) {
						cspType = oCspInfo.Type;
						cspName = oCspInfo.Name;
					}
				}
				if(!cspName || !cspType) throw new Error('No suitable CSP!');

				//oPrivateKey.Length = 512;
				oPrivateKey.KeySpec = X509KeySpec.XCN_AT_SIGNATURE;
				oPrivateKey.Existing = false;
				oPrivateKey.ExportPolicy = X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG;
				oPrivateKey.ProviderName = cspName;
				oPrivateKey.ProviderType = cspType;
				// под виндой нельзя задать ПИН тк не дает доступа
				//oPrivateKey.Pin = pin; //CX509PrivateKey::put_Pin: Access is denied. 0x80070005 (WIN32: 5)

				oRequest.InitializeFromPrivateKey(X509CertificateEnrollmentContext.ContextUser, oPrivateKey, '');

				oKeyUsage.InitializeEncode(
					X509KeyUsageFlags.XCN_CERT_DIGITAL_SIGNATURE_KEY_USAGE |
					X509KeyUsageFlags.XCN_CERT_KEY_ENCIPHERMENT_KEY_USAGE |
					X509KeyUsageFlags.XCN_CERT_NON_REPUDIATION_KEY_USAGE |
					X509KeyUsageFlags.XCN_CERT_DATA_ENCIPHERMENT_KEY_USAGE
				);

				var aEnhancedKeyUsageOIDs = [];
				for(var i=0; i<ekuOids.length; i++) {
					aEnhancedKeyUsageOIDs.push(cadesplugin.CreateObject('X509Enrollment.CObjectId'));
					aEnhancedKeyUsageOIDs[i].InitializeFromValue(ekuOids[i]);
					oEnhancedKeyUsageOIDs.Add(aEnhancedKeyUsageOIDs[i]);
				}

				oEnhancedKeyUsage.InitializeEncode(oEnhancedKeyUsageOIDs);

				oRequest.X509Extensions.Add(oKeyUsage);
				oRequest.X509Extensions.Add(oEnhancedKeyUsage);

				//subject sign tool
				var ssOID = cadesplugin.CreateObject('X509Enrollment.CObjectId');
				ssOID.InitializeFromValue('1.2.643.100.111');
				var shortName = cspName.slice(0, maxLengthCSPName);
				var utf8arr = stringToUtf8ByteArray(shortName);
				utf8arr.unshift(asn1UTF8StringTag, shortName.length);
				var base64String = btoa(String.fromCharCode.apply(null, new Uint8Array(utf8arr)));
				var oSubjectSignTool = cadesplugin.CreateObject('X509Enrollment.CX509Extension');
				oSubjectSignTool.Initialize(ssOID, EncodingType.XCN_CRYPT_STRING_BASE64, base64String);
				oRequest.X509Extensions.Add(oSubjectSignTool);

				var strName = dn.toString();
				oDn.Encode(strName, X500NameFlags.XCN_CERT_X500_NAME_STR);
				
				oRequest.Subject = oDn;

				oEnroll.InitializeFromRequest(oRequest);

				var csr = oEnroll.CreateRequest(EncodingType.XCN_CRYPT_STRING_BASE64);
				defer.resolve(csr);
			}
			catch(e) {
				console.log(e);				
				defer.reject(e.message || e);
			}
		}
		return defer.promise();
	};

	/**
	 * Запись сертификата.
	 * @param {string} certBase64
	 * @returns {promise}
	 */
	this.writeCertificate = function(certBase64){
		var defer = $.Deferred();
		if(canAsync) {
			var oEnroll, oStore, existingSha = [];
			this.listCertificates().then(function(certs){
				for(var i in certs) {
					existingSha.push(certs[i].shift());
				}
				return cadesplugin.CreateObjectAsync('X509Enrollment.CX509Enrollment');
			}).then(function(enroll){
				oEnroll = enroll;
				return oEnroll.Initialize(X509CertificateEnrollmentContext.ContextUser);
			}).then(function(){
				return oEnroll.InstallResponse(InstallResponseRestrictionFlags.AllowNone, certBase64, EncodingType.XCN_CRYPT_STRING_BASE64, '');
			}).then(this.listCertificates).then(function(certs){
				for(var i in certs) {
					var sha = certs[i].shift();
					if(existingSha.indexOf(sha) < 0) defer.resolve(sha);
				}
				defer.reject('Не удалось найти установленный сертификат по отпечатку');
			}, function(e){
				console.log(arguments);
				defer.reject(e.message || e);
			});
		}
		else {
			try {
				var existingSha = [];
				var oStore = cadesplugin.CreateObject("CAPICOM.Store");
				oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
				var oCertificates = oStore.Certificates;
				for(var i=1; i<=oCertificates.Count; i++) {
					existingSha.push(oCertificates.Item(i).Thumbprint);
				}
				oStore.Close();

				var oEnroll = cadesplugin.CreateObject('X509Enrollment.CX509Enrollment');
				oEnroll.Initialize(X509CertificateEnrollmentContext.ContextUser);
				oEnroll.InstallResponse(InstallResponseRestrictionFlags.AllowNone, certBase64, EncodingType.XCN_CRYPT_STRING_BASE64, '');

				var oStore = cadesplugin.CreateObject("CAPICOM.Store");
				oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
				var oCertificates = oStore.Certificates;
				for(var i=1; i<=oCertificates.Count; i++) {
					var sha = oCertificates.Item(i).Thumbprint;
					if(existingSha.indexOf(sha) < 0) defer.resolve(sha);
				}
				oStore.Close();
				defer.reject('Не удалось найти установленный сертификат по отпечатку');
			}
			catch(e) {
				console.log(e);
				defer.reject(e.message || e);
			}
		}
		return defer.promise();
	};

	this.certificateInfo = function(certThumbprint){
		var defer = $.Deferred();
		var infoToString = function(){
			return	  'Название:              ' + this.Name +
					'\nИздатель:              ' + this.IssuerName +
					'\nСубъект:               ' + this.SubjectName +
					'\nВерсия:                ' + this.Version +
					'\nСерийный №:            ' + this.SerialNumber +
					'\nОтпечаток SHA1:        ' + this.Thumbprint +
					'\nНе дествителен до:     ' + this.ValidFromDate +
					'\nНе действителен после: ' + this.ValidToDate +
					'\nПриватный ключ:        ' + (this.HasPrivateKey ? 'Есть' : 'Нет') +
					'\nВалидный:              ' + (this.IsValid ? 'Да' : 'Нет');
		};
		if(canAsync) {
			var oStore, oCertificates, oCertificate, oInfo = {};
			cadesplugin.then(function(){
				return cadesplugin.CreateObjectAsync("CAPICOM.Store");
			}).then(function(o){
				oStore = o;
				return oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE,
								   cadesplugin.CAPICOM_MY_STORE,
								   cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
			}).then(function(){
				return oStore.Certificates;
			}).then(function(certificates){
				return certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint);
			}).then(function(certificates){
				oCertificates = certificates;
				return oCertificates.Count;
			}).then(function(count){
				if(count != 1) throw new Error('Не обнаружено сертификатов c указанным SHA1');
				return oCertificates.Item(1);
			}).then(function(certificate){
				oCertificate = certificate;
				return oStore.Close();
			}).then(function(){
				var promises = [
					oCertificate.HasPrivateKey(),
					oCertificate.IsValid(),
					oCertificate.IssuerName,
					oCertificate.SerialNumber,
					oCertificate.SubjectName,
					oCertificate.Thumbprint,
					oCertificate.ValidFromDate,
					oCertificate.ValidToDate,
					oCertificate.Version
				];
				return Promise.all(promises);
			}).then(function(a){
				oInfo = {
					HasPrivateKey: a[0],
					IsValid: undefined, // a[1],
					IssuerName: a[2],
					SerialNumber: a[3],
					SubjectName: a[4],
					Name: undefined,
					Thumbprint: a[5],
					ValidFromDate: new Date(a[6]),
					ValidToDate: new Date(a[7]),
					Version: a[8]
				};
				var oCertificateStatus = a[1];
				return oCertificateStatus.Result;
			}).then(function(result){
				var oParesedSubj = parseSubject(oInfo.SubjectName);
				oInfo.Name = oParesedSubj.toString();
				oInfo.IsValid = result;
				oInfo.toString = infoToString;
				defer.resolve(oInfo);
			}, function(e){
				console.log(arguments);
				if(e.message && e.message.indexOf('0x800B010A')+1) e.message = cadesErrorMesages['0x800B010A'];
				defer.reject(e.message || e);
			});
		}
		else {
			try {
				var oStore = cadesplugin.CreateObject("CAPICOM.Store");
				oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

				var oCertificates = oStore.Certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint);
				if (oCertificates.Count != 1) {
					defer.reject("Не обнаружено сертификатов c указанным SHA1");
				}
				var oCertificate = oCertificates.Item(1);
				oStore.Close();

				var oCertificateStatus = oCertificate.IsValid();
				var oParesedSubj = parseSubject(oCertificate.SubjectName);
				var oInfo = {
					HasPrivateKey: oCertificate.HasPrivateKey(),
					IsValid: oCertificateStatus.Result,
					IssuerName: oCertificate.IssuerName,
					SerialNumber: oCertificate.SerialNumber,
					SubjectName: oCertificate.SubjectName,
					Name: oParesedSubj.toString(),
					Thumbprint: oCertificate.Thumbprint,
					ValidFromDate: new Date(oCertificate.ValidFromDate),
					ValidToDate: new Date(oCertificate.ValidToDate),
					Version: oCertificate.Version
				};
				oInfo.toString = infoToString;
				defer.resolve(oInfo);
			}
			catch (e) {
				console.log(e);
				if(e.message && e.message.indexOf('0x800B010A')+1) e.message = cadesErrorMesages['0x800B010A'];
				defer.reject(e.message || e);
			}
		}
		return defer.promise();
	};

	/**
	 * Получение массива доступных сертификатов [[thumbprint, subject], ...]
	 * @returns {promise}
	 */
	this.listCertificates = function(){
		var defer = $.Deferred();
		if(canAsync) {
			var oStore, oCertificates, ret;
			cadesplugin.then(function(){
				return cadesplugin.CreateObjectAsync("CAPICOM.Store");
			}).then(function(store){				
				oStore = store;
				return oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE,
								   cadesplugin.CAPICOM_MY_STORE,
								   cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
			}).then(function(){
				return oStore.Certificates;
			}).then(function(certificates){
				oCertificates = certificates;
				return certificates.Count;
			}).then(function(count){
				if(count < 1) throw new Error('Не обнаружено сертификатов');
				var certs = [];
				for(var i=1; i<=count; i++) certs.push(oCertificates.Item(i));
				return Promise.all(certs);
			}).then(function(certificates){
				var certs = [];
				for(var i in certificates) certs.push(certificates[i].SubjectName, certificates[i].Thumbprint);
				return Promise.all(certs);
			}).then(function(subjects){
				var certs = [];
				for(var i=0; i<subjects.length; i+=2) {
					var s = parseSubject(subjects[i]);
					certs.push([subjects[i+1], s.toString()]);
				}
				ret = certs;
				return oStore.Close();
			}).then(function(){
				defer.resolve(ret);
			}, function(e){
				console.log(arguments);
				defer.reject(e.message || e);
			});
		}
		else {
			try {
				var oStore = cadesplugin.CreateObject("CAPICOM.Store");
				oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

				var oCertificates = oStore.Certificates;
				var certs = [];
				for(var i=1; i<=oCertificates.Count; i++) {
					var oCertificate = oCertificates.Item(i);
					var s = parseSubject(oCertificate.SubjectName);
					certs.push([oCertificate.Thumbprint, s.toString()]);
				}
				oStore.Close();
				defer.resolve(certs);
			}
			catch(e) {
				console.log(e);
				defer.reject(e.message || e);
			}
		}
		return defer.promise();
	};

	/**
	 * Подпись данных (отсоединенная).
	 * @param {string} dataBase64
	 * @param {string} certThumbprint
	 * @param {string} pin будет запрошен, если отсутствует
	 * @returns {promise}
	 */
	this.signData = function(dataBase64, certThumbprint, pin){
		var defer = $.Deferred();
		if(canAsync) {
			var oStore, oCertificates, oCertificate, oSigner, oSignedData;
			cadesplugin.then(function(){
				return Promise.all([
					cadesplugin.CreateObjectAsync("CAPICOM.Store"),
					cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner"),
					cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData")
				]);
			}).then(function(objects){
				oStore = objects[0];
				oSigner = objects[1];
				oSignedData = objects[2];				
				return oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE,
								   cadesplugin.CAPICOM_MY_STORE,
								   cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
			}).then(function(){
				return oStore.Certificates;
			}).then(function(certificates){				
				return certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint);
			}).then(function(certificates){
				oCertificates = certificates;
				return oCertificates.Count;
			}).then(function(count){
				if(count != 1) throw new Error('Не обнаружено сертификатов c указанным SHA1');
				return oCertificates.Item(1);
			}).then(function(certificate){
				oCertificate = certificate;				
				return oStore.Close();
			}).then(function(){				
				var promises = [
					oSigner.propset_Certificate(oCertificate),
					oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN)
				];
				if(pin) promises.push(oSigner.propset_KeyPin(pin));
				return Promise.all(promises);
			}).then(function(){
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			}).then(function(){
				return oSignedData.propset_Content(dataBase64);
			}).then(function(){
				return oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);
			}).then(function(sign){
				defer.resolve(sign);
			}, function(e){
				console.log(arguments);
				if(e.message && e.message.indexOf('0x800B010A')+1) e.message = cadesErrorMesages['0x800B010A'];
				defer.reject(e.message || e);
			});
		}
		else {
			try {
				var oStore = cadesplugin.CreateObject("CAPICOM.Store");
				oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

				var oCertificates = oStore.Certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint);
				if (oCertificates.Count != 1) {
					defer.reject("Не обнаружено сертификатов c указанным SHA1");
				}
				var oCertificate = oCertificates.Item(1);
				oStore.Close();

				var oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
				oSigner.Certificate = oCertificate;
				oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
				if(pin) oSigner.KeyPin = pin;

				var oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				oSignedData.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
				oSignedData.Content = dataBase64;

				var sSignedMessage = oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);
				defer.resolve(sSignedMessage);
			}
			catch (e) {
				console.log(e);
				if(e.message && e.message.indexOf('0x800B010A')+1) e.message = cadesErrorMesages['0x800B010A'];
				defer.reject(e.message || e);
			}
		}
		return defer.promise();
	};

	/**
	 * Совместная подпись данных (двумя сертификатами).
	 * @param {string} dataBase64
	 * @param {string} certThumbprint SHA1 отпечаток первого сертификата
	 * @param {string} pin будет запрошен, если отсутствует
	 * @param {string} certThumbprint2 SHA1 отпечаток второго сертификата
	 * @param {string} pin2 будет запрошен, если отсутствует
	 * @returns {promise}
	 */
	this.signData2 = function(dataBase64, certThumbprint, pin, certThumbprint2, pin2){
		var defer = $.Deferred();
		if(canAsync) {
			var oStore, oCertificate, oCertificate2, oSigner, oSigner2, oSignedData;
			cadesplugin.then(function(){
				return Promise.all([
					cadesplugin.CreateObjectAsync("CAPICOM.Store"),
					cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner"),					
					cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData")
				]);
			}).then(function(objects){
				oStore = objects[0];
				oSigner = objects[1];				
				oSignedData = objects[2];
				if(!oStore) throw new Error('Не обнаружено хранилище');
				return oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE,
								   cadesplugin.CAPICOM_MY_STORE,
								   cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
			}).then(function(){
				return oStore.Certificates;
			}).then(function(certificates){				
				return Promise.all([
					certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint),
					certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint2)
				]);
			}).then(function(certs){
				return Promise.all([
					certs[0].Count,
					certs[0].Item(1),
					certs[1].Count,
					certs[1].Item(1)
				]);
			}).then(function(certificates){
				if(certificates[0] != 1) new Error('Не найден сертификат по SHA1');
				if(certificates[2] != 1) new Error('Не найден сертификат-2 по SHA1');
				oCertificate = certificates[1];
				oCertificate2 = certificates[3];
				return oStore.Close();
			}).then(function(){
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			}).then(function(){
				return oSignedData.propset_Content(dataBase64);
			}).then(function(){
				var promises = [
					oSigner.propset_Certificate(oCertificate),
					oSigner.propset_KeyPin(pin ? pin : '')
				];
				return Promise.all(promises);
			}).then(function(){
				return oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);
			}).then(function(sign){
				//console.log('sign1: %s', sign);
				var promises = [
					oSigner.propset_Certificate(oCertificate2),
					oSigner.propset_KeyPin(pin2 ? pin2 : '')
				];
				return Promise.all(promises);
			}).then(function(){
				return oSignedData.CoSignCades(oSigner, cadesplugin.CADESCOM_CADES_BES);
			}).then(function(sign2){
				//console.log('sign2: %s', sign2);
				defer.resolve(sign2);
			}, function(e){
				console.log(arguments);
				if(e.message && e.message.indexOf('0x800B010A')+1) e.message = cadesErrorMesages['0x800B010A'];
				defer.reject(e.message || e);
			});
		}
		else {
			try {
				var oStore = cadesplugin.CreateObject("CAPICOM.Store");
				oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

				var oCertificates = oStore.Certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint);
				if (oCertificates.Count != 1) {
					defer.reject("Не найден сертификат по SHA1");
				}
				var oCertificate = oCertificates.Item(1);

				var oCertificates2 = oStore.Certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint2);
				if (oCertificates2.Count != 1) {
					defer.reject("Не найден сертификат-2 по SHA1");
				}
				var oCertificate2 = oCertificates2.Item(1);
				oStore.Close();

				var oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				oSignedData.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
				oSignedData.Content = dataBase64;

				var oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
				oSigner.Certificate = oCertificate;
				//oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
				oSigner.KeyPin = pin ? pin : '';
				var sSignedMessage = oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);

				var oSigner2 = cadesplugin.CreateObject("CAdESCOM.CPSigner");
				oSigner2.Certificate = oCertificate2;
				//oSigner2.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
				oSigner2.KeyPin = pin2 ? pin2 : '';
				var sSignedMessage2 = oSignedData.CoSignCades(oSigner2, cadesplugin.CADESCOM_CADES_BES);

				defer.resolve(sSignedMessage2);
			}
			catch (e) {
				console.log(e);
				if(e.message && e.message.indexOf('0x800B010A')+1) e.message = cadesErrorMesages['0x800B010A'];
				defer.reject(e.message || e);
			}
		}
		return defer.promise();
	};

	function parseSubject(subjectName){
		var o = {
			toString: function(){
				var snils = this['СНИЛС'] || this['SNILS'];
				var inn = this['ИНН'] || this['INN'];
				return '' + this['CN'] + (inn ?  '; ИНН ' + inn : '') + (snils ?  '; СНИЛС ' + snils : '');
			}
		};
		var a = subjectName.split(',');
		for(var i in a) {
			var b = a[i].match(/^\s*([A-ZА-ЯЁ]+)=(.+)$/);
			if(b) o[b[1]] = b[2];
		}
		return o;
	}

	/**
	 * https://stackoverflow.com/questions/18729405/how-to-convert-utf8-string-to-byte-array/28227607#28227607
	 * @param {string} str
	 * @returns {Array}
	 */
	function stringToUtf8ByteArray(str) {
		// TODO(user): Use native implementations if/when available
		var out = [], p = 0;
		for (var i = 0; i < str.length; i++) {
			var c = str.charCodeAt(i);
			if (c < 128) {
				out[p++] = c;
			}
			else if (c < 2048) {
				out[p++] = (c >> 6) | 192;
				out[p++] = (c & 63) | 128;
			}
			else if (
					((c & 0xFC00) == 0xD800) && (i + 1) < str.length &&
					((str.charCodeAt(i + 1) & 0xFC00) == 0xDC00)) {
				// Surrogate Pair
				c = 0x10000 + ((c & 0x03FF) << 10) + (str.charCodeAt(++i) & 0x03FF);
				out[p++] = (c >> 18) | 240;
				out[p++] = ((c >> 12) & 63) | 128;
				out[p++] = ((c >> 6) & 63) | 128;
				out[p++] = (c & 63) | 128;
			}
			else {
				out[p++] = (c >> 12) | 224;
				out[p++] = ((c >> 6) & 63) | 128;
				out[p++] = (c & 63) | 128;
			}
		}
		return out;
	}
}