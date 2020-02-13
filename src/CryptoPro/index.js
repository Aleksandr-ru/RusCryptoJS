/**
 * CryptoPRO simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */

import DN from '../DN';
import { 
	X509KeySpec, 
	X509PrivateKeyExportFlags, 
	X509CertificateEnrollmentContext, 
	X509KeyUsageFlags, 
	X500NameFlags, 
	EncodingType, 
	InstallResponseRestrictionFlags, 
	ProviderTypes, 
	cadesErrorMesages 
} from './constants';
import { convertDN } from '../helpers';

function CryptoPro() {
	//If the string contains fewer than 128 bytes, the Length field of the TLV triplet requires only one byte to specify the content length.
	//If the string is more than 127 bytes, bit 7 of the Length field is set to 1 and bits 6 through 0 specify the number of additional bytes used to identify the content length.
	var maxLengthCSPName = 127;
	
	// https://www.cryptopro.ru/forum2/default.aspx?g=posts&m=38467#post38467
	var asn1UTF8StringTag = 0x0c; // 12, UTF8String

	var canAsync;

	var binded = false;

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {Promise<Object>} версия
	 */
	this.init = function(){
		window.cadesplugin_skip_extension_install = true; // считаем что уже все установлено
		window.allow_firefox_cadesplugin_async = true; // FF 52+

		require('./cadesplugin_api');
		canAsync = !!cadesplugin.CreateObjectAsync;

		return new Promise((resolve, reject) => {
			if(!window.cadesplugin) {
				throw new Error('КриптоПро ЭЦП Browser plug-in не обнаружен');
			}
			resolve();
		}).then(() => {
			if(canAsync) {
				return cadesplugin.then(function(){
					return cadesplugin.CreateObjectAsync("CAdESCOM.About");
				}).then(function(oAbout){
					return oAbout.Version;
				}).then(function(version) {
					return {version };
				}).catch(function(e) {
					// 'Плагин не загружен'
					var err = getError(e);
					throw new Error(err);
				});
			}
			else {
				return new Promise(resolve => {
					try {
						var oAbout = cadesplugin.CreateObject("CAdESCOM.About");
						if(!oAbout || !oAbout.Version) {
							throw new Error('КриптоПро ЭЦП Browser plug-in не загружен');
						}
						var CurrentPluginVersion = oAbout.Version;
						resolve({
							version: CurrentPluginVersion
						});
					}
					catch(e) {
						// 'Плагин не загружен'
						var err = getError(e);
						throw new Error(err);
					}
				});
			}
		});
	};

	/**
	 * Включает кеширование ПИНов от контейнеров чтоб не тробовать повторного ввода
	 * возможно не поддерживается в ИЕ
	 * @see https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=10170
	 * @param {string} userPin не используется
	 * @returns {Promise<boolean>} new binded state
	 */
	this.bind = function(userPin) {
		binded = true;
		return Promise.resolve(binded);
	};

	/**
	 * Заглушка для совместимости
	 * @returns {Promise<boolean>} new binded state
	 */
	this.unbind = function() {
		binded = false;
		return Promise.resolve(binded);
	};

	/**
	 * Создание CSR.
	 * @param {DN} dn
	 * @param {string} pin
	 * @param {array} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @param {int} providerType по умолчанию 80 (ГОСТ Р 34.10-2012) или 75 (ГОСТ Р 34.10-2001)
	 * @returns {Promise<Object>} объект с полями { csr: 'base64 запрос на сертификат' }
	 * @see DN
	 */
	this.generateCSR = function(dn, pin, ekuOids, providerType){
		if(!ekuOids || !ekuOids.length) {
			ekuOids = [
				'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
				'1.3.6.1.5.5.7.3.4' // Защищенная электронная почта
			];
		}
		if(!providerType) {
			providerType = ProviderTypes.GOST_R_34_10_2012;
		}
		if(canAsync) {
			var oEnroll, oRequest, oPrivateKey, oExtensions, oKeyUsage, oEnhancedKeyUsage, oEnhancedKeyUsageOIDs, aOIDs, oSstOID, oDn, oCspInformations, sCSPName, oSubjectSignTool;
			return cadesplugin.then(function(){
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
				var cspType, cspName;
				for(var i=0; i<aCspInfo.length; i+=3) {
					var bLegacyCsp = aCspInfo[i];
					var nType = aCspInfo[i+1];
					var sName = aCspInfo[i+2];

					if(bLegacyCsp && nType == providerType) {
						cspType = nType;
						cspName = sCSPName = sName;
						break;
					}
				}
				if(!cspName || !cspType) {
					throw new Error('No suitable CSP!');
				}

				var aPromises = [
					oPrivateKey.propset_KeySpec(X509KeySpec.XCN_AT_SIGNATURE),
					oPrivateKey.propset_Existing(false),
					oPrivateKey.propset_ExportPolicy(X509PrivateKeyExportFlags.XCN_NCRYPT_ALLOW_EXPORT_FLAG),
					oPrivateKey.propset_ProviderType(cspType),
					oPrivateKey.propset_ProviderName(cspName)
				];
				if(pin) aPromises.push(oPrivateKey.propset_Pin(pin));
				return Promise.all(aPromises);
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
				return { csr };
			}).catch(function(e){
				console.log(arguments);
				var err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
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
						if(oCspInfo.LegacyCsp && oCspInfo.Type == providerType) {
							cspType = oCspInfo.Type;
							cspName = oCspInfo.Name;
							break;
						}
					}
					if(!cspName || !cspType) {
						throw new Error('No suitable CSP!');
					}

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
					resolve({ csr });
				}
				catch(e) {
					console.log(e);
					var err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Запись сертификата.
	 * @param {string} certBase64
	 * @returns {Promise<string>} thumbprint
	 */
	this.writeCertificate = function(certBase64){
		if(canAsync) {
			var oEnroll, existingSha = [];
			return this.listCertificates().then(function(certs){
				for(var i in certs) {
					existingSha.push(certs[i].id);
				}
				return cadesplugin.CreateObjectAsync('X509Enrollment.CX509Enrollment');
			}).then(function(enroll){
				oEnroll = enroll;
				return oEnroll.Initialize(X509CertificateEnrollmentContext.ContextUser);
			}).then(function(){
				return oEnroll.InstallResponse(InstallResponseRestrictionFlags.AllowNone, certBase64, EncodingType.XCN_CRYPT_STRING_BASE64, '');
			}).then(this.listCertificates).then(function(certs){
				for(var i in certs) {
					var sha = certs[i].id;
					if(existingSha.indexOf(sha) < 0) {
						return sha;
					}
				}
				throw new Error('Не удалось найти установленный сертификат по отпечатку');
			}).catch(function(e){
				console.log(arguments);
				var err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
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
					var found = false;
					for(var i=1; i<=oCertificates.Count; i++) {
						var sha = oCertificates.Item(i).Thumbprint;
						if(existingSha.indexOf(sha) < 0) {
							found = true;
						}
					}
					oStore.Close();
					if(found) {
						resolve(sha);
					}
					else {
						throw new Error('Не удалось найти установленный сертификат по отпечатку');
					}
				}
				catch(e) {
					console.log(e);
					var err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Получение информации о сертификате.
	 * @param {string} certThumbprint
	 * @returns {Promise<Object>}
	 */
	this.certificateInfo = function(certThumbprint){
		const infoToString = function () {
			return    'Название:              ' + this.Name +
					'\nИздатель:              ' + this.IssuerName +
					'\nСубъект:               ' + this.SubjectName +
					'\nВерсия:                ' + this.Version +
					'\nСерийный №:            ' + this.SerialNumber +
					'\nОтпечаток SHA1:        ' + this.Thumbprint +
					'\nНе действителен до:    ' + this.ValidFromDate +
					'\nНе действителен после: ' + this.ValidToDate +
					'\nПриватный ключ:        ' + (this.HasPrivateKey ? 'Есть' : 'Нет') +
					'\nВалидный:              ' + (this.IsValid ? 'Да' : 'Нет');
		};

		if(canAsync) {
			let oInfo = {};
			return getCertificateObject(certThumbprint)
			.then(oCertificate => Promise.all([
				oCertificate.HasPrivateKey(),
				oCertificate.IsValid(),
				oCertificate.IssuerName,
				oCertificate.SerialNumber,
				oCertificate.SubjectName,
				oCertificate.Thumbprint,
				oCertificate.ValidFromDate,
				oCertificate.ValidToDate,
				oCertificate.Version
			]))
			.then(a => {
				oInfo = {
					HasPrivateKey: a[0],
					IsValid: undefined, // a[1],
					//TODO: Issuer object
					IssuerName: a[2],
					SerialNumber: a[3],
					SubjectName: a[4],
					Subject: undefined,
					Name: undefined,
					Thumbprint: a[5],
					ValidFromDate: new Date(a[6]),
					ValidToDate: new Date(a[7]),
					Version: a[8]
				};
				const oCertificateStatus = a[1];
				return oCertificateStatus.Result;
			})
			.then(result => {
				let oParsedSubj = parseSubject(oInfo.SubjectName);
				oParsedSubj = convertDN(oParsedSubj);
				oInfo.Subject = oParsedSubj;
				oInfo.Name = oParsedSubj['CN'];
				oInfo.IsValid = result;
				oInfo.toString = infoToString;
				return oInfo;
			})
			.catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint);
					const oCertificateStatus = oCertificate.IsValid();
					let oParesedSubj = parseSubject(oCertificate.SubjectName);
					oParesedSubj = convertDN(oParesedSubj);
					const oInfo = {
						HasPrivateKey: oCertificate.HasPrivateKey(),
						IsValid: oCertificateStatus.Result,
						//TODO: Issuer object
						IssuerName: oCertificate.IssuerName,
						SerialNumber: oCertificate.SerialNumber,
						SubjectName: oCertificate.SubjectName,
						Subject: oParesedSubj,
						Name: oParesedSubj['CN'],
						Thumbprint: oCertificate.Thumbprint,
						ValidFromDate: new Date(oCertificate.ValidFromDate),
						ValidToDate: new Date(oCertificate.ValidToDate),
						Version: oCertificate.Version
					};
					oInfo.toString = infoToString;
					resolve(oInfo);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Получение массива доступных сертификатов
	 * @returns {Promise<Array>} [ {id: thumbprint, name: subject}, ...]
	 */
	this.listCertificates = function(){
		if(canAsync) {
			var oStore, oCertificates, ret;
			return cadesplugin.then(function(){
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
					var oDN = parseSubject(subjects[i]);
					certs.push({
						id: subjects[i+1], 
						name: formatCertificateName(oDN)
					});
				}
				ret = certs;
				return oStore.Close();
			}).then(function(){
				return ret;
			}).catch(function(e){
				console.log(arguments);
				var err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					var oStore = cadesplugin.CreateObject("CAPICOM.Store");
					oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE, cadesplugin.CAPICOM_MY_STORE, cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

					var oCertificates = oStore.Certificates;
					var certs = [];
					for(var i=1; i<=oCertificates.Count; i++) {
						var oCertificate = oCertificates.Item(i);
						var oDN = parseSubject(oCertificate.SubjectName);
						certs.push({
							id: oCertificate.Thumbprint, 
							name: formatCertificateName(oDN)
						});
					}
					oStore.Close();
					resolve(certs);
				}
				catch(e) {
					console.log(e);
					var err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Чтение сертификата
	 * @param {string} certThumbprint
	 * @returns {Promise<string>} base64
	 */
	this.readCertificate = function(certThumbprint){
		if(canAsync) {
			return getCertificateObject(certThumbprint)
			.then(cert => cert.Export(cadesplugin.CADESCOM_ENCODE_BASE64))
			.catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint);
					const data = oCertificate.Export(cadesplugin.CADESCOM_ENCODE_BASE64);
					resolve(data);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Подпись данных (отсоединенная).
	 * @param {string} dataBase64
	 * @param {string} certThumbprint
	 * @param {string} pin будет запрошен, если отсутствует
	 * @returns {Promise<string>} base64
	 */
	this.signData = function(dataBase64, certThumbprint, pin){
		if(canAsync) {
			let oCertificate, oSigner, oSignedData;
			return getCertificateObject(certThumbprint)
			.then(certificate => {
				oCertificate = certificate;
				return Promise.all([
					cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner"),
					cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData")
				]);
			})
			.then(objects => {
				oSigner = objects[0];
				oSignedData = objects[1];
				return oCertificate.PrivateKey;
			})
			.then(privateKey => privateKey.propset_CachePin(binded))
			.then(() => Promise.all([
				oSigner.propset_Certificate(oCertificate),
				// oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN),
				oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY),
				oSigner.propset_KeyPin(pin ? pin : ''),
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY)
			]))
			.then(() => oSignedData.propset_Content(dataBase64))
			.then(() => oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true))
			.catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint);

					if(oCertificate.PrivateKey && oCertificate.PrivateKey.CachePin !== undefined) {
						// возможно не поддерживается в ИЕ
						// https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=10170
						oCertificate.PrivateKey.CachePin = binded;
					}

					const oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
					oSigner.Certificate = oCertificate;
					// oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
					oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY;
					oSigner.KeyPin = pin ? pin : '';

					const oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
					// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
					oSignedData.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
					oSignedData.Content = dataBase64;

					const sSignedMessage = oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);
					resolve(sSignedMessage);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Совместная подпись данных (двумя сертификатами).
	 * @param {string} dataBase64
	 * @param {string} certThumbprint SHA1 отпечаток первого сертификата
	 * @param {string} pin будет запрошен, если отсутствует
	 * @param {string} certThumbprint2 SHA1 отпечаток второго сертификата
	 * @param {string} pin2 будет запрошен, если отсутствует
	 * @returns {Promise<string>} base64
	 */
	this.signData2 = function(dataBase64, certThumbprint, pin, certThumbprint2, pin2){
		if(canAsync) {
			let oCertificate, oCertificate2, oSigner, oSignedData;
			return Promise.all([
				getCertificateObject(certThumbprint),
				getCertificateObject(certThumbprint2)
			])
			.then(certs => {
				oCertificate = certs[0];
				oCertificate2 = certs[1];
				return Promise.all([
					cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner"),
					cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData")
				]);
			})
			.then(objects => {
				oSigner = objects[0];
				oSignedData = objects[1];
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			})
			.then(() => oSignedData.propset_Content(dataBase64))
			.then(() => Promise.all([
				oSigner.propset_Certificate(oCertificate),
				// oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN),
				oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY),
				oSigner.propset_KeyPin(pin ? pin : '')
			]))
			.then(() => oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true))
			.then(() => Promise.all([
				oSigner.propset_Certificate(oCertificate2),
				// oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN),
				oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY),
				oSigner.propset_KeyPin(pin2 ? pin2 : '')
			]))
			.then(() => oSignedData.CoSignCades(oSigner, cadesplugin.CADESCOM_CADES_BES))
			.catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint);
					const oCertificate2 = getCertificateObject(certThumbprint2);

					const oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
					// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
					oSignedData.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
					oSignedData.Content = dataBase64;

					const oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
					oSigner.Certificate = oCertificate;
					// oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
					oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY;
					oSigner.KeyPin = pin ? pin : '';
					const sSignedMessage = oSignedData.SignCades(oSigner, cadesplugin.CADESCOM_CADES_BES, true);

					oSigner.Certificate = oCertificate2;
					// oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
					oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY;
					oSigner.KeyPin = pin2 ? pin2 : '';
					const sSignedMessage2 = oSignedData.CoSignCades(oSigner, cadesplugin.CADESCOM_CADES_BES);

					resolve(sSignedMessage2);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Добавить подпись к существующей.
	 * @param {string} dataBase64
	 * @param {string} signBase64 существующая подпись
	 * @param {string} certThumbprint SHA1 отпечаток первого сертификата
	 * @param {string} pin будет запрошен, если отсутствует
	 * @returns {Promise<string>} base64
	 */
	this.addSign = function(dataBase64, signBase64, certThumbprint, pin){
		if(canAsync) {
			var oCertificate, oSigner, oSignedData;
			return getCertificateObject(certThumbprint)
			.then(certificate => {
				oCertificate = certificate;
				return Promise.all([
					cadesplugin.CreateObjectAsync("CAdESCOM.CPSigner"),
					cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData")
				]);
			})
			.then(objects => {
				oSigner = objects[0];
				oSignedData = objects[1];
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			})
			.then(() => {
				return oSignedData.propset_Content(dataBase64);
			})
			.then(() => {
				return oSignedData.VerifyCades(signBase64, cadesplugin.CADESCOM_CADES_BES, true).catch(function(e){
					console.log('Existing sign not verified: %o', e);
					// Для создания второй подписи успешная проверка не требуется.
					// Вы можете перехватить исключение при проверке, и добавить подпись вторую.
					// Проверка нужна только для того что бы подпись попала внутрь SignedData.
				});
			})
			.then(result => {
				//console.log('sign1: %s', sign);
				var promises = [
					oSigner.propset_Certificate(oCertificate),
					// oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN),
					oSigner.propset_Options(cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY),
					oSigner.propset_KeyPin(pin ? pin : '')
				];
				return Promise.all(promises);
			}).then(() => {
				return oSignedData.CoSignCades(oSigner, cadesplugin.CADESCOM_CADES_BES);
			}).catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint);
					const oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
					// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
					oSignedData.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
					oSignedData.Content = dataBase64;

					try {
						oSignedData.VerifyCades(signBase64, cadesplugin.CADESCOM_CADES_BES, true);
					}
					catch(e) {
						console.log('Existing sign not verified: %o', e);
						// Для создания второй подписи успешная проверка не требуется.
						// Вы можете перехватить исключение при проверке, и добавить подпись вторую.
						// Проверка нужна только для того что бы подпись попала внутрь SignedData.
					}

					const oSigner = cadesplugin.CreateObject("CAdESCOM.CPSigner");
					oSigner.Certificate = oCertificate;
					// oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
					oSigner.Options = cadesplugin.CAPICOM_CERTIFICATE_INCLUDE_END_ENTITY_ONLY;
					oSigner.KeyPin = pin ? pin : '';
					const sSignedMessage = oSignedData.CoSignCades(oSigner, cadesplugin.CADESCOM_CADES_BES);

					resolve(sSignedMessage);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Проверить подпись.
	 * @param {string} dataBase64
	 * @param {string} signBase64 существующая подпись
	 * @returns {Promise<boolean>} true или reject
	 */
	this.verifySign = function(dataBase64, signBase64){
		if(canAsync) {
			var oSignedData;
			return cadesplugin.then(function(){
				return cadesplugin.CreateObjectAsync("CAdESCOM.CadesSignedData");
			}).then(function(object){
				oSignedData = object;

				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oSignedData.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			}).then(function(){
				return oSignedData.propset_Content(dataBase64);
			}).then(function(){
				return oSignedData.VerifyCades(signBase64, cadesplugin.CADESCOM_CADES_BES, true);
			}).then(function(){
				//console.log('sign2: %s', sign2);
				return true;
			}).catch(function(e){
				console.log(arguments);
				var err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					var oSignedData = cadesplugin.CreateObject("CAdESCOM.CadesSignedData");
					// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
					oSignedData.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
					oSignedData.Content = dataBase64;
					oSignedData.VerifyCades(signBase64, cadesplugin.CADESCOM_CADES_BES, true);
					resolve(true);
				}
				catch (e) {
					console.log(e);
					var err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Шифрование данных
	 * @param {string} dataBase64 данные в base64
	 * @param {string} certThumbprint SHA1 отпечаток сертификата
	 * @returns {Promise<string>} base64 enveloped data
	 */
	this.encryptData = function(dataBase64, certThumbprint) {
		if(canAsync) {
			let oCertificate, oEnvelop, oRecipients;
			return getCertificateObject(certThumbprint)
			.then(certificate => {
				oCertificate = certificate;
				return cadesplugin.CreateObjectAsync("CAdESCOM.CPEnvelopedData");
			})
			.then(envelop => {
				oEnvelop = envelop;
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oEnvelop.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			})
			.then(() => oEnvelop.propset_Content(dataBase64))
			.then(() => oEnvelop.Recipients)
			.then(recipients => {
				oRecipients = recipients;
				return oRecipients.Clear();
			})
			.then(() => oRecipients.Add(oCertificate))
			.then(() => oEnvelop.Encrypt())
			.catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint);
					const oEnvelop = cadesplugin.CreateObject("CAdESCOM.CPEnvelopedData");
					oEnvelop.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
					oEnvelop.Content = dataBase64;
					oEnvelop.Recipients.Clear();
					oEnvelop.Recipients.Add(oCertificate);
					const encryptedData = oEnvelop.Encrypt();
					resolve(encryptedData);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	/**
	 * Дешифрование данных
	 * @param {string} dataBase64 данные в base64
	 * @param {string} certThumbprint SHA1 отпечаток сертификата
	 * @param {string} pin будет запрошен, если отсутствует
	 * @returns {Promise<string>} base64
	 */
	this.decryptData = function(dataBase64, certThumbprint, pin) {
		if(canAsync) {
			let oCertificate, oEnvelop, oRecipients;
			return getCertificateObject(certThumbprint, pin)
			.then(certificate => {
				oCertificate = certificate;
				return cadesplugin.CreateObjectAsync("CAdESCOM.CPEnvelopedData");
			})
			.then(envelop => {
				oEnvelop = envelop;
				// Значение свойства ContentEncoding должно быть задано до заполнения свойства Content
				return oEnvelop.propset_ContentEncoding(cadesplugin.CADESCOM_BASE64_TO_BINARY);
			})
			// .then(() => oEnvelop.propset_Content(dataBase64))
			.then(() => oEnvelop.Recipients)
			.then(recipients => {
				oRecipients = recipients;
				return oRecipients.Clear();
			})
			.then(() => oRecipients.Add(oCertificate))
			.then(() => oEnvelop.Decrypt(dataBase64))
			.then(() => oEnvelop.Content)
			.catch(e => {
				console.log(arguments);
				const err = getError(e);
				throw new Error(err);
			});
		}
		else {
			return new Promise(resolve => {
				try {
					const oCertificate = getCertificateObject(certThumbprint, pin);
					const oEnvelop = cadesplugin.CreateObject("CAdESCOM.CPEnvelopedData");
					oEnvelop.ContentEncoding = cadesplugin.CADESCOM_BASE64_TO_BINARY;
					// oEnvelop.Content = dataBase64;
					oEnvelop.Recipients.Clear();
					oEnvelop.Recipients.Add(oCertificate);
					oEnvelop.Decrypt(dataBase64);
					resolve(oEnvelop.Content);
				}
				catch (e) {
					console.log(e);
					const err = getError(e);
					throw new Error(err);
				}
			});
		}
	};

	function getCertificateObject(certThumbprint, pin) {
		if(canAsync) {
			let oStore, oCertificate;
			return cadesplugin
			.then(() => cadesplugin.CreateObjectAsync("CAPICOM.Store")) //TODO: CADESCOM.Store ?
			.then(o => {
				oStore = o;
				return oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE,
								   cadesplugin.CAPICOM_MY_STORE,
								   cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);
			})
			.then(() => oStore.Certificates)
			.then(certificates => certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint))
			.then(certificates => {
				return Promise.all([
					certificates.Count,
					certificates.Item(1)
				]);
			})
			.then(([count, certificate]) => {
				if(count != 1) {
					throw new Error("Не обнаружен сертификат c отпечатком " + certThumbprint);
				}
				oCertificate = certificate;
				return oStore.Close();
			})
			.then(() => oCertificate.HasPrivateKey())
			.then(hasKey => {
				let p = Promise.resolve();
				if (hasKey && pin) {
					p = p.then(() => oCertificate.PrivateKey).then(privateKey => Promise.all([
						privateKey.propset_KeyPin(pin ? pin : ''),
						privateKey.propset_CachePin(binded)
					]));
				}
				return p;
			})
			.then(() => oCertificate);
		}
		else {
			const oStore = cadesplugin.CreateObject("CAPICOM.Store");
			oStore.Open(cadesplugin.CAPICOM_CURRENT_USER_STORE,
						cadesplugin.CAPICOM_MY_STORE,
						cadesplugin.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED);

			const oCertificates = oStore.Certificates.Find(cadesplugin.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, certThumbprint);
			if (oCertificates.Count != 1) {
				throw new Error("Не обнаружен сертификат c отпечатком " + certThumbprint);
			}
			const oCertificate = oCertificates.Item(1);
			if (oCertificate.HasPrivateKey && pin) {
				oCertificate.PrivateKey.KeyPin = pin ? pin : '';
				if(oCertificate.PrivateKey.CachePin !== undefined) {
					// возможно не поддерживается в ИЕ
					// https://www.cryptopro.ru/forum2/default.aspx?g=posts&t=10170
					oCertificate.PrivateKey.CachePin = binded;
				}
			}
			oStore.Close();
			return oCertificate;
		}
	}

	/**
	 * Получить текст ошибки
	 * @param {Error} e
	 * @returns {string}
	 */
	function getError(e) {
		if(e.message) {
			for(var i in cadesErrorMesages) {
				if(cadesErrorMesages.hasOwnProperty(i)) {
					if(e.message.indexOf(i)+1) {
						e.message = cadesErrorMesages[i];
						break;
					}
				}
			}
		}
		return e.message || e;
	}

	/**
	 * Разобрать субъект в объект DN
	 * @param {string} subjectName
	 * @returns {DN}
	 */
	function parseSubject(subjectName){
		var dn = new DN;
		var pairs = subjectName.match(/([а-яёА-ЯЁa-zA-Z0-9\.]+)=(?:("[^"]+?")|(.+?))(?:,|$)/g).map(el => el.replace(/,$/, ''));
		pairs.forEach(pair => {
			var d = pair.match(/([^=]+)=(.*)/);
			if (d.length === 3) {
				var rdn = d[1].trim().replace(/^OID\./, '');
				var val = d[2].trim().replace(/^"(.*)"$/, '$1');
				dn[rdn] = val;
			}
		});
		return dn;
	}

	/**
	 * Получить название сертификата
	 * @param {DN} o объект, включающий в себя значения всех полей сертификата.
	 * @returns {String}
	 */
	function formatCertificateName(o) {
		var snils = o['СНИЛС'] || o['SNILS'];
		var inn = o['ИНН'] || o['INN'];
		return '' + o['CN'] + (inn ?  '; ИНН ' + inn : '') + (snils ?  '; СНИЛС ' + snils : '');
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

export default CryptoPro;
