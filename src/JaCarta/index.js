/**
 * JaCarta GOST simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */

import DN from '../DN';
import errors from './errors';
import { convertDN } from '../helpers';

function JaCarta() {
	var client, tokenId;

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {Promise<Object>} версия, информация о токене
	 */
	this.init = function(){
		return new Promise((resolve, reject) => {
			if (typeof(JCWebClient) !== 'undefined') {
				resolve();
			}
			else {
				getScript('https://localhost:24738/JCWebClient.js', resolve, reject);
			}
		}).then(() => {
			return new Promise(resolve => {
				try {
					if(typeof JCWebClient != 'undefined') {
						// Установлен клиент одной из версий JC-WebClient (2.x или новой) либо оба клиента
						if(typeof JCWebClient.id == 'undefined') {
							// Установлен клиент новой версии, работающей через локальный веб-сервер
							client = JCWebClient();
							client.initialize();
						}
						else {
							// Установлен клиент версии 2.x, работающей через NPAPI и ActiveX
							throw new Error('JaCarta WebClient 2.x не поддерживается');
						}
					}
					else {
						//Не установлен клиент ни старой, ни новой версии JC-WebClient
						throw new Error('Не установлен клиент ни старой, ни новой версии JC-WebClient');
					}

					if(!client.checkWebBrowserVersion()) {
						throw new Error('Браузер не поддерживается');
					}

					var aTokens = client.getAllTokens();
					if(aTokens && aTokens.length == 1) {
						// OK 1 токен
						tokenId = aTokens.shift();				
					}
					else if(aTokens && aTokens.length > 1) {
						throw new Error('Подключено ' + aTokens.length + ' токена(ов)');
					}
					else {
						throw new Error('Нет подключенных токенов');
					}
					var version = client.getPluginVersion();
					var tokenInfo = client.getTokenInfo(tokenId);
					resolve({
						version,
						serial: tokenInfo[0], // серийный номер электронного ключа.
						flags: tokenInfo[1],  // флаги электронного ключа.
						label: tokenInfo[2],  // метка электронного ключа.
						type: tokenInfo[3]
					});
				}
				catch(e) {
					var err = getError();
					throw new Error(e.message || err);
				}
			});
		});
	};

	/**
	 * Авторизация на токене с пин-кодом юзера
	 * @param {string} userPin если нет, то предлгает ввести пин через UI плагина
	 * @returns {Promise}
	 */
	this.bind = function(userPin) {
		return new Promise(resolve => {
			try {
				var state = client.getLoggedInState().shift();
				if(state === 1) {
					resolve();
				}
				else if(!userPin) {
					if(client.bindTokenUI(tokenId)) {
						resolve();
					}
					else {
						throw new Error('Пользователь отменил ввод PIN-кода');
					}
				}
				else {
					client.bindTokenAsync(tokenId, userPin, function(a){
						if(a && a[0] == 'Error') {
							var code = a[1];
							var err = getError(code);
							throw new Error(err);
						}
						else {
							resolve();
						}
					});
				}
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Отменить предъявление PIN-кода. Необходимо вызывать при завершении сеанса работы
	 * @returns {Promise}
	 */
	this.unbind = function() {
		return new Promise(resolve => {
			try {
				var state = client.getLoggedInState().shift();
				if(state === 1) {
					client.unbindToken();
				}
				resolve();
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Очистка токена (удаление всех контейнеров)
	 * @returns {Promise<number>} количество удаленных контейнеров
	 */
	this.clean = function(){
		return new Promise(resolve => {
			try {
				var aContainers = client.getCertificateList(tokenId);
				for(var i in aContainers) {
					var containerId = aContainers[i].shift();
					client.deleteContainerOrCertificate(containerId);
				}
				resolve(i);
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Создать запрос на сертификат
	 * @param {DN} dn
	 * @param {string} description описание контейнера
	 * @param {array} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @param {string} ecParams параметры эллиптической кривой ключевой пары. Может принимать значения A, B, C, XA, XB.
	 * @returns {Promise<Object>} объект с полями { csr: 'base64 запрос на сертификат', containerId }
	 * @see DN
	 */
	this.generateCSR = function(dn, description, ekuOids, ecParams){
		if(!ekuOids || !ekuOids.length) {
			ekuOids = [
				'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
				'1.3.6.1.5.5.7.3.4' // Защищенная электронная почта
			];
		}
		if(!ecParams) ecParams = 'XA';
		return new Promise(resolve => {
			try {
				client.createContainerAsync(ecParams, description, function(a){
					if(a && a[0] == 'Error') {
						var code = a[1];
						var err = getError(code);
						throw new Error(err);
					}
					else {
						var containerId = a;
						var aDn = [];
						for(var i in dn) if(dn.hasOwnProperty(i)) {
							aDn.push(i, dn[i]);
						}
						var exts = [
							'certificatePolicies',	'1.2.643.100.113.1',
							'keyUsage',				'digitalSignature,keyEncipherment,nonRepudiation,dataEncipherment',
							'extendedKeyUsage',		ekuOids.toString(),
							'1.2.643.100.111',		'ASN1:FORMAT:UTF8,UTF8:"Криптотокен" (АЛАДДИН Р.Д.)'
						];
						client.genCSRAsync(containerId, aDn, exts, function(a){
							if(a && a[0] == 'Error') {
								var code = a[1];
								var err = getError(code);
								throw new Error(err);
							}
							else {
								// base64(запрос на сертификат в формате PKCS#10)
								var csr = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
								resolve({
									csr: pemSplit(csr), 
									containerId
								});
							}
						});
					}
				});			
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Записать сертификат в контейнер
	 * @param {string} certificate base64(массив байт со значением сертификата в формате DER)
	 * @param {int} идентификатор контейнера куда записывать
	 * @returns {Promise}
	 */
	this.writeCertificate = function(certificate, containerId){
		return new Promise(resolve => {
			try {
				var aCertificate = [];
				var der = atob(certificate);
				for(var i=0; i<der.length; i++) {
					aCertificate[i] = der.charCodeAt(i);
				}
				client.writeCertificateAsync(containerId, aCertificate, function(){
					resolve();
				});
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Получение информации о сертификате.
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {Promise<Object>}
	 */
	this.certificateInfo = function(containerId){
		return new Promise(resolve => {
			try {
				var o = client.parseX509CertificateEx(tokenId, containerId);
				var dn = new DN;
				for(var i in o.Data.Subject) {
					var rdn = o.Data.Subject[i].rdn;
					var val = o.Data.Subject[i].value;
					dn[rdn] = val;
				}
				dn = convertDN(dn);
				var dnI = new DN;
				for(var i in o.Data.Issuer) {
					var rdn = o.Data.Issuer[i].rdn;
					var val = o.Data.Issuer[i].value;
					dnI[rdn] = val;
				}
				var dt = new Date();
				var info = {
					Name: dn.CN,
					Issuer: dnI,
					IssuerName: dnI.CN,
					Subject: dn,
					SubjectName: dn.toString(),
					Version: o.Data.Version,
					SerialNumber: o.Data['Serial Number'].map(byte2hex).join(''),
					Thumbprint: o.Signature.map(byte2hex).join(''),
					ValidFromDate: o.Data.Validity['Not Before'],
					ValidToDate: o.Data.Validity['Not After'],
					HasPrivateKey: true,
					IsValid: dt >= o.Data.Validity['Not Before'] && dt <= o.Data.Validity['Not After'],
					toString: function(){
						return 'Название:              ' + this.Name +
							'\nИздатель:              ' + this.IssuerName +
							'\nСубъект:               ' + this.SubjectName +
							'\nВерсия:                ' + this.Version +
							'\nСерийный №:            ' + this.SerialNumber +
							'\nОтпечаток SHA1:        ' + this.Thumbprint +
							'\nНе действителен до:    ' + this.ValidFromDate +
							'\nНе действителен после: ' + this.ValidToDate +
							'\nПриватный ключ:        ' + (this.HasPrivateKey ? 'Есть' : 'Нет') +
							'\nВалидный:              ' + (this.IsValid ? 'Да' : 'Нет');
					}
				};
				resolve(info);
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Получение массива доступных сертификатов
	 * @returns {Promise<Array>} [{id, subject}, ...]
	 */
	this.listCertificates = function(){
		return new Promise(resolve => {
			try {
				client.getCertificateListAsync(tokenId, function(a){
					if(a && a[0] == 'Error') {
						var code = a[1];
						var err = getError(code);
						throw new Error(err);
					}
					else {
						var certs = [];
						for(var i=0; i<a.length; i++) {
							var id = a[i][0];
							var contName = a[i][1];
							try {
								var o = client.parseX509CertificateEx(tokenId, contId);
								var name = formatCertificateName(o, contName);
								certs.push({ id, name });
							}
							catch(e) {
								console.log('Certificate (%s) info error: %s',  contId, e.message);
							}
						}
						resolve(certs);
					}
				});
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};
	
	/**
	 * Получить сертификат из контейнера
	 * @param {int} containerId 
	 * @returns {Promise<string>} base64(массив байт со значением сертификата в формате DER)
	 */
	this.readCertificate = function(containerId){
		return new Promise(resolve => {
			try {
				var state = client.getLoggedInState().shift();
				if(state === 0) {
					var a = client.readCertificateEx(tokenId, containerId);
				}
				else {
					var a = client.readCertificate(containerId);
				}
				if(a && a.length) {
					// base64(массив байт со значением сертификата в формате DER)
					var cert = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
					resolve(pemSplit(cert));
				}
				else {
					throw new Error('Нет сертификата в контейнере');
				}
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Подписать данные. Выдает подпись в формате PKCS#7, опционально закодированную в Base64
	 * @param {string} data данные (и подпись) закодированы в base64
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {Promise<string>} строка-подпись в формате PKCS#7, закодированная в Base64.
	 */
	this.signData = function(dataBase64, containerId){
		var attachedSignature = false;
		return new Promise(resolve => {
			try {
				client.signBase64EncodedDataAsync(containerId, dataBase64, attachedSignature, false, function(a){
					if(a && a[0] == 'Error') {
						var code = a[1];
						var err = getError(code);
						throw new Error(err);
					}
					else {
						var sign = pemSplit(a);
						resolve(sign);
					}
				});
			}
			catch(e) {
				var err = getError();
				throw new Error(err || e.message);
			}
		});
	};

	/**
	 * Шифрование данных не поддерживается
	 * @returns {Promise}
	 */
	this.encryptData = function() {
		return new Promise(function () {
			throw new Error('Encrypt feature is not supported, please upgrade to JaCarta-2 GOST');
		});
	}

	/**
	 * Дешифрование данных не поддерживается
	 * @returns {Promise<>}
	 */
	this.decryptData = function() {
		return new Promise(function () {
			throw new Error('Decrypt feature is not supported, please upgrade to JaCarta-2 GOST');
		});
	}

	/**
	 * Получить ошибку по коду
	 * @param {string} mnemo мнемонический код ошибки CKR_*
	 * @returns {string|Boolean} false если нет ошибки (CKR_OK)
	 */
	function getError(mnemo) {
		try {
			if(!mnemo) {
				var code = client.getLastError();
				mnemo = client.getErrorMessage(code);
			}
			if(mnemo == 'CKR_OK') {
				return false;
			}
			return errors[mnemo] || mnemo;
		}
		catch(e) {
			return e.message;
		}
	}

	/**
	 * Получить название сертификата
	 * @param {type} o объект, включающий в себя значения всех полей сертификата.
	 * @param {type} containerName
	 * @returns {string} 
	 */
	function formatCertificateName(o, containerName)
	{
		var dn = new DN;
		for(var i in o.Data.Subject) {
			var rdn = o.Data.Subject[i].rdn;
			var val = o.Data.Subject[i].value;
			dn[rdn] = val;
		}
		dn.toString = function(){
			var cn = this['CN'] || this['2.5.4.3'];
			var snils = this['СНИЛС'] || this['SNILS'] || this['1.2.643.100.3'];
			var inn = this['ИНН'] || this['INN'] || this['1.2.643.3.131.1.1'];
			return '' + cn + (inn ?  '; ИНН ' + inn : '') + (snils ?  '; СНИЛС ' + snils : '') + (containerName ? ' (' + containerName + ')' : '');
		};
		return dn.toString();
	}

	function byte2hex(byte) {
		//console.log('byte %d -> %s', byte, byte.toString(16));
		return ('0' + byte.toString(16)).slice(-2);
	}

	// https://gist.github.com/hendriklammers/5231994
	function pemSplit(str) {
		var re = new RegExp('.{1,64}', 'g');
		return str.match(re).join('\n');
	}

	/** 
	 * Функция загрузки скрипта.
	 * @param src - адрес расположения скрипта;
	 * @param done - callback-функция, срабатывающая при успешной загрузки скрипта;
	 * @param fail - callback-функция, срабатывающая при неудачной загрузки скрипта.
	*/
	function getScript(src, done, fail) {
		var parent = document.getElementsByTagName('body')[0];

		var script = document.createElement('script');
		script.type = 'text/javascript';
		script.src = src;

		if (script.readyState) {  // IE
			script.onreadystatechange = function () {
				if (script.readyState === "loaded" || script.readyState === "complete") {
					script.onreadystatechange = null;
					// На некоторых браузерах мы попадаем сюда и в тех случаях когда скрипт не загружен,
					// поэтому дополнительно проверяем валидность JCWebClient
					if (typeof (JCWebClient) === 'undefined') {
						onFail("JCWebClient is invalid");
					}
					else {
						done();
					}
				}
				else if (script.readyState !== "loading") {
					onFail("JCWebClient hasn't been loaded");
				}
			}
		}
		else {  // Others
			script.onload = done;
			script.onerror = function() {
				onFail("JCWebClient hasn't been loaded");
			};
		}

		parent.appendChild(script);

		function onFail(errorMsg) {
			parent.removeChild(script);
			fail(errorMsg);
		}
	}
}

export default JaCarta;
