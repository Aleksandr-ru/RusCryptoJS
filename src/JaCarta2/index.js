/**
 * JaCarta-2 GOST simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */
import DN from '../DN';
import errors from './errors';
import { convertDN, stripDnQuotes } from '../helpers';

function JaCarta2() {

	var client, tokenId;
	// const debug = process.env.NODE_ENV === 'development';	

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {Promise<Object>} версия, информация о токене
	 */
	this.init = function() {
		var final = {};
		return new Promise((resolve, reject) => {
			if (typeof(JCWebClient2) !== 'undefined') {
				resolve();
			}
			else {
				getScript('https://localhost:24738/JCWebClient.js', resolve, reject);
			}
		}).then(() => {
			return new Promise((resolve, reject) => {
				if(typeof JCWebClient2 != 'undefined') {
					client = JCWebClient2;
					client.initialize();
					client.defaults({
						async: true
					});
					client.getJCWebClientVersion({
						onSuccess: resolve,
						onError: errorHandler(reject)
					});
				}
				else {
					//Не установлен клиент JCWebClient2
					throw new Error('Не установлен клиент JCWebClient2');
				}
			});
		}).then(version => {
			console.log('JCWebClient2 v.%s', version);
			final['version'] = version;
			return new Promise((resolve, reject) => {
				client.getAllSlots({
					onSuccess: resolve,
					onError: errorHandler(reject)
				});
			});
		}).then(slots => {
			return new Promise((resolve, reject) => {
				// console.log('Got %d slots', slots.length, slots);
				var aTokens = slots.filter(a => {
					return a.tokenExists;
				});
				if(aTokens && aTokens.length == 1) {
					// OK 1 токен
					var token = aTokens.shift();
					resolve(token.id);			
				}
				else if(aTokens && aTokens.length > 1) {
					throw new Error('Подключено ' + aTokens.length + ' токена(ов)');
				}
				else {
					throw new Error('Нет подключенных токенов');
				}
			});
		}).then(tokenID => {
			tokenId = tokenID;
			return new Promise((resolve, reject) => {
				client.getTokenInfo({
					args: { tokenID: tokenId },
					onSuccess: resolve,
					onError: errorHandler(reject)
				});
			});
		}).then(info => {
			return Object.assign(final, info);
		});
	};

	/**
	 * Авторизация на токене с пин-кодом юзера
	 * @param {string} userPin если нет, то предлгает ввести пин через UI плагина
	 * @returns {Promise}
	 */
	this.bind = function(userPin) {
		return new Promise((resolve, reject) => {
			client.getLoggedInState({
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(result => {
			if(result.state === JCWebClient2.Vars.AuthState.binded && result.tokenID === tokenId) {
				return true;
			}
			else {
				return new Promise((resolve, reject) => {
					var args = { tokenID: tokenId };
					if(!userPin) {
						args.useUI = true;
					}
					else {
						args.pin = userPin;
					}
					client.bindToken({
						args: args,
						onSuccess: resolve,
						onError: errorHandler(reject)
					});
				});
			}
		});
	};

	/**
	 * Отменить предъявление PIN-кода. Необходимо вызывать при завершении сеанса работы
	 * @returns {Promise}
	 */
	this.unbind = function() {
		return new Promise((resolve, reject) => {
			client.getLoggedInState({
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(result => {
			if(result.state !== JCWebClient2.Vars.AuthState.notBinded) {
				return new Promise((resolve, reject) => {
					client.unbindToken({
						onSuccess: resolve,
						onError: errorHandler(reject)
					});
				});	
			}
			else {
				return true;
			}
		});
	};

	/**
	 * Очистка токена (удаление всех контейнеров)
	 * @returns {Promise}
	 */
	this.clean = function(){
		return new Promise((resolve, reject) => {
			client.getContainerList({
				args: {
					tokenID: tokenId
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(containers => {
			var p = Promise.resolve();
			for(var i in containers) {
				p = p.then(function(){
					return new Promise((resolve, reject) => {
						client.deletePKIObject({
							args: {
								id: containers[i].id
							},
							onSuccess: resolve,
							onError: errorHandler(reject)
						});
					});
				});
			}
			return p;
		});
	};

	/**
	 * Создать запрос на сертификат
	 * @param {DN} dn
	 * @param {string} description описание контейнера
	 * @param {array} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @param {string} algorithm Алгоритм "GOST-2012-256" (по-умолчанию) или "GOST-2001".
	 * @returns {Promise<Object>} объект с полями { csr: 'base64 запрос на сертификат', keyPairId }
	 * @see DN
	 */
	this.generateCSR = function(dn, description, ekuOids, algorithm){
		if(!ekuOids || !ekuOids.length) {
			ekuOids = [
				'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
				'1.3.6.1.5.5.7.3.4' // Защищенная электронная почта
			];
		}
		if(!algorithm) {
			// algorithm = JCWebClient2.Vars.KeyAlgorithm.GOST_2001; //default "GOST-2001"
			algorithm = JCWebClient2.Vars.KeyAlgorithm.GOST_2012_256; // "GOST-2012-256"
		} 
		var exts = {
			'certificatePolicies': '1.2.643.100.113.1',
			'keyUsage': 'digitalSignature,keyEncipherment,nonRepudiation,dataEncipherment',
			'extendedKeyUsage': ekuOids.toString(),
			'1.2.643.100.111': 'ASN1:FORMAT:UTF8,UTF8:"Криптотокен" (АЛАДДИН Р.Д.)'
		};
		var paramSet = 'XA';
		var id;
		return new Promise((resolve, reject) => {
			client.createKeyPair({
				args: {
					paramSet: paramSet,
					description: description,
					algorithm: algorithm
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(keyPairId => {
			id = keyPairId;
			return new Promise((resolve, reject) => {
				client.genCSR({
					args: {
						id: id,
      					dn: dn,
      					exts: exts
					},
					onSuccess: resolve,
					onError: errorHandler(reject)
				});
			});
		}).then(a => {
			// base64(запрос на сертификат в формате PKCS#10)
			var csr = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
			return { 
				csr: pemSplit(csr),
				keyPairId: id
			};
		});
	};

	/**
	 * Записать сертификат в контейнер
	 * @param {string} certificate base64(массив байт со значением сертификата в формате DER)
	 * @param {int} keyPairId идентификатор контейнера куда записывать
	 * @returns {Promise<number>} идентификатор образованного контейнера.
	 */
	this.writeCertificate = function(certificate, keyPairId) {
		return new Promise((resolve, reject) => {
			client.writeUserCertificate({
				args: {
					keyPairID: keyPairId,
					cert: certificate
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		});
	};

	/**
	 * Получение информации о сертификате.
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {Promise<Object>}
	 */
	this.certificateInfo = function(containerId) {
		return new Promise((resolve, reject) => {
			client.parseX509Certificate({
				args: {
					tokenID: tokenId,
					id: containerId
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(o => {
			var dn = makeDN(o.Data.Subject);
			var dnI = makeDN(o.Data.Issuer);
			var dt = new Date();
			var info = {
				Name: dn.CN,
				Issuer: dnI,			
				IssuerName: stripDnQuotes(dnI.toString()),
				Subject: dn,
				SubjectName: stripDnQuotes(dn.toString()),
				Version: o.Data.Version,
				SerialNumber: o.Data['Serial Number'].map(byte2hex).join(''),
				Thumbprint: o.Signature.map(byte2hex).join(''),
				ValidFromDate: o.Data.Validity['Not Before'],
				ValidToDate: o.Data.Validity['Not After'],
				HasPrivateKey: true,
				IsValid: dt >= o.Data.Validity['Not Before'] && dt <= o.Data.Validity['Not After'],
				Algorithm: o.Data['Subject Public Key Info']['Public Key Algorithm'],
				//ProviderName: '', //TODO
				//ProviderType: undefined, //TODO
				toString: function() {
					return 'Название:              ' + this.Name +
						 '\nИздатель:              ' + this.IssuerName +
						 '\nСубъект:               ' + this.SubjectName +
						 '\nВерсия:                ' + this.Version +
						 '\nАлгоритм:              ' + this.Algorithm + // PublicKey Algorithm
						 '\nСерийный №:            ' + this.SerialNumber +
						 '\nОтпечаток SHA1:        ' + this.Thumbprint +
						 '\nНе действителен до:    ' + this.ValidFromDate +
						 '\nНе действителен после: ' + this.ValidToDate +
						 '\nПриватный ключ:        ' + (this.HasPrivateKey ? 'Есть' : 'Нет') +
						 '\nВалидный:              ' + (this.IsValid ? 'Да' : 'Нет');
				}
			};
			return info;
		});
	};

	/**
	 * Получение массива доступных сертификатов
	 * @returns {Promise<Array>} [{ id, name }, ...]
	 */
	this.listCertificates = function() {
		return new Promise((resolve, reject) => {
			client.getContainerList({
				args: {
					tokenID: tokenId
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(a => {
			var certs = [];
			var p = Promise.resolve();
			for(var i=0; i<a.length; i++) {
				var contId = a[i].id;
				var contName = a[i].description;
				
				(function(contId, contName) {
					p = p.then(function() {
						return new Promise((resolve, reject) => {
							client.parseX509Certificate({
								args: {
									tokenID: tokenId,
									id: contId
								},
								onSuccess: resolve,
								onError: errorHandler(reject)
							});
						}).then(o => {
							certs.push({
								id: contId,
								name: formatCertificateName(o, contName)
							});
							return certs.length;
						});
					});
				})(contId, contName);
			}
			return p.then(function(){
				return certs;
			});
		});
	};
	
	/**
	 * Получить сертификат из контейнера
	 * @param {int} containerId
	 * @returns {Promise<string>} base64(массив байт со значением сертификата в формате DER)
	 */
	this.readCertificate = function(containerId) {
		return new Promise((resolve, reject) => {
			client.getCertificateBody({
				args: {
					id: containerId,
					tokenID: tokenId
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(a => {
			if(a && a.length) {
				// base64(массив байт со значением сертификата в формате DER)
				var cert = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
				return pemSplit(cert);
			}
			else {
				throw new Error('Нет сертификата в контейнере');
			}
		});
	};

	/**
	 * Подписать данные. Выдает подпись в формате PKCS#7, закодированную в Base64
	 * @param {string} dataBase64 Данные для подписи в виде строки, закодированной в Base64
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @param {object} [options]
	 * @param {boolean} [options.attached] присоединенная подпись
	 * @returns {Promise<string>} строка-подпись в формате PKCS#7, закодированная в Base64.
	 */
	this.signData = function(dataBase64, containerId, options){
		if (!options) options = {};
		const { attached } = options;
		return new Promise((resolve, reject) => {
			client.signBase64EncodedData({
				args: {
					contID: containerId,
					data: dataBase64,
					attachedSignature: !!attached
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		}).then(sign => {
			return pemSplit(sign);
		});
	};

	/**
	 * Проверить подпись.
	 * @param {string} dataBase64 игнорируется если прикрепленная подпись
	 * @param {string} signBase64 существующая подпись
	 * @param {object} [options]
	 * @param {boolean} [options.attached] присоединенная подпись
	 * @returns {Promise<boolean>} true или reject
	 */
	this.verifySign = function(dataBase64, signBase64, options){
		if (!options) options = {};
		const { attached } = options;
		const args = {
			signature: Array.from(atob(signBase64), c => c.charCodeAt(0)),
			options: {
				tokenID: tokenId,
				useToken: true
			}
		};
		if (!attached) {
			args.data = Array.from(atob(dataBase64), c => c.charCodeAt(0));
		}
		return new Promise((resolve, reject) => {
			client.verifyData({
				args,
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		});
	};

	/**
	 * Шифрование данных
	 * @param {string} dataBase64 данные в base64
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {Promise<string>} base64 enveloped data
	 */
	this.encryptData = function(dataBase64, containerId) {
		// https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer/21797381
		const dataByte = Array.from(atob(dataBase64), c => c.charCodeAt(0));
		return this.readCertificate(containerId).then(cert => new Promise((resolve, reject) => {
			client.encryptData({
				args: {
					contID: containerId,
					receiverCertificate: cert,
					data: dataByte // Данные для шифрования в виде массива байт.
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		})).then(data => {
			const base64 = btoa(String.fromCharCode.apply(null, new Uint8Array(data)));
			return pemSplit(base64);
		});
	};

	/**
	 * Дешифрование данных
	 * @param {string} dataBase64 данные в base64
	 * @param {int} containerId идентификатор контейнера (ключа)
	 * @returns {Promise<string>} base64
	 */
	this.decryptData = function(dataBase64, containerId) {
		const dataByte = Array.from(atob(dataBase64), c => c.charCodeAt(0));
		return this.readCertificate(containerId).then(cert => new Promise((resolve, reject) => {
			const certByte = Array.from(atob(cert), c => c.charCodeAt(0));
			client.decryptData({
				args: {
					contID: containerId,
					senderCertificate: certByte, // Сертификат отправителя в виде массива байт.
					data: dataByte // Массив байт с зашифрованными данными в формате CMS.
				},
				onSuccess: resolve,
				onError: errorHandler(reject)
			});
		})).then(data => btoa(String.fromCharCode.apply(null, new Uint8Array(data))));
	};

	function errorHandler(reject)
	{
		return function(e) {
			if(client && e.name === 'JCWebClientError' && errors[e.message]) {
				// подменяем сообщение на более понятное
				e.message = errors[e.message];
			}
			reject(e);
		}
	}

	/**
	 * Создать DN из массива [{rdn: ..., value: ...}, ...]
	 * @param {[index: number]: { rdn: string, value: string }} obj 
	 * @returns {DN}
	 */
	function makeDN(obj)
	{
		var dn = new DN;
		for(var i in obj) {
			var rdn = obj[i].rdn;
			var val = obj[i].value;
			if (rdn && val) {
				dn[rdn] = val;
			}
		}
		return convertDN(dn);
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
					// поэтому дополнительно проверяем валидность JCWebClient2
					if (typeof (JCWebClient2) === 'undefined') {
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

export default JaCarta2;
