/**
 * JaCarta-2 GOST simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */
import DN from '../DN';

function JaCarta2() {

	var client, tokenId;

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {Promise<Object>} версия, информация о токене
	 */
	this.init = function() {
		var final = {};
		return new Promise((resolve, reject) => {
			if(typeof(Uint8Array) != 'function') {
				throw new Error('Upgrade your browser to something supports Uint8Array!');
			}
			else if(!window.btoa || !window.atob) {
				throw new Error('Upgrade your browser to something supports native base64 encoding!');
			}
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
						onError: reject
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
					onError: reject
				});
			});
		}).then(slots => {
			return new Promise((resolve, reject) => {
				console.log('Got %d slots', slots.length);
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
			this.tokenId = tokenID;
			return new Promise((resolve, reject) => {
				client.getTokenInfo({
					args: { tokenID: tokenID },
					onSuccess: resolve,
					onError: reject
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
				onError: reject
			});
		}).then(result => {
			if(result.state === JCWebClient2.Vars.AuthState.binded && result.tokenID === tokenId) {
				return true;
			}
			else {
				return new Promise((resolve, reject) => {
					var args = { tokenID: this.tokenId };
					if(!userPin) {
						args.useUI = true;
					}
					else {
						args.pin = userPin;
					}
					client.bindToken({
						args: args,
						onSuccess: resolve,
						onError: reject
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
				onError: reject
			});
		}).then(result => {
			if(result.state !== JCWebClient2.Vars.AuthState.notBinded) {
				return new Promise((resolve, reject) => {
					client.unbindToken({
						onSuccess: resolve,
						onError: reject
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
					tokenID: this.tokenId
				},
				onSuccess: resolve,
				onError: reject
			});
		}).then(containers => {
			var promises = [];
			for(var i in containers) {
				promises.push(new Promise((resolve, reject) => {
					var contId = containers[i].id;
					client.deleteContainer({
						args: {
							contID: contId
						},
						onSuccess: resolve,
						onError: reject
					});
				}));
			}
			return Promise.all(promises);
		});
	};

	/**
	 * Создать запрос на сертификат
	 * @param {DN} dn
	 * @param {string} description описание контейнера
	 * @param {array} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @param {string} ecParams параметры эллиптической кривой ключевой пары. Может принимать значения A, B, C, XA, XB.
	 * @returns {Promise<Object>} объект с полями { csr: 'base64 запрос на сертификат', keyPairId }
	 * @see DN
	 */
	this.generateCSR = function(dn, description, ekuOids, paramSet){
		if(!ekuOids || !ekuOids.length) {
			ekuOids = [
				'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
				'1.3.6.1.5.5.7.3.4' // Защищенная электронная почта
			];
		}
		if(!paramSet) paramSet = 'XA';
		var exts = {
			'certificatePolicies': '1.2.643.100.113.1',
			'keyUsage': 'digitalSignature,keyEncipherment,nonRepudiation,dataEncipherment',
			'extendedKeyUsage': ekuOids.toString(),
			'1.2.643.100.111': 'ASN1:FORMAT:UTF8,UTF8:"Криптотокен" (АЛАДДИН Р.Д.)'
		};
		var id;
		return new Promise((resolve, reject) => {
			client.createKeyPair({
				args: {
					paramSet: paramSet,
      				description: description
				},
				onSuccess: resolve,
				onError: reject
			});
		}).then(keyPairId => {
			id = keyPairId;
			return new Promise((resolve, reject) => {
				client.genCSR({
					args: {
						id: containerId,
      					dn: dn,
      					exts: exts
					},
					onSuccess: resolve,
					onError: reject
				});
			});
		}).then(a => {
			// base64(запрос на сертификат в формате PKCS#10)
			var csr = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
			return { 
				csr: csr,
				keyPairId: id
			};
		});
	};

	/**
	 * Записать сертификат в контейнер
	 * @param {string} certificate base64(массив байт со значением сертификата в формате DER)
	 * @param {int} идентификатор контейнера куда записывать
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
				onError: reject
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
					tokenID: this.tokenId,
					id: containerId
				},
				onSuccess: resolve,
				onError: reject
			});
		}).then(o => {
			var dn = new DN;
			for(var i in o.Data.Subject) {
				var rdn = o.Data.Subject[i].rdn;
				var val = o.Data.Subject[i].value;
				dn[rdn] = val;
			}
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
				toString: function() {
					return 'Название:              ' + this.Name +
						 '\nИздатель:              ' + this.IssuerName +
						 '\nСубъект:               ' + this.SubjectName +
						 '\nВерсия:                ' + this.Version +
						 '\nСерийный №:            ' + this.SerialNumber +
						 '\nОтпечаток SHA1:        ' + this.Thumbprint +
						 '\nНе дествителен до:     ' + this.ValidFromDate +
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
			client.getStandaloneCertificateList({
				args: {
					tokenID: this.tokenId
				},
				onSuccess: resolve,
				onError: reject
			});
		}).then(a => {
			var promises = [];
			for(var i=0; i<a.length; i++) {
				var contId = a[i][0];
				var contName = a[i][1];
				(function(contId, contName) {
					promises.push(new Promise((resolve, reject) => {
						client.parseX509Certificate({
							args: {
								tokenID: this.tokenId,
								id: contId
							},
							onSuccess: resolve,
							onError: reject
						});
					}).then(o => {
						return {
							id: contId,
							name: formatCertificateName(o, contName)
						};
					}));
				})(contId, contName);
			}
			return Promise.all(promises);
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
					tokenID: this.tokenId
				},
				onSuccess: resolve,
				onError: reject
			});
		}).then(a => {
			if(a && a.length) {
				// base64(массив байт со значением сертификата в формате DER)
				var cert = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
				return cert;
			}
			else {
				throw new Error('Нет сертификата в контейнере');
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
		return new Promise((resolve, reject) => {
			client.signBase64EncodedData({
				args: {
					contID: containerId,
					data: dataBase64
				},
				onSuccess: resolve,
				onError: reject
			});
		}).then(sign => {
			return sign;
		});
	};

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