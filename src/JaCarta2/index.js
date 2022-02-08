/**
 * JaCarta-2 GOST simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */
import sha1 from 'js-sha1';
import DN from '../DN';
import errors from './errors';
import { convertDN, stripDnQuotes } from '../helpers';

function JaCarta2() {

	let client, tokenId;
	// const debug = process.env.NODE_ENV === 'development';

	// костылёк из-за отсутствия isAsyncOperationInProgress в версии 4.3
	let asyncOperationInProgress = false;

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {Promise<{version: string, serialNumber: string, label: string, type: string, flags: Object}>} версия, информация о токене
	 */
	this.init = function () {
		const final = {};
		return new Promise((resolve, reject) => {
			if (typeof (JCWebClient2) !== 'undefined') {
				resolve();
			}
			else {
				getScript('https://localhost:24738/JCWebClient.js', resolve, reject);
			}
		}).then(() => {
			client = JCWebClient2;
			client.initialize();
			if (!client.isAsyncOperationInProgress) {
				client.isAsyncOperationInProgress = () => asyncOperationInProgress;
			}
			return sync(client.Cmds.getJCWebClientVersion);
		}).then(version => {
			// console.log('JCWebClient2 v.%s', version);
			final['version'] = version;
			return sync(client.Cmds.getAllSlots);
		}).then(slots => {
			return new Promise(resolve => {
				// console.log('Got %d slots', slots.length, slots);
				const aTokens = slots.filter(a => {
					return a.tokenExists;
				});
				if (aTokens && aTokens.length === 1) {
					// OK 1 токен
					const token = aTokens.shift();
					resolve(token.id);
				}
				else if (aTokens && aTokens.length > 1) {
					throw new Error('Подключено ' + aTokens.length + ' токена(ов)');
				}
				else {
					throw new Error('Нет подключенных токенов');
				}
			});
		}).then(tokenID => {
			tokenId = tokenID;
			return sync(client.Cmds.getTokenInfo, {
				tokenID
			});
		}).then(info => {
			const allowedTypes = [ client.Vars.TokenType.gost, client.Vars.TokenType.gost2 ];
			if (allowedTypes.indexOf(info.type) === -1) {
				throw new Error('Подключен токен недопустимого типа: ' + info.type);
			}
			return Object.assign(final, info);
		});
	};

	/**
	 * Авторизация на токене с пин-кодом юзера
	 * @param {string} userPin если нет, то предлагает ввести пин через UI плагина
	 * @returns {Promise<void>}
	 */
	this.bind = function (userPin) {
		return sync(client.Cmds.getLoggedInState).then(result => {
			if (result.state === client.Vars.AuthState.binded && result.tokenID === tokenId) {
				return true;
			}
			else {
				const args = {
					tokenID: tokenId
				};
				if (!userPin) {
					args.useUI = true;
				}
				else {
					args.pin = userPin;
				}
				return sync(client.Cmds.bindToken, args);
			}
		});
	};

	/**
	 * Отменить предъявление PIN-кода. Необходимо вызывать при завершении сеанса работы
	 * @returns {Promise<void>}
	 */
	this.unbind = function () {
		return sync(client.Cmds.getLoggedInState).then(result => {
			if (result.state !== client.Vars.AuthState.notBinded) {
				return sync(client.Cmds.unbindToken);
			}
			else {
				return true;
			}
		});
	};

	/**
	 * Очистка токена (удаление всех контейнеров)
	 * @returns {Promise<void>}
	 */
	this.clean = function () {
		return sync(client.Cmds.getContainerList, {
			tokenID: tokenId
		}).then(containers => {
			let p = Promise.resolve();
			for (let i in containers) {
				p = p.then(() => sync(client.Cmds.deletePKIObject, {
					id: containers[i].id
				}));
			}
			return p;
		});
	};

	/**
	 * Создать запрос на сертификат
	 * @param {DN} dn
	 * @param {Array<string>} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @param {object} [options]
	 * @param {string} [options.description] описание контейнера
	 * @param {string} [options.algorithm] Алгоритм "GOST-2012-256" (по-умолчанию) или "GOST-2001".
	 * @returns {Promise<{ csr: string; keyPairId: number; }>} объект с полями {csr: 'base64 запрос на сертификат', keyPairId}
	 * @see DN
	 */
	this.generateCSR = function (dn, ekuOids, options) {
		if (!ekuOids || !ekuOids.length) ekuOids = [
			'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
			'1.3.6.1.5.5.7.3.4' // Защищенная электронная почта
		];
		if (!options) options = {};
		const description = options.description || dn.CN; //TODO: subj to change
		const algorithm = options.algorithm || client.Vars.KeyAlgorithm.GOST_2012_256; // "GOST-2012-256"
		const exts = {
			'certificatePolicies': '1.2.643.100.113.1',
			'keyUsage': 'digitalSignature,keyEncipherment,nonRepudiation,dataEncipherment',
			'extendedKeyUsage': ekuOids.toString(),
			'1.2.643.100.111': 'ASN1:FORMAT:UTF8,UTF8:"Криптотокен" (АЛАДДИН Р.Д.)'
		};
		const paramSet = 'XA';
		let id;

		return sync(client.Cmds.createKeyPair, {
			paramSet: paramSet,
			description: description,
			algorithm: algorithm
		}).then(keyPairId => {
			id = keyPairId;
			return sync(client.Cmds.genCSR, {
				id,
				dn,
				exts
			});
		}).then(a => {
			// base64(запрос на сертификат в формате PKCS#10)
			const csr = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
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
	this.writeCertificate = function (certificate, keyPairId) {
		return sync(client.Cmds.writeUserCertificate, {
			keyPairID: keyPairId,
			cert: certificate
		});
	};

	/**
	 * Получение информации о сертификате.
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {Promise<Object>}
	 */
	this.certificateInfo = function (containerId) {
		return sync(client.Cmds.parseX509Certificate, {
			tokenID: tokenId,
			id: containerId
		}).then(o => {
			const dn = makeDN(o.Data.Subject);
			const dnI = makeDN(o.Data.Issuer);
			const dt = new Date();
			return {
				Name: dn.CN,
				Issuer: dnI,
				IssuerName: stripDnQuotes(dnI.toString()),
				Subject: dn,
				SubjectName: stripDnQuotes(dn.toString()),
				Version: o.Data.Version,
				SerialNumber: o.Data['Serial Number'].map(byte2hex).join(''),
				Thumbprint: undefined, // sha1(body)
				ValidFromDate: o.Data.Validity['Not Before'],
				ValidToDate: o.Data.Validity['Not After'],
				HasPrivateKey: true,
				IsValid: dt >= o.Data.Validity['Not Before'] && dt <= o.Data.Validity['Not After'],
				Algorithm: o.Data['Subject Public Key Info']['Public Key Algorithm'],
				//ProviderName: '', //TODO
				//ProviderType: undefined, //TODO
				toString: function () {
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
		}).then(info => sync(client.Cmds.getCertificateBody, {
			id: containerId,
			tokenID: tokenId
		}).then(a => {
			info.Thumbprint = sha1(a); // supports byte `Array`
			return info;
		}));
	};

	/**
	 * Получение массива доступных сертификатов
	 * @returns {Promise<{id: string; name: string;}[]>} [{id, name}, ...]
	 */
	this.listCertificates = function () {
		return sync(client.Cmds.getContainerList, {
			tokenID: tokenId
		}).then(a => {
			const certs = [];
			let p = Promise.resolve();
			for (let i = 0; i < a.length; i++) {
				const contId = a[i].id;
				const contName = a[i].description;

				(function (contId, contName) {
					p = p.then(() => sync(client.Cmds.parseX509Certificate, {
						tokenID: tokenId,
						id: contId
					}).then(o => {
						const dn = makeDN(o.Data && o.Data.Subject);
						certs.push({
							id: contId,
							name: formatCertificateName(dn, contName)
						});
						return certs.length;
					}));
				})(contId, contName);
			}
			return p.then(function () {
				return certs;
			});
		});
	};

	/**
	 * Получить сертификат из контейнера
	 * @param {int} containerId
	 * @returns {Promise<string>} base64(массив байт со значением сертификата в формате DER)
	 */
	this.readCertificate = function (containerId) {
		return sync(client.Cmds.getCertificateBody, {
			id: containerId,
			tokenID: tokenId
		}).then(a => {
			if (a && a.length) {
				// base64(массив байт со значением сертификата в формате DER)
				const cert = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
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
	this.signData = function (dataBase64, containerId, options) {
		if (!options) options = {};
		const {attached} = options;
		return sync(client.Cmds.signBase64EncodedData, {
			contID: containerId,
			data: dataBase64,
			attachedSignature: !!attached
		}).then(sign => pemSplit(sign));
	};

	/**
	 * Проверить подпись.
	 * @param {string} dataBase64 игнорируется если прикрепленная подпись
	 * @param {string} signBase64 существующая подпись
	 * @param {object} [options]
	 * @param {boolean} [options.attached] присоединенная подпись
	 * @returns {Promise<boolean>} true или reject
	 */
	this.verifySign = function (dataBase64, signBase64, options) {
		if (!options) options = {};
		const {attached} = options;
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
		return sync(client.Cmds.verifyData, args);
	};

	/**
	 * Шифрование данных
	 * @param {string} dataBase64 данные в base64
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {Promise<string>} base64 enveloped data
	 */
	this.encryptData = function (dataBase64, containerId) {
		// https://stackoverflow.com/questions/21797299/convert-base64-string-to-arraybuffer/21797381
		const dataByte = Array.from(atob(dataBase64), c => c.charCodeAt(0));
		return this.readCertificate(containerId).then(cert => sync(client.Cmds.encryptData, {
			contID: containerId,
			receiverCertificate: cert, // для 4.2 и ниже
			receiverCertificates: [cert], // для 4.3 и выше
			data: dataByte // Данные для шифрования в виде массива байт.
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
	this.decryptData = function (dataBase64, containerId) {
		const dataByte = Array.from(atob(dataBase64), c => c.charCodeAt(0));
		return this.readCertificate(containerId).then(cert => {
			const certByte = Array.from(atob(cert), c => c.charCodeAt(0));
			return sync(client.Cmds.decryptData, {
				contID: containerId,
				senderCertificate: certByte, // Сертификат отправителя в виде массива байт.
				data: dataByte // Массив байт с зашифрованными данными в формате CMS.
			})
		}).then(data => btoa(String.fromCharCode.apply(null, new Uint8Array(data))));
	};

	/**
	 * Выполнить асинхронную команду не перебивая другие
	 * @param {string} cmd Тип выполняемый команды из JCWebClient2.Cmds...
	 * @param {Object} args Аргументы команды
	 * @returns {Promise<any>}
	 */
	function sync(cmd, args)
	{
		return new Promise(resolve => {
			const timeout = 100;
			let delay = 0;
			const checkFn = function () {
				if (delay > 60000) {
					throw new Error('Не удалось дождаться завершения асинхронной операции');
				}
				else if (client.isAsyncOperationInProgress()) {
					setTimeout(checkFn, timeout);
					delay += timeout;
				}
				else {
					resolve();
				}
			};
			setTimeout(checkFn, 0); // первый же запуск в следующем тике
		}).then(() => new Promise((resolve, reject) => {
			asyncOperationInProgress = true;
			client.exec({
				async: true,
				cmd,
				args,
				onSuccess: successHandler(resolve),
				onError: errorHandler(reject)
			});
		}));
	}

	/**
	 * Обработчик успешного выполнения
	 * @param {function(any)} resolve
	 * @returns {function(any): void}
	 */
	function successHandler(resolve)
	{
		return result => {
			asyncOperationInProgress = false;
			resolve(result);
		}
	}

	/**
	 * Обработчик ошибок
	 * @param {function(any)} reject
	 * @returns {function(error: any): void}
	 */
	function errorHandler(reject)
	{
		return error => {
			asyncOperationInProgress = false;
			if(client && error.name === 'JCWebClientError' && errors[error.message]) {
				// подменяем сообщение на более понятное
				error.message = errors[error.message];
			}
			reject(error);
		}
	}

	/**
	 * Создать DN из массива [{rdn: ..., value: ...}, ...]
	 * @param {Array<{ rdn: string, value: string }>} obj
	 * @returns {DN}
	 */
	function makeDN(obj)
	{
		const dn = new DN;
		for(let i in obj) {
			const rdn = obj[i].rdn;
			const val = obj[i].value;
			if (rdn && val) {
				dn[rdn] = val;
			}
		}
		return convertDN(dn);
	}

	/**
	 * Получить название сертификата
	 * @param {DN} o объект, включающий в себя значения субъекта сертификата.
	 * @param {string} containerName
	 * @returns {string} 
	 */
	function formatCertificateName(o, containerName)
	{
		return '' + o['CN']
			+ (o['INNLE'] ? '; ИНН ЮЛ ' + o['INNLE'] : '')
			+ (o['INN'] ? '; ИНН ' + o['INN'] : '')
			+ (o['SNILS'] ? '; СНИЛС ' + o['SNILS'] : '')
			+ (containerName ? ' (' + containerName + ')' : '');
	}

	/**
	 * Переводит байт из десятичного в шестнадцатеричное представление
	 * @param {number} byte
	 * @returns {string}
	 */
	function byte2hex(byte) {
		//console.log('byte %d -> %s', byte, byte.toString(16));
		return ('0' + byte.toString(16)).slice(-2);
	}

	// https://gist.github.com/hendriklammers/5231994
	function pemSplit(str) {
		const re = new RegExp('.{1,64}', 'g');
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
