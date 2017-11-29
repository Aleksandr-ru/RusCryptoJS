/**
 * JaCarta GOST simplified library
 * @author Aleksandr.ru
 * @link http://aleksandr.ru
 */

function DN(){};
DN.prototype.toString = function(){
	var ret = '';
	for(var i in this) if(this.hasOwnProperty(i)) ret += i + '="' + this[i].replace(/"/g, '') + '", ';
	return ret;
};

function JaCarta() {
	var errors = {
		CKR_CANCEL: 'пользователь отказался от выполнения операции.',
		CKR_HOST_MEMORY: 'недостаточно памяти для выполнения функции.',
		CKR_SLOT_ID_INVALID: 'неправильный идентификатор слота.',
		CKR_GENERAL_ERROR: 'Критическая ошибка, связанная с аппаратным обеспечением; Неудачная попытка проверки пути сертификации.',
		CKR_FUNCTION_FAILED: 'при выполнении функции возник сбой.',
		CKR_ARGUMENTS_BAD: 'недопустимый аргумент.',
		CKR_ATTRIBUTE_READ_ONLY: 'предпринята попытка присвоения значения атрибуту, который нельзя изменять.',
		CKR_ATTRIBUTE_TYPE_INVALID: 'некорректный тип атрибута.',
		CKR_ATTRIBUTE_VALUE_INVALID: 'атрибут нулевой длины.',
		CKR_DEVICE_ERROR: 'ошибка при обращении к устройству или слоту.',
		CKR_DEVICE_MEMORY: 'для выполнения функции недостаточно памяти в устройстве.',
		CKR_FUNCTION_CANCELED: 'время ожидания выполнения функции истекло.',
		CKR_KEY_HANDLE_INVALID: 'функции передан некорректный дескриптор ключа.',
		CKR_KEY_SIZE_RANGE: 'недопустимый размер ключа.',
		CKR_KEY_TYPE_INCONSISTENT: 'данный тип ключа не может использоваться с данным механизмом.',
		CKR_MECHANISM_INVALID: 'при выполнении криптографической функции был указан неправильный механизм.',
		CKR_MECHANISM_PARAM_INVALID: 'при выполнении криптографической функции были заданы некорректные параметры механизма.',
		CKR_OBJECT_HANDLE_INVALID: 'функции передан некорректный дескриптор объекта.',
		CKR_OPERATION_ACTIVE: 'одна или несколько выполняющихся операций препятствуют выполнению новой операции.',
		CKR_OPERATION_NOT_INITIALIZED: 'выполнение операции без предварительного указания параметров невозможно.',
		CKR_PIN_INCORRECT: 'функции передан неверный PIN-код.',
		CKR_PIN_LEN_RANGE: 'недопустимая длина PIN-кода.',
		CKR_PIN_LOCKED: 'PIN-код заблокирован.',
		CKR_SESSION_HANDLE_INVALID: 'функции передан некорректный дескриптор сессии.',
		CKR_SESSION_PARALLEL_NOT_SUPPORTED: 'невозможно открыть параллельную сессию.',
		CKR_SESSION_EXISTS: 'уже открыта сессия работы с тем же устройством.',
		CKR_SESSION_READ_ONLY_EXISTS: 'сессия открыта только для чтения. Смена режима невозможна.',
		CKR_SESSION_READ_WRITE_SO_EXISTS: 'открыта сессия чтения/записи. Открыть сеанс только для чтения невозможно.',
		CKR_SIGNATURE_INVALID: 'неправильное значение электронной подписи.',
		CKR_TEMPLATE_INCOMPLETE: 'для создания объекта недостаточно атрибутов.',
		CKR_TOKEN_NOT_PRESENT: 'в момент выполнения функции устройство было отключено.',
		CKR_TOKEN_WRITE_PROTECTED: 'устройство недоступно для записи.',
		CKR_USER_ALREADY_LOGGED_IN: 'пользователь уже предъявил PIN-код.',
		CKR_USER_NOT_LOGGED_IN: 'функция не может быть выполнена в гостевом режиме работы устройства.',
		CKR_USER_PIN_NOT_INITIALIZED: 'начальное значение PIN-кода не установлено.',
		CKR_USER_TYPE_INVALID: 'функция не может быть выполнена в текущем режиме работы устройства.',
		CKR_USER_ANOTHER_ALREADY_LOGGED_IN: 'невозможно переключение из режима администратора в режим пользователя или обратно.',
		CKR_BUFFER_TOO_SMALL: 'размер заданного буфера является недостаточным для сохранения результатов функции.',
		CKR_INFORMATION_SENSITIVE: 'запрашиваемый объект недоступен для чтения.',
		CKR_CRYPTOKI_NOT_INITIALIZED: 'выполнение функции без инициализации Единой библиотеки PKCS#11 (библиотеки Cryptoki) невозможно.',
		CKR_CRYPTOKI_ALREADY_INITIALIZED: 'попытка повторно инициализировать библиотеку Cryptoki.',
		CKR_FUNCTION_REJECTED: 'пользователь отменил операцию.',
		NOT_STATE_TOKEN_BINDED: 'значение параметра state отличается от STATE_TOKEN_BINDED (1).',
		NOT_STATE_NOT_BINDED: 'значение параметра state отличается от STATE_TOKEN_BINDED (0).',
		IS_STATE_NOT_BINDED: 'параметр state принимает значение STATE_TOKEN_BINDED (0).',
		NOT_STATE_UNILATERAL_AUTHENTICATION_IN_PROGRESS: 'значение параметра state отличается от STATE_TOKEN_BINDED (4).',
		NOT_STATE_SECURE_CHANNEL_CONNECTION_IN_PROGRESS: 'значение параметра state отличается от STATE_TOKEN_BINDED (2).',
		NOT_STATE_SECURE_CHANNEL_ESTABLISHED: 'значение параметра state отличается от STATE_TOKEN_BINDED (3).',
		CERTIFICATE_NOT_FOUND: 'сертификат не обнаружен.',
		PUBLIC_KEY_NOT_FOUND: 'открытый ключ не обнаружен в памяти поддерживаемого устройства.',
		SERVER_PUBLIC_KEY_NOT_FOUND: 'не найден открытый ключ сервера.',
		INVALID_SERVER_PUBLIC_KEY: 'неверный открытый ключ сервера.',
		DATA_TO_SIGN_ZERO_LENGTH: 'на подпись были представлены данные, имеющие нулевую длину.',
		DATA_TO_VERIFY_ZERO_LENGTH: 'на проверку подписи были представлены данные, имеющие нулевую длину.',
		SIGNATURE_TO_VERIFY_ZERO_LENGTH: 'на проверку была представлена подпись, имеющая нулевую длину.',
		INVALID_EC_PARAMS: 'неверно заданы параметры криптографических преобразований по ГОСТ Р 34.10-2001.',
		TOKEN_MEMORY_TOO_SMALL: 'для выполнения операции в поддерживаемом устройстве недостаточно свободной памяти.',
		KEY_SIZE_NOT_64: 'длина ключа не равна 64 битам.',
		CERT_NOT_MATCH_PUBLIC_KEY: 'сертификат не соответствует открытому ключу.',
		FAILED_CHECK_BROWSER_VERS: 'ошибка проверки версии используемого браузера.',
		BROWSER_VERS_NOT_SUPPORTED: 'используемая версия браузера не поддерживается.',
		INVALID_USER_TYPE: 'неверно указан тип PIN-кода.',
		PINS_NOT_MATCH: 'введённые значения нового PIN-кода неодинаковы.',
		USER_CHANGE_ADMIN_PIN_NOT_STATE_NOT_BINDED: 'cмена PIN-кода администратора невозможна, поскольку значение параметра state отличается от STATE_TOKEN_BINDED (0).',
		SSL_ERR_GEN_SESSION_KEY: 'ошибка при генерации ключа защиты данных, передаваемых между клиентом и сервером.',
		SSL_ERR_GOST_ENGINE: 'ошибка средства защиты, программно выполняющего криптографические преобразования на стороне клиента.',
		SSL_ERR_SSL_NEW: 'ошибка в начале выполнения протокола Handshake.',
		SSL_ERR_CONNECT: 'ошибка при выполнении протокола Handshake.',
		SSL_ERR_SSL_WRITE: 'ошибка при подготовке данных к защищённой передаче.',
		SSL_ERR_SSL_READ: 'ошибка при чтении защищённых для передачи данных.',
		SSL_ERR_LOAD_CERT_AND_KEY_FROM_TOKEN: 'ошибка при попытке считать сертификат и открытый ключ из памяти поддерживаемого устройства.',
		SSL_ERR_GET_PEER_PUBLIC_KEY: 'ошибка при получении открытого ключа сервера.',
		CERT_PARS_ERR_GET_PUBLIC_KEY: 'не удалось считать открытый ключ из сертификата.',
		CERT_PARS_ERR_GET_ISSUER_AND_SER_NUMBER: 'не удалось считать имя удостоверяющего центра и серийный номер из сертификата.',
		UNKNOWN_ERROR: 'неизвестная ошибка.'
	};

	var client, tokenId;

	/**
	 * Инициализация и проверка наличия требуемых возможностей
	 * @returns {promise}
	 */
	this.init = function(){
		var defer = $.Deferred();
		if(typeof(Uint8Array) != 'function') {
			defer.reject('Upgrade your browser to something supports Uint8Array!');
		}
		else if(!window.btoa || !window.atob) {
			defer.reject('Upgrade your browser to something supports native base64 encoding!');
		}
		else try {
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
			defer.resolve(version);
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message || e);
		}
		return defer.promise();
	};

	/**
	 * Авторизация на токене с пин-кодом юзера
	 * @param {string} userPin если нет, то предлгает ввести пин через UI плагина
	 * @returns {promise}
	 */
	this.bind = function(userPin) {
		var defer = $.Deferred();

		try {
			var state = client.getLoggedInState().shift();
			if(state === 1) {
				defer.resolve();
			}
			else if(!userPin) {
				if(client.bindTokenUI(tokenId)) {
					defer.resolve();
				}
				else {
					defer.reject('Пользователь отменил ввод PIN-кода');
				}
			}
			else {
				client.bindTokenAsync(tokenId, userPin, function(a){
					if(a && a[0] == 'Error') {
						var code = a[1];
						var err = getError(code);
						defer.reject(err);
					}
					else {
						defer.resolve();
					}
				});
			}
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};
	
	this.unbind = function() {
		var defer = $.Deferred();

		try {
			var state = client.getLoggedInState().shift();
			if(state === 1) {
				client.unbindToken();
			}
			defer.resolve();
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};
	
	this.clean = function(){
		var defer = $.Deferred();

		try {
			var aContainers = client.getCertificateList(tokenId);
			for(var i in aContainers) {
				var containerId = aContainers[i].shift();
				client.deleteContainerOrCertificate(containerId);
			}
			defer.resolve(i);
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};

	/**
	 * Создать запрос на сертификат
	 * @param {DN} dn
	 * @param {string} description описание контейнера
	 * @param {array} ekuOids массив OID Extended Key Usage, по-умолчанию Аутентификация клиента '1.3.6.1.5.5.7.3.2' + Защищенная электронная почта '1.3.6.1.5.5.7.3.4'
	 * @param {string} ecParams параметры эллиптической кривой ключевой пары. Может принимать значения A, B, C, XA, XB.
	 * @returns {promise}
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
		var defer = $.Deferred();
		try {
			client.createContainerAsync(ecParams, description, function(a){
				if(a && a[0] == 'Error') {
					var code = a[1];
					var err = getError(code);
					defer.reject(err);
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
							defer.reject(err);
						}
						else {
							// base64(запрос на сертификат в формате PKCS#10)
							var csr = btoa(String.fromCharCode.apply(null, new Uint8Array(a)));
							defer.resolve(csr, containerId);
						}
					});
				}
			});			
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};

	/**
	 * Записать сертификат в контейнер
	 * @param {string} certificate base64(массив байт со значением сертификата в формате DER)
	 * @param {int} идентификатор контейнера куда записывать
	 * @returns {promise}
	 */
	this.writeCertificate = function(certificate, containerId){
		var defer = $.Deferred();

		try {
			var aCertificate = [];
			var der = atob(certificate);
			for(var i=0; i<der.length; i++) {
				aCertificate[i] = der.charCodeAt(i);
			}
			client.writeCertificateAsync(containerId, aCertificate, function(){
				defer.resolve();
			});
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};

	//TODO: certificateInfo

	/**
	 * Получение массива доступных сертификатов [[id, subject], ...]
	 * @returns {promise}
	 */
	this.listCertificates = function(){
		var defer = $.Deferred();

		try {
			client.getCertificateListAsync(tokenId, function(a){
				if(a && a[0] == 'Error') {
					var code = a[1];
					var err = getError(code);
					defer.reject(err);
				}
				else {
					var certs = a;
					for(var i=0; i<certs.length; i++) {
						var certId = certs[i][0];
						var certName = certs[i][1];
						if(!certName) {
							var inf = client.getCertificateInfo(tokenId, certId);
							certs[i][1] = parseCertificateInfo(inf);
						}
					}
					defer.resolve(certs);
				}
			});
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};
			
	/**
	 * Подписать данные. Выдает подпись в формате PKCS#7, опционально закодированную в Base64
	 * @param {string} data данные (и подпись) закодированы в base64
	 * @param {int} containerId идентификатор контейнера (сертификата)
	 * @returns {promise} строка-подпись в формате PKCS#7, закодированная в Base64.
	 */
	this.signData = function(dataBase64, containerId){
		var attachedSignature = false;
		var defer = $.Deferred();
		try {
			client.signBase64EncodedDataAsync(containerId, dataBase64, attachedSignature, false, function(a){
				if(a && a[0] == 'Error') {
					var code = a[1];
					var err = getError(code);
					defer.reject(err);
				}
				else {
					var sign = a;
					defer.resolve(sign);
				}
			});
		}
		catch(e) {
			var err = getError();
			defer.reject(err || e.message);
		}
		return defer.promise();
	};

	/**
	 * Получить ошибку по коду
	 * @param {int} code код ошибки
	 * @returns {string|Boolean} false если нет ошибки (CKR_OK)
	 */
	function getError(code) {
		try {
			code = code || client.getLastError();
			var message = client.getErrorMessage(code);
			if(!code || message == 'CKR_OK') {
				return false;
			}
			return errors[message] || message;
		}
		catch(e) {
			return e.message;
		}
	}

	/**
	 * Вытаскивает последний CN из массива байт информации о сертификате
	 * @param {array} inf
	 * @returns {string}
	 */
	function parseCertificateInfo(inf){
		var cert = atos(inf).replace(/\\/g, '');
		var cn = cert.match(/CN=[^\r\n]+/g);
		return cn.pop().slice(3);
	}

	/**
	 * http://stackoverflow.com/questions/14028148/convert-integer-array-to-string-at-javascript
	 * @param {array} arr
	 * @returns {String}
	 */
	function atos(arr){
		for (var i=0, l=arr.length, s='', c; c = arr[i++];) {
			s += String.fromCharCode(
				c > 0xdf && c < 0xf0 && i < l-1
					? (c & 0xf) << 12 | (arr[i++] & 0x3f) << 6 | arr[i++] & 0x3f
				: c > 0x7f && i < l
					? (c & 0x1f) << 6 | arr[i++] & 0x3f
				: c
			);
		}
		return s;
	}
}