# RusCryptoJS
JS для Российской криптографии (ГОСТ)

### Общие требования
- Поддержка base64 кодирования в браузере (btoa, atob)
- Поддержка Uint8Array в браузере
- jQuery 1.5+

## Крипто-ПРО
Для работы с Крипто-ПРО 4.x и Browser Plugin 2.x (cades plugin)

Использование:
```
<script>
	window.cadesplugin_skip_extension_install = false; // считаем что уже все установлено
	window.allow_firefox_cadesplugin_async = true; // FF 52+
</script>
<script src="jquery.js"></script><!-- требуется jQuery 1.5+ -->
<script src="es6-promise.min.js"></script><!-- на случай если не поддерживает -->
<script src="cadesplugin_api.js"></script><!-- родная библиотека от Крипто-ПРО -->
<script src="cryptopro.js"></script>
```

Список сертификатов:
```
<script>
	var cryptoPro = new CryptoPro;
	cryptoPro.init().then(function(version){
		console.log('CryptoPro %s', version);
		return cryptoPro.listCertificates();
	}).then(function(certs){
		for(var i in certs) $('#form select').append($('<option/>').val(certs[i][0]).text(certs[i][1]));
	}).fail(function(e){
		alert(e.message || e);
	});
</script>
```

Получение сертификата:
```
<script>
	var dn = new DN;
	dn.CN = 'ФИО';
	dn['OID.2.5.4.4'] = 'Фамилия';
	dn['OID.2.5.4.42'] = 'Имя Отчество';
	dn['OID.2.5.4.6'] = 'RU';
	dn['OID.2.5.4.8'] = '77 Москва';
	dn['OID.2.5.4.7'] = 'г. Москва';
	dn['OID.1.2.643.100.3'] = 'СНИЛС';
	dn['OID.1.2.643.3.131.1.1'] = 'ИНН';

	var cryptoPro = new CryptoPro;
	cryptoPro.init().then(function(){
		return cryptoPro.generateCSR(dn, '1111', [
			'1.3.6.1.5.5.7.3.2', // Аутентификация клиента
			'1.3.6.1.5.5.7.3.4', // Защищенная электронная почта
			'1.2.643.2.2.34.6', // Пользователь Центра Регистрации, HTTP, TLS клиент
			'1.2.643.5.1.24.2.1.3' // Запрос из ЕГРП для ФЛ
		]);
	}).then(function(csr){
		return $.getJSON('get-cert.php', {csr: csr}); // общение с УЦ на сервере
	}).then(function(json){
		return cryptoPro.writeCertificate(json.cert);
	}).then(function(certThumbprint){
		return cryptoPro.certificateInfo(certThumbprint);
	}).then(function(info){
		console.log(info);
	});
</script>
```

Подпись данных:
```
<script>
	var cryptoPro = new CryptoPro;
	cryptoPro.init().then(function(){
		return cryptoPro.signData(fileBodyBase64, certThumbprint);
	}).then(function(sign){
		console.log(sign);
		// Совмещенная (совместная) подпись
		return cryptoPro.signData2(fileBodyBase64, certThumbprint1, pin1, certThumbprint2, pin2);
	}).then(function(sign2){
		console.log(sign2);
	});
</script>
```

Более подробно см. документацию в коде.

## JaCarta ГОСТ
Для работы с JaCarta Web Plugin 3.x

Использование:
```
<script src="jquery.js"></script><!-- требуется jQuery 1.5+ -->
<script src="jacarta.js"></script>
```

Список сертификатов:
```
<script>
	var jaCarta = new JaCarta;
	jaCarta.init().then(function(version){
		console.log('JaCarta %s', version);
		return jaCarta.listCertificates();
	}).then(function(certs){
		for(var i in certs) $('#form select').append($('<option/>').val(certs[i][0]).text(certs[i][1]));
	}).fail(function(e){
		alert(e.message || e);
	});
</script>
```

Получение сертификата:
```
<script>
	var dn = new DN;
	dn.CN = 'ФИО';
	dn['OID.2.5.4.4'] = 'Фамилия';
	dn['OID.2.5.4.42'] = 'Имя Отчество';
	dn['OID.2.5.4.6'] = 'RU';
	dn['OID.2.5.4.8'] = '77 Москва';
	dn['OID.2.5.4.7'] = 'г. Москва';
	dn['OID.1.2.643.100.3'] = 'СНИЛС';
	dn['OID.1.2.643.3.131.1.1'] = 'ИНН';

	var jaCarta = new JaCarta;
	var containerId;
	jaCarta.init().then(function(){
		return jaCarta.generateCSR(dn, 'название');
	}).then(function(csr, contId){
		containerId = contId;
		return $.getJSON('get-cert.php', {csr: csr}); // общение с УЦ на сервере
	}).then(function(json){
		return jaCarta.writeCertificate(json.cert, containerId);
	});
</script>
```

Подпись данных:
```
<script>
	var jaCarta = new JaCarta;
	jaCarta.init().then(function(){
		return jaCarta.signData(fileBodyBase64, certId);
	}).then(function(sign){
		console.log(sign);
	});
</script>
```
Более подробно см. документацию в коде.

## RuToken
Возможно когда-гибудь...