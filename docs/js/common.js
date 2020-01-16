var oDn = {
    'CN': 'Иванов Иван',
    '2.5.4.4': 'Иванов',
    '2.5.4.42': 'Иван',
    '2.5.4.12': 'Директор департамента',
    '2.5.4.9': 'ул. Ивановская 99',
    '2.5.4.11': 'Отдел маркетинга',
    'O': 'ОАО "Серьезные люди"',
    '2.5.4.7': 'г. Москва', //L localityName нас пункт
    '2.5.4.8': '77 г. Москва', //S tateOrProvinceName регион
    'C': 'RU',
    '1.2.840.113549.1.9.1': 'example@domain.ru',
    '1.2.643.3.131.1.1': '000000000076', //'NUMERICSTRING:000000000076', //ИНН
    '1.2.643.100.1': '0000000000024', // 'NUMERICSTRING:0000000000024', // ОГРН
    '1.2.643.100.3': '00000000052', // 'NUMERICSTRING:00000000052' // СНИЛС
};
var inputPin = document.getElementById('pin');
var inputDescr = document.getElementById('descr');
var inputDN = document.getElementById('dn');
var inputCsr = document.getElementById('csr');
var inputCert = document.getElementById('cert');
var inputCertInfo = document.getElementById('certInfo');
var inputCertId = document.getElementById('certId');
var inputData = document.getElementById('data');
var inputSign = document.getElementById('sign');
var formCsr = document.getElementById('formCsr');
var formCert = document.getElementById('formCert');
var formSign = document.getElementById('formSign');
var buttonRefresh = document.getElementById('refresh');

inputDN.value = JSON.stringify(oDn, null, '\t');

buttonRefresh.addEventListener('click', e => {
    e.preventDefault();
    loadCerts();
});

inputCertId.addEventListener('change', e => {
    const contId = e.target.value;
    inputCertInfo.value = '';
    if(!contId) return;
    showInfo(contId);
});

formCsr.addEventListener('submit', e => {
    e.preventDefault();
    requestCSR();
});

formCert.addEventListener('submit', e => {
    e.preventDefault();
    requestCertificate();
});

formSign.addEventListener('submit', e => {
    e.preventDefault();
    signData();
});

function setCertOptions(certs) {
    inputCertId.innerHTML = '';
    var options = [];
    var placeholder = document.createElement('option');
    placeholder.selected = true;
    placeholder.disabled = true;
    placeholder.text = 'Выберите сертификат';
    placeholder.value = '';
    options.push(placeholder);

    for(var i in certs) {
        var option = document.createElement('option');
        option.value = certs[i].id;
        option.text = certs[i].name;
        options.push(option);
    }
    for(var i in options) {
        inputCertId.appendChild(options[i]);
    }
}