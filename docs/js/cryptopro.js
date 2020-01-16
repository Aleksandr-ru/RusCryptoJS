function showInfo(thumbprint) {
    var cryptopro = new window.RusCryptoJS.CryptoPro;
    return cryptopro.init().then(info => {
        console.log('Initialized', info);
        return cryptopro.certificateInfo(thumbprint);
    }).then(info => {
        console.log('CertInfo', info);
        inputCertInfo.value = info;
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

function loadCerts() {
    inputCertId.innerHTML = inputCertInfo.value = '';
    var options = [];
    var placeholder = document.createElement('option');
    placeholder.selected = true;
    placeholder.disabled = true;
    placeholder.text = 'Выберите сертификат';
    placeholder.value = '';
    options.push(placeholder);

    var cryptopro = new window.RusCryptoJS.CryptoPro;
    return cryptopro.init().then(info => {
        console.log('Initialized', info);
        return cryptopro.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        return setCertOptions(certs);
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

var GlobalCryptoPro;

function requestCSR() {
    inputCsr.value = inputCert.value = '';
    inputCert.disabled = true;
    try {
        var oDn = JSON.parse(inputDN.value);
    }
    catch(e) {
        console.log('Parse DN', e);
        alert(e.message || e);
    }
    var dn = Object.assign(new window.RusCryptoJS.DN, oDn);
    GlobalCryptoPro = new window.RusCryptoJS.CryptoPro;
    return GlobalCryptoPro.init().then(info => {
        console.log('Initialized', info);
        return GlobalCryptoPro.generateCSR(dn, inputDescr.value);
    }).then(result => {
        console.log('generateCSR', result);

        const csr = result.csr;
        inputCsr.value = csr;
        alert('Выпустите сертификат в УЦ на основе созданного CSR');
        inputCert.disabled = false;
        inputCsr.focus();
    }).catch(e => {
        alert('Failed! ' + e);
    });
};

function requestCertificate() {
    const cert = inputCert.value;
    if(!GlobalCryptoPro || !cert) {
        alert('Сначала надо создать CSR');
        return false;
    }    
    return GlobalCryptoPro
    .writeCertificate(cert)
    .then(thumbprint => {
        console.log('writeCertificate', thumbprint);
        return GlobalCryptoPro.certificateInfo(thumbprint);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        inputCsr.value = inputCert.value = '';
        inputCert.disabled = true;
        GlobalCryptoPro = undefined;
        return loadCerts();
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

function signData() {
    inputSign.value = '';
    var cryptopro = new window.RusCryptoJS.CryptoPro;
    var data = btoa(inputData.value)
    var thumbprint = inputCertId.value;
    return cryptopro.init().then(info => {
        console.log('Initialized', info);
        return cryptopro.signData(data, thumbprint);
    }).then(sign => {
        inputSign.value = sign;
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    });
}