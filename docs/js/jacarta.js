function showInfo(contId) {
    var jacarta = new window.RusCryptoJS.JaCarta;
    return jacarta.init().then(info => {
        console.log('Initialized', info);
        return jacarta.certificateInfo(contId);
    }).then(info => {
        console.log('CertInfo', info);
        inputCertInfo.value = info;
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

function loadCerts() {
    inputCertId.innerHTML = inputCertInfo.value = '';
    
    var jacarta = new window.RusCryptoJS.JaCarta;
    return jacarta.init().then(info => {
        console.log('Initialized', info);
        return jacarta.bind();
    }).then(_ => { 
        return jacarta.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        return setCertOptions(certs);
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta.unbind();
    });
}

var GlobalJaCarta;
var GlobalKeyPairId

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
    GlobalJaCarta = new window.RusCryptoJS.JaCarta2;
    return GlobalJaCarta.init().then(info => {
        console.log('Initialized', info);
        return GlobalJaCarta.bind(inputPin.value);
    }).then(_ => { 
        return GlobalJaCarta.generateCSR(dn, inputDescr.value);
    }).then(result => {
        console.log('generateCSR', result);

        const csr = result.csr;
        inputCsr.value = csr;
        
        GlobalKeyPairId = result.keyPairId;
        
        alert('Выпустите сертификат в УЦ на основе созданного CSR');
        inputCert.disabled = false;
        inputCsr.focus();
    }).catch(e => {
        alert('Failed! ' + e);
    });
};

function requestCertificate() {
    const cert = inputCert.value;
    if(!GlobalJaCarta || !GlobalKeyPairId || !cert) {
        alert('Сначала надо создать CSR');
        return false;
    }    
    return GlobalJaCarta
    .writeCertificate(cert, GlobalKeyPairId)
    .then(contId => {
        console.log('writeCertificate', contId);
        return GlobalJaCarta.certificateInfo(contId);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        inputCsr.value = inputCert.value = '';
        inputCert.disabled = true;
        return GlobalJaCarta.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        return setCertOptions(certs);
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        GlobalJaCarta.unbind();
        GlobalJaCarta = undefined;
    });
}

function signData() {
    inputSign.value = '';
    var jacarta = new window.RusCryptoJS.JaCarta;
    var data = btoa(inputData.value)
    var contId = inputCertId.value;
    return jacarta.init().then(info => {
        console.log('Initialized', info);
        return jacarta.bind();
    }).then(_ => { 
        return jacarta.signData(data, contId);
    }).then(sign => {
        inputSign.value = sign;
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta.unbind();
    });
}