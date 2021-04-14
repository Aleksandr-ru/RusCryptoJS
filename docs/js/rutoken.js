var chkAuth = document.getElementById('chkauth');

function showInfo(contId) {
    var rutoken = new window.RusCryptoJS.RuToken;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        if (chkAuth.checked) return rutoken.bind();
        else return Promise.resolve();
    }).then(() => {
        return rutoken.certificateInfo(contId);
    }).then(info => {
        console.log('CertInfo', info);
        inputCertInfo.value = info;
        if (chkAuth.checked) return rutoken.unbind();
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

function loadCerts() {
    inputCertId.innerHTML = inputCertInfo.value = '';

    var rutoken = new window.RusCryptoJS.RuToken;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        return setCertOptions(certs);
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

var GlobalRuToken;

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
    GlobalRuToken = new window.RusCryptoJS.RuToken;
    return GlobalRuToken.init().then(info => {
        console.log('Initialized', info);
        return GlobalRuToken.bind(inputPin.value);
    }).then(_ => { 
        return GlobalRuToken.generateCSR(dn, inputDescr.value);
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
    if(!GlobalRuToken || !cert) {
        alert('Сначала надо создать CSR');
        return false;
    }    
    return GlobalRuToken
    .writeCertificate(cert)
    .then(contId => {
        console.log('writeCertificate', contId);
        return GlobalRuToken.certificateInfo(contId);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        inputCsr.value = inputCert.value = '';
        inputCert.disabled = true;
        return GlobalRuToken.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        return setCertOptions(certs);
    }).then(null, e => {
        alert('Failed! ' + e);
    }).then(() => {
        GlobalRuToken.unbind();
        GlobalRuToken = undefined;
    });
}

function signData() {
    inputSign.value = '';
    var rutoken = new window.RusCryptoJS.RuToken;
    var data = btoa(inputData.value);
    var attached = inputAttached.checked;
    var contId = inputCertId.value;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.bind();
    }).then(_ => { 
        return rutoken.signData(data, contId, { attached });
    }).then(sign => {
        inputSign.value = sign;
        return rutoken.verifySign(data, sign, { attached });
    }).then(_ => {
        console.log('Signed and verified')
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        rutoken.unbind();
    });
}

function encryptData() {
    inputEncrypted.value = inputDecrypted.value = '';
    var rutoken = new window.RusCryptoJS.RuToken;
    var data = btoa(inputData2.value);
    var contId = inputCertId2.value;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.bind(inputPin2.value);
    }).then(_ => {
        return rutoken.encryptData(data, contId);
    }).then(encrypted => {
        inputEncrypted.value = encrypted;
        return rutoken.decryptData(encrypted, contId, inputPin2.value);
    }).then(decrypted => {
        inputDecrypted.value = atob(decrypted);
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        rutoken.unbind();
    });
}
