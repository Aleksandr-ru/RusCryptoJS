function showInfo(contId) {
    var rutoken = new window.RusCryptoJS.RuToken;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.certificateInfo(contId);
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

    var rutoken = new window.RusCryptoJS.RuToken;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.bind();
    }).then(_ => { 
        return rutoken.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        for(var i in certs) {
            var option = document.createElement('option');
            option.value = certs[i].id;
            option.text = certs[i].name;
            options.push(option);
        }
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        rutoken.unbind();
        for(var i in options) {
            inputCertId.appendChild(options[i]);
        }
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
    var contId = inputCertId.value;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.bind();
    }).then(_ => { 
        return rutoken.signData(data, contId);
    }).then(sign => {
        inputSign.value = sign;
        return rutoken.verifySign(data, sign);
    }).then(_ => {
        console.log('Signed and verified')
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        rutoken.unbind();
    });
}