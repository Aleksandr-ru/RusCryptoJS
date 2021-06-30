function showInfo(contId) {
    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.certificateInfo(contId);
    }).then(info => {
        console.log('CertInfo', info);
        inputCertInfo.value = info;
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

function loadCerts() {
    inputCertId.innerHTML = inputCertInfo.value = '';

    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        setCertOptions(certs);
        return certs;
    }).then(certs => {
        if (inputAllInfo.checked) {
            inputCertInfo.value = '';
            var infos = certs.map((cert, i) => jacarta2.certificateInfo(cert.id).then(info => {
                console.log('info %d %o', i, info);
                inputCertInfo.value += (i+1) + ' ' + '-'.repeat(100) + '\n' + info + '\n';
            }));
            return Promise.all(infos).then(() => alert('Done!'));
        }
    }).catch(e => {
        alert('Failed! ' + e);
    });
}

var GlobalJaCarta2;
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
    GlobalJaCarta2 = new window.RusCryptoJS.JaCarta2;
    return GlobalJaCarta2.init().then(info => {
        console.log('Initialized', info);
        return GlobalJaCarta2.bind(inputPin.value);
    }).then(_ => { 
        return GlobalJaCarta2.generateCSR(dn, inputDescr.value);
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
    if(!GlobalJaCarta2 || !GlobalKeyPairId || !cert) {
        alert('Сначала надо создать CSR');
        return false;
    }    
    return GlobalJaCarta2
    .writeCertificate(cert, GlobalKeyPairId)
    .then(contId => {
        console.log('writeCertificate', contId);
        return GlobalJaCarta2.certificateInfo(contId);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        inputCsr.value = inputCert.value = '';
        inputCert.disabled = true;
        return GlobalJaCarta2.listCertificates();
    }).then(certs => {
        console.log('Certs', certs);
        return setCertOptions(certs);
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        GlobalJaCarta2.unbind();
        GlobalJaCarta2 = undefined;
    });
}

function signData() {
    inputSign.value = '';
    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    var data = btoa(inputData.value);
    var attached = inputAttached.checked;
    var contId = inputCertId.value;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.bind();
    }).then(_ => { 
        return jacarta2.signData(data, contId, { attached });
    }).then(sign => {
        inputSign.value = sign;
        alert('Success!');
        return jacarta2.verifySign(data, sign, { attached });
    }).then(result => {
        console.log('Sign Verified: ', result);
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta2.unbind();
    });
}

function encryptData() {
    inputEncrypted.value = inputDecrypted.value = '';
    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    var data = btoa(inputData2.value);
    var contId = inputCertId2.value;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.bind(inputPin2.value);
    }).then(_ => {
        return jacarta2.encryptData(data, contId);
    }).then(encrypted => {
        inputEncrypted.value = encrypted;
        return jacarta2.decryptData(encrypted, contId, inputPin2.value);
    }).then(decrypted => {
        inputDecrypted.value = atob(decrypted);
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta2.unbind();
    });
}
