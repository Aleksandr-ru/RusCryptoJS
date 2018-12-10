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
        for(var i in certs) {
            var option = document.createElement('option');
            option.value = certs[i].id;
            option.text = certs[i].name;
            options.push(option);
        }
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        for(var i in options) {
            inputCertId.appendChild(options[i]);
        }
    });
}

function requestCertificate() {
    inputCsr.value = inputCert.value = '';
    try {
        var oDn = JSON.parse(inputDN.value);
    }
    catch(e) {
        console.log('Parse DN', e);
        alert(e.message || e);
    }
    var dn = Object.assign(new window.RusCryptoJS.DN, oDn);
    var cryptopro = new window.RusCryptoJS.CryptoPro;
    return cryptopro.init().then(info => {
        console.log('Initialized', info);
        return cryptopro.generateCSR(dn, inputDescr.value);
    }).then(result => {
        console.log('generateCSR', result);

        const csr = result.csr;
        inputCsr.value = csr;
        
        const data = new FormData();
        data.append('csr', csr);

        const url = inputCaUrl.value
        return fetch(url, {
            method: 'POST',
            body: data
        });
    }).then(response => {
        console.log('CA response', response);
        if(!response.ok) {
            throw new Error(response.statusText);
        }
        return response.json();
    }).then(json => {
        console.log('JSON', json);
        const cert = json.cert;
        inputCert.value = cert;
        return cryptopro.writeCertificate(cert);
    }).then(thumbprint => {
        console.log('writeCertificate', thumbprint);
        return cryptopro.certificateInfo(thumbprint);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
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