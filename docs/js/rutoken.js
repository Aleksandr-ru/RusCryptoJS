function showInfo(contId) {
    var rutoken = new window.RusCryptoJS.RuToken;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.certificateInfo(contId);
    }).then(info => {
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
    }).finally(() => {
        rutoken.unbind();
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
    var rutoken = new window.RusCryptoJS.RuToken;
    return rutoken.init().then(info => {
        console.log('Initialized', info);
        return rutoken.bind();
    }).then(_ => { 
        return rutoken.generateCSR(dn, inputDescr.value);
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
        inputCert = cert;
        return rutoken.writeCertificate(cert);
    }).then(certId => {
        console.log('writeCertificate', certId);
        return rutoken.certificateInfo(certId);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        return loadCerts();
    }).catch(e => {
        alert('Failed! ' + e);
    }).finally(() => {
        rutoken.unbind();
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
    }).finally(() => {
        rutoken.unbind();
    });
}