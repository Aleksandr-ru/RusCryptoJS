function showInfo(contId) {
    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.certificateInfo(contId);
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

    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.bind();
    }).then(_ => { 
        return jacarta2.listCertificates();
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
        jacarta2.unbind();
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
    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    var keyPairId;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.bind();
    }).then(_ => { 
        return jacarta2.generateCSR(dn, inputDescr.value);
    }).then(result => {
        console.log('generateCSR', result);

        const csr = result.csr;
        inputCsr.value = csr;
        
        keyPairId = result.keyPairId;
        
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
        return jacarta2.writeCertificate(cert, keyPairId);
    }).then(contId => {
        console.log('writeCertificate', contId);
        return jacarta2.certificateInfo(contId);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        return loadCerts();
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta2.unbind();
    });
}

function signData() {
    inputSign.value = '';
    var jacarta2 = new window.RusCryptoJS.JaCarta2;
    var data = btoa(inputData.value)
    var contId = inputCertId.value;
    return jacarta2.init().then(info => {
        console.log('Initialized', info);
        return jacarta2.bind();
    }).then(_ => { 
        return jacarta2.signData(data, contId);
    }).then(sign => {
        inputSign.value = sign;
        alert('Success!');
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta2.unbind();
    });
}