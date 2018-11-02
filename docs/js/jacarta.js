function showInfo(contId) {
    var jacarta = new window.RusCryptoJS.JaCarta;
    return jacarta.init().then(info => {
        console.log('Initialized', info);
        return jacarta.certificateInfo(contId);
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

    var jacarta = new window.RusCryptoJS.JaCarta;
    return jacarta.init().then(info => {
        console.log('Initialized', info);
        return jacarta.bind();
    }).then(_ => { 
        return jacarta.listCertificates();
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
        jacarta.unbind();
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
    var jacarta = new window.RusCryptoJS.JaCarta;
    var containerId;
    return jacarta.init().then(info => {
        console.log('Initialized', info);
        return jacarta.bind();
    }).then(_ => { 
        return jacarta.generateCSR(dn, inputDescr.value);
    }).then(result => {
        console.log('generateCSR', result);

        const csr = result.csr;
        inputCsr.value = csr;
        
        containerId = result.containerId;
        
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
        return jacarta.writeCertificate(cert, containerId);
    }).then(contId => {
        console.log('writeCertificate', contId);
        return jacarta.certificateInfo(contId);
    }).then(info => {
        console.log('Certificate info', info);
        alert('Success!');
        return loadCerts();
    }).catch(e => {
        alert('Failed! ' + e);
    }).then(() => {
        jacarta.unbind();
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