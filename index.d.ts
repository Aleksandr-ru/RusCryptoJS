export class DN {
    CN: string;
    [key: string]: string;
}

export interface InitResultInterface {
    version: string;
    serialNumber?: string; // JaCarta2
    label?: string; // JaCarta2, RuToken
    type?: string; // JaCarta2, RuToken
    flags?: { [key: string]: boolean; }; // JaCarta2
    serial?: string; // RuToken
    reader?: string; // RuToken
    model?: string; // RuToken
}

export interface CSROptionsInterface {
    pin?: string; // CryptoPro
    providerType?: number; // CryptoPro
    algorithm?: string; // JaCarta2, RuToken
    description?: string; // JaCarta2
    marker?: string;  // RuToken
}

export interface CSRInterface {
    csr: string;
    keyPairId?: number | string; // JaCarta | RuToken
}

export interface CertificateInfoInterface {
    Name: string;
    Issuer: DN;
    IssuerName: string;
    Subject: DN;
    SubjectName: string;
    Version: string;
    SerialNumber: string;
    Thumbprint: string;
    ValidFromDate: Date;
    ValidToDate: Date;
    HasPrivateKey: boolean;
    IsValid: boolean;
    Algorithm: string;
    ProviderName?: string; // CryptoPro
    ProviderType?: string; // CryptoPro
}

export interface CertListItemInterface {
    id: string;
    name: string;
}

export interface SignOptionsInterface {
    attached: boolean;
    pin?: string; // CryptoPro
    pin2?: string; // CryptoPro
}

export class CryptoPro {
    init(): Promise<InitResultInterface>;
    bind(userPin?: string): Promise<boolean>;
    unbind(): Promise<boolean>;
    generateCSR(dn: DN, ekuOids?: string[], options?: CSROptionsInterface): Promise<CSRInterface>;
    writeCertificate(certBase64: string): Promise<string>;
    certificateInfo(certThumbprint: string): Promise<CertificateInfoInterface>;
    listCertificates(): Promise<CertListItemInterface[]>;
    readCertificate(certThumbprint: string): Promise<string>;
    signData(dataBase64: string, certThumbprint: string, options?: SignOptionsInterface): Promise<string>;
    signData2(dataBase64: string, certThumbprint: string, certThumbprint2: string, options?: SignOptionsInterface): Promise<string>;
    addSign(dataBase64: string, signBase64: string, certThumbprint: string, options: SignOptionsInterface): Promise<string>;
    verifySign(dataBase64: string, signBase64: string, options?: SignOptionsInterface): Promise<boolean>;
    encryptData(dataBase64: string, certThumbprint: string): Promise<string>;
    decryptData(dataBase64: string, certThumbprint: string, pin?: string): Promise<string>;
}

export class JaCarta2 {
    init(): Promise<InitResultInterface>;
    bind(userPin?: string): Promise<void>;
    unbind(): Promise<void>;
    clean(): Promise<void>;
    generateCSR(dn: DN, ekuOids?: string[], options?: CSROptionsInterface): Promise<CSRInterface>;
    writeCertificate(certificate: string, keyPairId: number): Promise<number>;
    certificateInfo(containerId: number): Promise<CertificateInfoInterface>;
    listCertificates(): Promise<CertListItemInterface[]>;
    readCertificate(containerId: number): Promise<string>;
    signData(dataBase64: string, containerId: number, options?: SignOptionsInterface): Promise<string>;
    verifySign(dataBase64: string, signBase64: string, options?: SignOptionsInterface): Promise<boolean>;
    encryptData(dataBase64: string, containerId: number): Promise<string>;
    decryptData(dataBase64: string, containerId: number): Promise<string>;
}

export class RuToken {
    init(): Promise<InitResultInterface>;
    bind(userPin?: string): Promise<boolean>;
    unbind(): Promise<boolean>;
    clean(): Promise<number>;
    generateCSR(dn: DN, extKeyUsage?: string[], options?: CSROptionsInterface): Promise<CSRInterface>;
    writeCertificate(certificate: string): Promise<string>;
    certificateInfo(certId: string): Promise<CertificateInfoInterface>;
    listCertificates(): Promise<CertListItemInterface[]>;
    readCertificate(certId: string): Promise<string>;
    signData(dataBase64: string, certId: string, options?: SignOptionsInterface): Promise<string>;
    addSign(dataBase64: string, signBase64: string, certId: string, options?: SignOptionsInterface): Promise<string>;
    verifySign(dataBase64: string, signBase64: string, options?: SignOptionsInterface): Promise<boolean>;
    encryptData(dataBase64: string, certId: string): Promise<string>;
    decryptData(dataBase64: string, certId: string): Promise<string>;
}
