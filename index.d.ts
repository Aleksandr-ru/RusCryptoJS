export class DN {
    CN: string;
    [key: string]: string;
}

export interface IInitInfo {
    version: string;
    serialNumber?: string; // JaCarta2
    label?: string; // JaCarta2, RuToken
    type?: string; // JaCarta2, RuToken
    flags?: { [key: string]: boolean; }; // JaCarta2
    serial?: string; // RuToken
    reader?: string; // RuToken
    model?: string; // RuToken
}

export interface ICSR {
    csr: string;
    keyPairId?: number; // JaCarta2
    containerId?: string; // RuToken
}

export interface ICertificateInfo {
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
}

export interface ICertlistItem {
    id: string;
    name: string;
}

export interface ISignOptions {
    attached: boolean;
    pin?: string; // CryptoPro
    pin2?: string; // CryptoPro
}

export class CryptoPro {
    init(): Promise<IInitInfo>;
    bind(userPin?: string): Promise<boolean>;
    unbind(): Promise<boolean>;
    generateCSR(dn: DN, pin: string, ekuOids?: string[], providerType?: number): Promise<ICSR>;
    writeCertificate(certBase64: string): Promise<string>;
    certificateInfo(certThumbprint: string): Promise<ICertificateInfo>;
    listCertificates(): Promise<ICertlistItem[]>;
    readCertificate(certThumbprint: string): Promise<string>;
    signData(dataBase64: string, certThumbprint: string, options?: ISignOptions): Promise<string>;
    signData2(dataBase64: string, certThumbprint: string, certThumbprint2: string, options?: ISignOptions): Promise<string>;
    addSign(dataBase64: string, signBase64: string, certThumbprint: string, options: ISignOptions): Promise<string>;
    verifySign(dataBase64: string, signBase64: string, options?: ISignOptions): Promise<boolean>;
    encryptData(dataBase64: string, certThumbprint: string): Promise<string>;
    decryptData(dataBase64: string, certThumbprint: string, pin?: string): Promise<string>;
}

export class JaCarta2 {
    init(): Promise<IInitInfo>;
    bind(userPin?: string): Promise<void>;
    unbind(): Promise<void>;
    clean(): Promise<void>;
    generateCSR(dn: DN, description: string, ekuOids?: string[], algorithm?: string): Promise<ICSR>;
    writeCertificate(certificate: string, keyPairId: number): Promise<number>;
    certificateInfo(containerId: number): Promise<ICertificateInfo>;
    listCertificates(): Promise<ICertlistItem[]>;
    readCertificate(containerId: number): Promise<string>;
    signData(dataBase64: string, containerId: number, options?: ISignOptions): Promise<string>;
    verifySign(dataBase64: string, signBase64: string, options?: ISignOptions): Promise<boolean>;
    encryptData(dataBase64: string, containerId: number): Promise<string>;
    decryptData(dataBase64: string, containerId: number): Promise<string>;
}

export class RuToken {
    init(): Promise<IInitInfo>;
    bind(userPin?: string): Promise<boolean>;
    unbind(): Promise<boolean>;
    clean(): Promise<number>;
    generateCSR(dn: DN, marker: string, extKeyUsage?: string[], algorithm?: string): Promise<ICSR>;
    writeCertificate(certificate: string): Promise<string>;
    certificateInfo(certId: string): Promise<ICertificateInfo>;
    listCertificates(): Promise<ICertlistItem[]>;
    readCertificate(certId: string): Promise<string>;
    signData(dataBase64: string, certId: string, options?: ISignOptions): Promise<string>;
    addSign(dataBase64: string, signBase64: string, certId: string, options?: ISignOptions): Promise<string>;
    verifySign(dataBase64: string, signBase64: string, options?: ISignOptions): Promise<boolean>;
    encryptData(dataBase64: string, certId: string): Promise<string>;
    decryptData(dataBase64: string, certId: string): Promise<string>;
}
