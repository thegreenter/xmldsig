# XmlDSig - Greenter
[![Travis-CI](https://travis-ci.org/giansalex/xmldsig.svg?branch=master)](https://travis-ci.org/giansalex/xmldsig)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/cb56bff3cd1545f2841614448bf31da2)](https://www.codacy.com/app/giansalex/xmldsig?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=giansalex/xmldsig&amp;utm_campaign=Badge_Grade)  

Esta libreria se emplea para firmar comprobantes electrónicos según las normas de SUNAT.

Se requiere el certificado en formato .PEM, puede utilizar el siguiente ejemplo para [convertir el certificado .PFX al otros formatos](https://github.com/giansalex/xmldsig/blob/master/CONVERT.md).


## Instalar:

Empleando composer desde [packagist](https://packagist.org/packages/greenter/xmldsig).  

```bash
composer require greenter/xmldsig
```

## Ejemplo

```php

use Greenter\XMLSecLibs\Sunat\SignedXml;

require 'vendor/autoload.php';

$xmlPath = '20600995805-01-F001-1.xml';
$certPath = 'certifcate.pem'; // Antes convertir pfx -> pem (public+private key) 

$signer = new SignedXml();
$signer->setCertificateFromFile($certPath);

$xmlSigned = $signer->signFromFile($xmlPath);

file_put_contents("signed.xml", $xmlSigned);
```

**Resultado:**  

Antes:
```xml
<ext:UBLExtensions>
    <ext:UBLExtension>
        <ext:ExtensionContent></ext:ExtensionContent>
    </ext:UBLExtension>
</ext:UBLExtensions>
```

Despues:
```xml
<ext:UBLExtensions>
    <ext:UBLExtension>
        <ext:ExtensionContent>
            <ds:Signature Id="SignIMM">
                <ds:SignedInfo>
                    <ds:CanonicalizationMethod Algorithm="http://www.w3.org/TR/2001/REC-xml-c14n-20010315"/>
                    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
                    <ds:Reference URI="">
                    <ds:Transforms>
                        <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    </ds:Transforms>
                    <ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>
                    <ds:DigestValue>IwJuNQGQaHmmm3iv2jj8JDv70Ow=</ds:DigestValue>
                    </ds:Reference>
                </ds:SignedInfo>
                <ds:SignatureValue>
                nLaghokzMNrmrfPnbIg9b........wzZ2CgLTVjWQUAQ4wDAYDVQQIEwVNYWluZTE1UiLFwZXXXPUlf2o=
                </ds:SignatureValue>
                <ds:KeyInfo>
                    <ds:X509Data>
                        <ds:X509Certificate>
                        MIIFhzCCA3OgAwI......MIIEVDCCAzygAwIBAgIJAPTrkMJbCOr1MA0GCSqGSIb3DQEBBQUAMHkxCzAJBgNVBAYTAlVTVQQIEwVNYWluZTEgMOiRJ00nE=
                        </ds:X509Certificate>
                    </ds:X509Data>
                </ds:KeyInfo>
            </ds:Signature>
        </ext:ExtensionContent>
    </ext:UBLExtension>
</ext:UBLExtensions>
```
