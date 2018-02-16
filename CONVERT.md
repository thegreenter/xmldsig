## Convertir Pfx a otros formatos

## Convert to .PEM
El archivo resultante se utiliza para firmar los comprobantes electrónicos.
```php
use Greenter\XMLSecLibs\Certificate\X509Certificate;
use Greenter\XMLSecLibs\Certificate\X509ContentType;

require 'vendor/autoload.php';

$pfx = file_get_contents('your-cert.pfx');
$password = 'YOUR-PASSWORD';

$certificate = new X509Certificate($pfx, $password);
$pem = $certificate->export(X509ContentType::PEM);
    
file_put_contents('certificate.pem', $pem);
```

### Convert a .CER
El archivo resultante se utiliza para subirlo a SUNAT.
```php
use Greenter\XMLSecLibs\Certificate\X509Certificate;
use Greenter\XMLSecLibs\Certificate\X509ContentType;

require 'vendor/autoload.php';

$pfx = file_get_contents('your-cert.pfx');
$password = 'YOUR-PASSWORD';

$certificate = new X509Certificate($pfx, $password);
$cer = $certificate->export(X509ContentType::CER);
    
file_put_contents('certificate.cer', $cer);
```
