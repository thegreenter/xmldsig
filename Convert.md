## Convertir Pfx a otros formatos

## Convert to .PEM
El archivo resultante se utiliza para firmar los comprobantes electrónicos.
```php
use Greenter\XMLSecLibs\Tool\PfxConverter;

require __DIR__.'/../vendor/autoload.php';

$pfx = file_get_contents('your-cert.pfx');
$password = 'YOUR-PASSWORD';

$converter = new PfxConverter($pfx, $password);
$pem = $converter
    ->toPem()
    ->getResult();
    
file_put_contents('certificate.pem', $pem);
```

### Convert a .CER
El archivo resultante se utiliza para subirlo a SUNAT.
```php
use Greenter\XMLSecLibs\Tool\PfxConverter;

require __DIR__.'/../vendor/autoload.php';

$pfx = file_get_contents('your-cert.pfx');
$password = 'YOUR-PASSWORD';

$converter = new PfxConverter($pfx, $password);
$pem = $converter
    ->toCer()
    ->getResult();
    
file_put_contents('certificate.cer', $pem);
```