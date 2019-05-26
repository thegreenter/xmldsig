--TEST--
Check export .pfx to .pem
--FILE--
<?php

use Greenter\XMLSecLibs\Certificate\X509Certificate;
use Greenter\XMLSecLibs\Certificate\X509ContentType;

require __DIR__.'/../vendor/autoload.php';

$pfx = __DIR__.'/SFSCert.pfx';
$password = '123456';

try {
    $certificate = X509Certificate::createFromFile($pfx, $password);
    $pem = $certificate->export(X509ContentType::PEM);
    echo "OK\n";
} catch (Exception $e) {
    echo $e->getMessage();
}

?>
--EXPECTF--
OK