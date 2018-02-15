<?php

use Greenter\XMLSecLibs\Certificate\X509Certificate;
use Greenter\XMLSecLibs\Certificate\X509ContentType;

require __DIR__.'/../vendor/autoload.php';

$pfx = __DIR__.'/SFSCert.pfx';
$password = '123456';

try {
    $certificate = X509Certificate::createFromFile($pfx, $password);
    echo $certificate->getName();
    $pem = $certificate->export(X509ContentType::PEM);
    //file_put_contents('my.pem', $pem);
} catch (Exception $e) {
    echo $e->getMessage();
}
