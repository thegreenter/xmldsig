<?php

use Greenter\XMLSecLibs\Tool\PfxConverter;

require __DIR__.'/../vendor/autoload.php';

$pfx = file_get_contents(__DIR__.'/SFSCert.pfx');
$password = '123456';

$converter = new PfxConverter($pfx, $password);
$pem = $converter
    ->toPem()
    ->getResult();
//file_put_contents('my.pem', $pem);
