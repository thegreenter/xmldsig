<?php

require __DIR__.'/../vendor/autoload.php';

try {
    $signed = new \Greenter\XMLSecLibs\Sunat\SignedXml();
    $result = $signed->verifyXml(file_get_contents(__DIR__.'/invoce.xml'));

    var_dump($result);
} catch (Exception $e) {
    echo $e->getMessage();
}
