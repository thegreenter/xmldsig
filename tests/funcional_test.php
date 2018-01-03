<?php
/**
 * Created by PhpStorm.
 * User: Administrador
 * Date: 02/08/2017
 * Time: 10:23 AM
 */

use Greenter\XMLSecLibs\Sunat\SunatXmlSecAdapter;

require '../vendor/autoload.php';

$xmlPath = __DIR__ . '/invoice.xml';
$certPath = __DIR__ . '/privkey.pem'; // Convertir pfx to pem
$pcertPath = __DIR__ . '/mycert.pem';

$doc = new DOMDocument();

$xmlDocument = new DOMDocument();
$xmlDocument->load($xmlPath);

$xmlTool = new SunatXmlSecAdapter();
$xmlTool->setPrivateKey(file_get_contents($certPath));
$xmlTool->setPublicKey(file_get_contents($pcertPath));

$xmlTool->sign($xmlDocument);


$content = $xmlDocument->saveXML();

$pKey = $xmlTool->getPublicKey($doc);
if ($pKey != file_get_contents($pcertPath)) {
    echo "Erro in Cert Key";
    die();
}

header('Content-Type: text/xml');
echo $content;
