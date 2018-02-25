<?php
/**
 * Created by PhpStorm.
 * User: Administrador
 * Date: 02/08/2017
 * Time: 10:23 AM
 */

use Greenter\XMLSecLibs\Sunat\SignedXml;

require '../vendor/autoload.php';

$xmlPath = __DIR__ . '/invoice.xml';
$certPath = __DIR__ . '/certificate.pem'; // Convertir pfx to pem

$xmlDocument = new DOMDocument();
$xmlDocument->load($xmlPath);

$xmlTool = new SignedXml();
$xmlTool->setCertificateFromFile($certPath);

$xmlTool->sign($xmlDocument);

$content = $xmlDocument->saveXML();

$xmlTool->verify($xmlDocument);

header('Content-Type: text/xml');
echo $content;
