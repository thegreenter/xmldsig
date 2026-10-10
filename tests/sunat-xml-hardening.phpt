--TEST--
Sunat SignedXml rejects invalid XML, DOCTYPE and algorithms outside the allowlist
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

require __DIR__.'/../vendor/autoload.php';

$certPath = __DIR__ . '/certificate.pem';
$xml = file_get_contents(__DIR__ . '/invoice.xml');

$signer = new SignedXml();
$signer->setCertificateFromFile($certPath);

foreach (['empty' => '', 'invalid' => '<Invoice>', 'doctype' => '<!DOCTYPE r [<!ENTITY e "x">]><r>&e;</r>'] as $label => $content) {
    try {
        $signer->signXml($content);
        echo $label, ": signed\n";
    } catch (InvalidArgumentException $e) {
        echo $label, ': ', strtok($e->getMessage(), ':'), "\n";
    }
}

// Exclusive canonicalization.
$signer->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
$signed = $signer->signXml($xml);
echo 'exc-c14n: ', var_export(strpos($signed, XMLSecurityDSig::EXC_C14N) !== false && $signer->verifyXml($signed), true), "\n";
try {
    $signer->setCanonicalMethod(XMLSecurityDSig::C14N_COMMENTS);
} catch (InvalidArgumentException $e) {
    echo $e->getMessage(), "\n";
}

// Signature and digest algorithms outside the allowlist are not accepted.
function lowLevelSign($xml, $signatureAlgorithm, $digestAlgorithm)
{
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::C14N);
    $dsig->addReference($doc, $digestAlgorithm, [XMLSecurityDSig::ENVELOPED], ['force_uri' => true]);
    $key = new XMLSecurityKey($signatureAlgorithm, ['type' => 'private']);
    $key->loadKey(__DIR__ . '/certificate.pem', true);
    $dsig->sign($key, $doc->documentElement);
    $dsig->add509Cert(file_get_contents(__DIR__ . '/certificate.pem'));

    return $doc->saveXML();
}

$verifier = new SignedXml();
echo 'rsa-sha256/sha256: ', var_export($verifier->verifyXml(lowLevelSign($xml, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::SHA256)), true), "\n";
echo 'rsa-sha512: ', var_export($verifier->verifyXml(lowLevelSign($xml, XMLSecurityKey::RSA_SHA512, XMLSecurityDSig::SHA256)), true), "\n";
echo 'ripemd160: ', var_export($verifier->verifyXml(lowLevelSign($xml, XMLSecurityKey::RSA_SHA256, XMLSecurityDSig::RIPEMD160)), true), "\n";

$hmac = str_replace(XMLSecurityKey::RSA_SHA1, XMLSecurityKey::HMAC_SHA1, lowLevelSign($xml, XMLSecurityKey::RSA_SHA1, XMLSecurityDSig::SHA1));
echo 'hmac-sha1: ', var_export($verifier->verifyXml($hmac), true), "\n";
$verifier->setCertificateFromFile($certPath);
echo 'hmac-sha1 configured cert: ', var_export($verifier->verifyXml($hmac), true), "\n";
?>
--EXPECT--
empty: XML content is empty.
invalid: Invalid XML content
doctype: XML documents with DOCTYPE are not allowed.
exc-c14n: true
Unsupported canonical method: http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments
rsa-sha256/sha256: true
rsa-sha512: false
ripemd160: false
hmac-sha1: false
hmac-sha1 configured cert: false
