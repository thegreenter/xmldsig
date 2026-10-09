--TEST--
SignedXml: hardened parsing, algorithm allowlist and trusted certificate
--FILE--
<?php
require(dirname(__FILE__) . '/../vendor/autoload.php');
use Greenter\XMLSecLibs\Sunat\SignedXml;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;

$dir = dirname(__FILE__);
$trusted = file_get_contents($dir . '/mycert.pem');
$invoice = file_get_contents($dir . '/invoice.xml');

// Self-signed certificate that nobody trusts.
$key = openssl_pkey_new(array('private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA));
$x509 = openssl_csr_sign(openssl_csr_new(array('commonName' => 'Atacante'), $key), null, $key, 1);
openssl_pkey_export($key, $otherKey);
openssl_x509_export($x509, $otherCert);

$signer = new SignedXml();
$signer->setCertificate(file_get_contents($dir . '/privkey.pem') . $trusted);
$signed = $signer->signXml($invoice);

$attacker = new SignedXml();
$attacker->setCertificate($otherKey . $otherCert);
$forged = $attacker->signXml($invoice);

function check($label, $callback) {
    try {
        $result = var_export($callback(), true);
    } catch (Exception $e) {
        $result = get_class($e);
    }
    echo $label, ': ', $result, "\n";
}

check('signed', function () use ($signed) { return (new SignedXml())->verifyXml($signed); });
check('forged without trust', function () use ($forged) { return (new SignedXml())->verifyXml($forged); });
check('signed with trust', function () use ($signed, $trusted) {
    $v = new SignedXml();
    $v->setTrustedCertificate($trusted);
    return $v->verifyXml($signed);
});
check('forged with trust', function () use ($forged, $trusted) {
    $v = new SignedXml();
    $v->setTrustedCertificate($trusted);
    return $v->verifyXml($forged);
});
check('forged without embedded cert', function () use ($forged, $trusted) {
    $xml = preg_replace('#<ds:KeyInfo>.*</ds:KeyInfo>#s', '', $forged);
    $v = new SignedXml();
    $v->setTrustedCertificate($trusted);
    return $v->verifyXml($xml);
});
check('tampered', function () use ($signed) {
    return (new SignedXml())->verifyXml(str_replace('F001-1', 'F001-2', $signed));
});
check('hmac', function () use ($signed) {
    $xml = str_replace(XMLSecurityKey::RSA_SHA1, XMLSecurityKey::HMAC_SHA1, $signed);
    return (new SignedXml())->verifyXml($xml);
});
check('xpath transform', function () use ($signed) {
    $xml = str_replace(
        '</ds:Transforms>',
        '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116"><ds:XPath>1</ds:XPath></ds:Transform></ds:Transforms>',
        $signed
    );
    return (new SignedXml())->verifyXml($xml);
});
check('doctype', function () {
    return (new SignedXml())->verifyXml('<?xml version="1.0"?><!DOCTYPE a [<!ENTITY e "x">]><a>&e;</a>');
});
check('invalid xml', function () { return (new SignedXml())->verifyXml('<a>'); });
check('sha256', function () use ($dir, $invoice) {
    $s = new SignedXml();
    $s->setCertificate(file_get_contents($dir . '/privkey.pem') . file_get_contents($dir . '/mycert.pem'));
    $s->setKeyAlgorithm(XMLSecurityKey::RSA_SHA256);
    $s->setDigestAlgorithm(XMLSecurityDSig::SHA256);
    $xml = $s->signXml($invoice);
    return strpos($xml, XMLSecurityKey::RSA_SHA256) !== false && (new SignedXml())->verifyXml($xml);
});
check('unsupported algorithm', function () {
    (new SignedXml())->setKeyAlgorithm(XMLSecurityKey::HMAC_SHA1);
});
check('invalid trusted certificate', function () {
    (new SignedXml())->setTrustedCertificate('not a certificate');
});
?>
--EXPECT--
signed: true
forged without trust: true
signed with trust: true
forged with trust: false
forged without embedded cert: false
tampered: false
hmac: false
xpath transform: false
doctype: InvalidArgumentException
invalid xml: InvalidArgumentException
sha256: true
unsupported algorithm: InvalidArgumentException
invalid trusted certificate: InvalidArgumentException
