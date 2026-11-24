--TEST--
Sunat SignedXml verifies with the configured certificate instead of the embedded one
--FILE--
<?php

use Greenter\XMLSecLibs\Sunat\SignedXml;

require __DIR__.'/../vendor/autoload.php';

$trustedCert = file_get_contents(__DIR__ . '/certificate.pem');
$xml = file_get_contents(__DIR__ . '/invoice.xml');

// Self-signed certificate of an attacker.
$key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
$csr = openssl_csr_new(['commonName' => 'Atacante'], $key, ['digest_alg' => 'sha256']);
$x509 = openssl_csr_sign($csr, null, $key, 1, ['digest_alg' => 'sha256']);
openssl_pkey_export($key, $attackerKey);
openssl_x509_export($x509, $attackerCert);

$attacker = new SignedXml();
$attacker->setCertificate($attackerKey . $attackerCert);
$forged = $attacker->signXml($xml);

$signer = new SignedXml();
$signer->setCertificate($trustedCert);
$genuine = $signer->signXml($xml);

// Without a configured certificate only the integrity is checked.
$verifier = new SignedXml();
echo 'embedded cert, forged: ', var_export($verifier->verifyXml($forged), true), "\n";
echo 'configured cert unchanged: ', var_export($verifier->getPublicKey(), true), "\n";

// With a configured certificate the signer must match.
$verifier = new SignedXml();
$verifier->setCertificate($trustedCert);
echo 'trusted cert, forged: ', var_export($verifier->verifyXml($forged), true), "\n";
echo 'trusted cert, genuine: ', var_export($verifier->verifyXml($genuine), true), "\n";

// getPublicKey($doc) returns the embedded certificate without replacing the configured one.
$doc = new DOMDocument();
$doc->loadXML($forged);
$embedded = $verifier->getPublicKey($doc);
echo 'embedded is attacker: ', var_export(
    openssl_x509_fingerprint($embedded, 'sha256') === openssl_x509_fingerprint($attackerCert, 'sha256'),
    true
), "\n";
echo 'configured kept: ', var_export($verifier->getPublicKey() === $trustedCert, true), "\n";

// Tampered document.
$tampered = str_replace('<cbc:ID>2005</cbc:ID>', '<cbc:ID>2006</cbc:ID>', $genuine);
echo 'tampered: ', var_export($tampered !== $genuine && !$verifier->verifyXml($tampered), true), "\n";
?>
--EXPECT--
embedded cert, forged: true
configured cert unchanged: NULL
trusted cert, forged: false
trusted cert, genuine: true
embedded is attacker: true
configured kept: true
tampered: true
