--TEST--
Reference and algorithm hardening during verification
--FILE--
<?php
require(dirname(__FILE__) . '/../xmlseclibs.php');
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;
use Greenter\XMLSecLibs\XMLSecEnc;

function signDoc($xml, $transforms, $uriNode = false, $digest = XMLSecurityDSig::SHA256)
{
    $doc = new DOMDocument();
    $doc->loadXML($xml);
    $dsig = new XMLSecurityDSig();
    $dsig->setCanonicalMethod(XMLSecurityDSig::EXC_C14N);
    $node = $uriNode ? $doc->getElementsByTagName('Data')->item(0) : $doc;
    $dsig->addReference($node, $digest, $transforms, ['overwrite' => false, 'force_uri' => true]);
    $key = new XMLSecurityKey(XMLSecurityKey::RSA_SHA256, ['type' => 'private']);
    $key->loadKey(dirname(__FILE__) . '/privkey.pem', true);
    $dsig->sign($key, $doc->documentElement);
    $dsig->add509Cert(file_get_contents(dirname(__FILE__) . '/mycert.pem'));

    return $doc->saveXML();
}

function check($label, $xml, ?callable $configure = null, ?callable $keyFactory = null)
{
    try {
        $doc = new DOMDocument();
        $doc->loadXML($xml);
        $dsig = new XMLSecurityDSig();
        if ($configure) {
            $configure($dsig);
        }
        $sig = $dsig->locateSignature($doc);
        $dsig->canonicalizeSignedInfo();
        $key = $keyFactory ? $keyFactory($dsig) : $dsig->locateKey();
        XMLSecEnc::staticLocateKeyInfo($key, $sig);
        $result = $dsig->verify($key);
        $dsig->validateReference();
        echo $label, ': ', var_export($result, true), "\n";
    } catch (Exception $e) {
        echo $label, ': ', $e->getMessage(), "\n";
    }
}

$enveloped = [XMLSecurityDSig::ENVELOPED, XMLSecurityDSig::EXC_C14N];

// Valid reference by Id.
$byId = signDoc('<Root><Data Id="a">signed</Data></Root>', $enveloped, true);
check('by id', $byId);

// Duplicate Id (signature wrapping).
$wrapped = str_replace('<Root>', '<Root><Data Id="a">evil</Data>', $byId);
check('duplicate id', $wrapped);

// Unresolved Id.
check('missing id', str_replace('Id="a"', 'Id="b"', $byId));

// External reference.
$external = str_replace('URI="#a"', 'URI="http://example.com/doc.xml#a"', $byId);
check('external uri', $external);

// XPath transform is rejected during verification unless enabled.
$xpath = signDoc(
    '<Root><Data>signed</Data></Root>',
    [XMLSecurityDSig::ENVELOPED, [XMLSecurityDSig::XPATH => ['query' => 'self::Data or ancestor::Data']]]
);
check('xpath transform', $xpath);
check('xpath transform allowed', $xpath, function ($dsig) {
    $dsig->allowXPathTransforms = true;
});

// Unknown transform.
$unknown = str_replace(
    XMLSecurityDSig::EXC_C14N . '"/></ds:Transforms>',
    XMLSecurityDSig::EXC_C14N . '"/><ds:Transform Algorithm="urn:unknown"/></ds:Transforms>',
    signDoc('<Root><Data>signed</Data></Root>', $enveloped)
);
check('unknown transform', $unknown);

// Algorithm allowlists.
$sha512 = signDoc('<Root><Data>signed</Data></Root>', $enveloped, false, XMLSecurityDSig::SHA512);
check('digest allowed', $sha512);
check('digest not allowed', $sha512, function ($dsig) {
    $dsig->allowedDigestAlgorithms = [XMLSecurityDSig::SHA256];
});
check('signature not allowed', $sha512, function ($dsig) {
    $dsig->allowedSignatureAlgorithms = [XMLSecurityKey::RSA_SHA1];
});

// The key must match the SignatureMethod of the document.
check('key mismatch', $sha512, null, function () {
    return new XMLSecurityKey(XMLSecurityKey::RSA_SHA1, ['type' => 'public']);
});

// HMAC with the public certificate as secret (algorithm confusion).
$doc = new DOMDocument();
$doc->loadXML($sha512);
$xp = new DOMXPath($doc);
$xp->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);
$xp->query('//ds:SignatureMethod')->item(0)->setAttribute('Algorithm', XMLSecurityKey::HMAC_SHA1);
$signedInfo = $xp->query('//ds:SignedInfo')->item(0)->C14N(true, false);
$cert = file_get_contents(dirname(__FILE__) . '/mycert.pem');
$xp->query('//ds:SignatureValue')->item(0)->nodeValue = base64_encode(hash_hmac('sha1', $signedInfo, $cert, true));
check('hmac with certificate', $doc->saveXML());

// DOCTYPE is rejected.
check('doctype', str_replace('<Root>', '<!DOCTYPE Root [<!ENTITY e "a">]><Root>', $byId));
?>
--EXPECT--
by id: 1
duplicate id: Reference URI identifies multiple nodes
missing id: Reference URI does not identify a node
external uri: Reference URI must be a same-document reference
xpath transform: XPath Transforms are not allowed during verification
xpath transform allowed: 1
unknown transform: Unsupported Transform algorithm: 'urn:unknown'
digest allowed: 1
digest not allowed: DigestMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmlenc#sha512'
signature not allowed: SignatureMethod algorithm is not allowed: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
key mismatch: SignatureMethod algorithm does not match the supplied key type
hmac with certificate: Asymmetric key material cannot be used as an HMAC key
doctype: A DOCTYPE is not allowed in a document being verified
