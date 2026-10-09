<?php

namespace Greenter\XMLSecLibs\Sunat;

use DOMDocument;
use DOMElement;
use DOMXPath;
use InvalidArgumentException;
use Greenter\XMLSecLibs\XMLSecEnc;
use Greenter\XMLSecLibs\XMLSecurityDSig;
use Greenter\XMLSecLibs\XMLSecurityKey;
use RuntimeException;
use UnexpectedValueException;

/**
 * Class SignedXml
 */
class SignedXml
{
    /* Transform */
    const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
    const EXT_NS = 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2';

    /**
     * Algoritmos aceptados al verificar una firma.
     *
     * @var string[]
     */
    private static $allowedSignatureMethods = array(
        XMLSecurityKey::RSA_SHA1,
        XMLSecurityKey::RSA_SHA256,
        XMLSecurityKey::RSA_SHA384,
        XMLSecurityKey::RSA_SHA512,
    );
    /** @var string[] */
    private static $allowedDigestMethods = array(
        XMLSecurityDSig::SHA1,
        XMLSecurityDSig::SHA256,
        XMLSecurityDSig::SHA384,
        XMLSecurityDSig::SHA512,
    );
    /** @var string[] */
    private static $allowedCanonicalMethods = array(
        XMLSecurityDSig::C14N,
        XMLSecurityDSig::C14N_COMMENTS,
        XMLSecurityDSig::EXC_C14N,
        XMLSecurityDSig::EXC_C14N_COMMENTS,
    );
    /**
     * Private key.
     *
     * @var string
     */
    protected $privateKey;

    /**
     * Public key.
     *
     * @var string
     */
    protected $publicKey;

    /**
     * Signature algorithm URI. By default RSA with SHA1.
     *
     * @var string
     */
    protected $keyAlgorithm = XMLSecurityKey::RSA_SHA1;

    /**
     * Digest algorithm URI. By default SHA1.
     *
     * @var string
     *
     * @see AdapterInterface::SHA1
     */
    protected $digestAlgorithm = XMLSecurityDSig::SHA1;

    /**
     * Canonical algorithm URI. By default C14N.
     *
     * @var string
     *
     * @see AdapterInterface::XML_C14N
     */
    protected $canonicalMethod = XMLSecurityDSig::C14N;

    /**
     * Certificado de confianza (PEM). Si se establece, verify() sólo acepta firmas hechas con él.
     *
     * @var string|null
     */
    protected $trustedCertificate;


    /**
     * Firma el contenido del xml y retorna el contenido firmado.
     *
     * @param string $content
     * @return string
     */
    public function signXml($content)
    {
        $doc = $this->getDocXml($content);
        $this->sign($doc);

        return $doc->saveXML();
    }

    /**
     * Verifica la firma del xml.
     *
     * @param string $content
     * @return bool
     */
    public function verifyXml($content)
    {
        $doc = $this->getDocXml($content);
        $this->getPublicKey($doc);

        return $this->verify($doc);
    }

    /**
     * Set certificated in PEM format
     * @param string $cert
     */
    public function setCertificate($cert)
    {
        $this->privateKey = $cert;
        $this->publicKey = $cert;
    }

    /**
     * Establece el certificado (PEM) con el que deben estar firmados los XML al verificar.
     *
     * Sin un certificado de confianza, verify() usa el certificado incluido en el propio XML,
     * por lo que sólo comprueba la integridad del documento, no quién lo firmó.
     *
     * @param string $cert
     */
    public function setTrustedCertificate($cert)
    {
        $x509 = @openssl_x509_read($cert);
        if ($x509 === false || !openssl_x509_export($x509, $pem)) {
            throw new InvalidArgumentException('Invalid trusted certificate');
        }

        $this->trustedCertificate = $pem;
    }

    /**
     * Algoritmo de firma (ej. XMLSecurityKey::RSA_SHA256). Por defecto RSA-SHA1.
     *
     * @param string $algorithm
     */
    public function setKeyAlgorithm($algorithm)
    {
        if (!in_array($algorithm, self::$allowedSignatureMethods, true)) {
            throw new InvalidArgumentException('Unsupported signature algorithm');
        }

        $this->keyAlgorithm = $algorithm;
    }

    /**
     * Algoritmo de digest (ej. XMLSecurityDSig::SHA256). Por defecto SHA1.
     *
     * @param string $algorithm
     */
    public function setDigestAlgorithm($algorithm)
    {
        if (!in_array($algorithm, self::$allowedDigestMethods, true)) {
            throw new InvalidArgumentException('Unsupported digest algorithm');
        }

        $this->digestAlgorithm = $algorithm;
    }

    /**
     * Método de canonicalización. Por defecto C14N.
     *
     * @param string $method
     */
    public function setCanonicalMethod($method)
    {
        if (!in_array($method, self::$allowedCanonicalMethods, true)) {
            throw new InvalidArgumentException('Unsupported canonicalization method');
        }

        $this->canonicalMethod = $method;
    }

    /**
     * @param string $filename
     */
    public function setCertificateFromFile($filename)
    {
        if (!file_exists($filename)) {
            throw new \InvalidArgumentException('Certificate File not found');
        }

        $this->setCertificate(file_get_contents($filename));
    }

    /**
     * @inheritdoc
     */
    public function getPublicKey(DOMDocument $doc = null)
    {
        if ($doc) {
            $this->setPublicKeyFromNode($doc);
        }

        return $this->publicKey;
    }

    /**
     * @inheritdoc
     */
    public function sign(DOMDocument $data)
    {
        if (null === $this->privateKey) {
            throw new RuntimeException(
                'Missing private key. Use setPrivateKey to set one.'
            );
        }

        $objKey = new XMLSecurityKey(
            $this->keyAlgorithm,
            [
                 'type' => 'private',
            ]
        );
        $objKey->loadKey($this->privateKey);

        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objXMLSecDSig->setCanonicalMethod($this->canonicalMethod);
        $objXMLSecDSig->addReference($data, $this->digestAlgorithm, [self::ENVELOPED], ['force_uri' => true]);
        $objXMLSecDSig->sign($objKey, $this->getNodeSign($data));

        /* Add associated public key */
        if ($this->getPublicKey()) {
            $objXMLSecDSig->add509Cert($this->getPublicKey());
        }
    }

    /**
     * Sign from file.
     * @param string $filename
     * @return string
     */
    public function signFromFile($filename)
    {
        if (!file_exists($filename)) {
            throw new \InvalidArgumentException('File to sign, not found');
        }

        return $this->signXml(file_get_contents($filename));
    }

    /**
     * @inheritdoc
     */
    public function verify(DOMDocument $data)
    {
        $objKey = null;
        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($data);
        if (!$objDSig) {
            throw new UnexpectedValueException('Signature DOM element not found.');
        }
        if (!$this->hasAllowedAlgorithms($objDSig)) {
            return false;
        }
        $objXMLSecDSig->canonicalizeSignedInfo();

        if ($this->trustedCertificate !== null) {
            $objKey = $this->createTrustedKey($objXMLSecDSig, $objDSig);
            if (!$objKey) {
                return false;
            }
        } elseif (!$this->getPublicKey()) {
            // try to get the public key from the certificate
            $objKey = $objXMLSecDSig->locateKey();
            if (!$objKey) {
                throw new RuntimeException(
                    'There is no set either private key or public key for signature verification.'
                );
            }

            XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
            $this->publicKey = $objKey->getX509Certificate();
            $this->keyAlgorithm = $objKey->getAlgorithm();
        }

        if (!$objKey) {
            $objKey = new XMLSecurityKey(
                $this->keyAlgorithm,
                [
                     'type' => 'public',
                ]
            );
            $objKey->loadKey($this->getPublicKey());
        }

        // Check signature
        if (1 !== $objXMLSecDSig->verify($objKey)) {
            return false;
        }

        // Check references (data)
        try {
            $objXMLSecDSig->validateReference();
        } catch (\Exception $e) {
            return false;
        }

        return true;
    }

    /**
     * Comprueba que la firma sólo use algoritmos y transformaciones permitidos
     * (evita HMAC, DSA, RIPEMD-160, transformaciones XPath, etc.).
     *
     * @param DOMElement $signature
     * @return bool
     */
    protected function hasAllowedAlgorithms(DOMElement $signature)
    {
        $xpath = new DOMXPath($signature->ownerDocument);
        $xpath->registerNamespace('ds', XMLSecurityDSig::XMLDSIGNS);

        $checks = array(
            array('./ds:SignedInfo/ds:SignatureMethod', self::$allowedSignatureMethods),
            array('./ds:SignedInfo/ds:CanonicalizationMethod', self::$allowedCanonicalMethods),
            array('./ds:SignedInfo/ds:Reference/ds:DigestMethod', self::$allowedDigestMethods),
            array('./ds:SignedInfo/ds:Reference/ds:Transforms/ds:Transform',
                array_merge(array(self::ENVELOPED), self::$allowedCanonicalMethods)),
        );
        foreach ($checks as $check) {
            list($query, $allowed) = $check;
            foreach ($xpath->query($query, $signature) as $node) {
                /** @var DOMElement $node */
                if (!in_array($node->getAttribute('Algorithm'), $allowed, true)) {
                    return false;
                }
            }
        }

        return $xpath->query('./ds:SignedInfo/ds:SignatureMethod', $signature)->length === 1;
    }

    /**
     * Crea la clave de verificación a partir del certificado de confianza.
     * Devuelve null si el XML incluye un certificado distinto.
     *
     * @param XMLSecurityDSig $objXMLSecDSig
     * @param DOMElement $signature
     * @return XMLSecurityKey|null
     */
    private function createTrustedKey(XMLSecurityDSig $objXMLSecDSig, DOMElement $signature)
    {
        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            return null;
        }

        $embeddedKey = clone $objKey;
        XMLSecEnc::staticLocateKeyInfo($embeddedKey, $signature);
        $embedded = $embeddedKey->getX509Certificate();
        if ($embedded && self::fingerprint($this->trustedCertificate) !== self::fingerprint($embedded)) {
            return null;
        }

        $objKey->loadKey($this->trustedCertificate, false, true);

        return $objKey;
    }

    /**
     * Huella SHA-256 del certificado (DER).
     *
     * @param string $pem
     * @return string
     */
    private static function fingerprint($pem)
    {
        $der = base64_decode(preg_replace('/-----[^-]+-----|\s+/', '', $pem));

        return hash('sha256', $der);
    }

    /**
     * Create the XMLSecurityDSig class.
     *
     * @return XMLSecurityDSig
     */
    protected function createXmlSecurityDSig()
    {
        return new XMLSecurityDSig();
    }

    /**
     * Try to extract the public key from DOM node.
     *
     * Sets publicKey and keyAlgorithm properties if success.
     *
     * @see publicKey
     * @see keyAlgorithm
     *
     * @param DOMDocument $doc
     *
     * @return bool `true` If public key was extracted or `false` if cannot be possible
     * @throws \Exception
     */
    protected function setPublicKeyFromNode(DOMDocument $doc)
    {
        // try to get the public key from the certificate
        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($doc);
        if (!$objDSig) {
            return false;
        }

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey) {
            return false;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
        $this->publicKey = $objKey->getX509Certificate();
        $this->keyAlgorithm = $objKey->getAlgorithm();

        return true;
    }

    private function getNodeSign(DOMDocument $data)
    {
        $els = $data->getElementsByTagNameNS(
            self::EXT_NS,
            'ExtensionContent');

        $nodeSign = null;
        foreach ($els as $element) {
            /** @var \DOMElement $element*/
            $val = $element->nodeValue;
            if (strlen(trim($val)) === 0) {
                $nodeSign = $element;
                break;
            }
        }

        if ($nodeSign == null) {
            $nodeSign = $data->documentElement;
        }

        return $nodeSign;
    }

    /**
     * @param string $content
     * @return \DOMDocument
     */
    private function getDocXml($content)
    {
        $content = (string) $content;
        if (preg_match('/<!DOCTYPE/i', $content)) {
            throw new InvalidArgumentException('XML with DOCTYPE is not allowed');
        }

        $useErrors = libxml_use_internal_errors(true);
        $disableEntities = PHP_VERSION_ID < 80000 ? libxml_disable_entity_loader(true) : null;

        $doc = new DOMDocument();
        $loaded = $doc->loadXML($content, LIBXML_NONET);

        if ($disableEntities !== null) {
            libxml_disable_entity_loader($disableEntities);
        }
        $errors = libxml_get_errors();
        libxml_clear_errors();
        libxml_use_internal_errors($useErrors);

        if (!$loaded || $doc->doctype !== null) {
            $message = $errors ? trim($errors[0]->message) : 'Invalid XML';
            throw new InvalidArgumentException('Invalid XML content: '.$message);
        }

        return $doc;
    }
}
