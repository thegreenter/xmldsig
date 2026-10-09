<?php

namespace Greenter\XMLSecLibs\Sunat;

use DOMDocument;
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
    const ENVELOPED = XMLSecurityDSig::ENVELOPED;
    const EXT_NS = 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2';

    /**
     * Supported signature algorithm URIs.
     *
     * @var array
     */
    protected static $signatureAlgorithms = [
        XMLSecurityKey::RSA_SHA1,
        XMLSecurityKey::RSA_SHA256,
    ];

    /**
     * Supported digest algorithm URIs.
     *
     * @var array
     */
    protected static $digestAlgorithms = [
        XMLSecurityDSig::SHA1,
        XMLSecurityDSig::SHA256,
    ];

    /**
     * Supported canonicalization algorithm URIs.
     *
     * @var array
     */
    protected static $canonicalMethods = [
        XMLSecurityDSig::C14N,
        XMLSecurityDSig::EXC_C14N,
    ];

    /**
     * Transforms accepted while verifying a signature.
     *
     * @var array
     */
    protected static $transforms = [
        XMLSecurityDSig::ENVELOPED,
        XMLSecurityDSig::C14N,
        XMLSecurityDSig::C14N_COMMENTS,
        XMLSecurityDSig::EXC_C14N,
        XMLSecurityDSig::EXC_C14N_COMMENTS,
    ];

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
     * Si se configuró un certificado (setCertificate/setCertificateFromFile) la firma
     * se verifica con ese certificado. Si no, se usa el certificado incluido en el
     * propio XML: en ese caso `true` sólo indica que el documento no fue alterado
     * después de firmarse, no quién lo firmó.
     *
     * @param string $content
     * @return bool
     */
    public function verifyXml($content)
    {
        $doc = $this->getDocXml($content);

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
     * Set the signature algorithm (SignatureMethod). By default RSA with SHA1.
     *
     * @param string $algorithm XMLSecurityKey::RSA_SHA1 or XMLSecurityKey::RSA_SHA256.
     *
     * @throws \InvalidArgumentException If the algorithm is not supported.
     */
    public function setSignatureAlgorithm($algorithm)
    {
        if (!in_array($algorithm, static::$signatureAlgorithms, true)) {
            throw new \InvalidArgumentException('Unsupported signature algorithm: '.$algorithm);
        }

        $this->keyAlgorithm = $algorithm;
    }

    /**
     * Set the digest algorithm (DigestMethod). By default SHA1.
     *
     * @param string $algorithm XMLSecurityDSig::SHA1 or XMLSecurityDSig::SHA256.
     *
     * @throws \InvalidArgumentException If the algorithm is not supported.
     */
    public function setDigestAlgorithm($algorithm)
    {
        if (!in_array($algorithm, static::$digestAlgorithms, true)) {
            throw new \InvalidArgumentException('Unsupported digest algorithm: '.$algorithm);
        }

        $this->digestAlgorithm = $algorithm;
    }

    /**
     * Set the canonicalization algorithm (CanonicalizationMethod). By default C14N.
     *
     * @param string $method XMLSecurityDSig::C14N or XMLSecurityDSig::EXC_C14N.
     *
     * @throws \InvalidArgumentException If the algorithm is not supported.
     */
    public function setCanonicalMethod($method)
    {
        if (!in_array($method, static::$canonicalMethods, true)) {
            throw new \InvalidArgumentException('Unsupported canonical method: '.$method);
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
     * Returns the configured certificate or, when $doc is given, the certificate
     * included in the signature of $doc (without changing the configured one).
     *
     * @param DOMDocument|null $doc
     * @return string|null
     */
    public function getPublicKey(?DOMDocument $doc = null)
    {
        if ($doc) {
            $objKey = $this->getKeyFromNode($doc);

            return $objKey ? $objKey->getX509Certificate() : null;
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
     * Verify the signature of the document.
     *
     * Uses the configured certificate when there is one, otherwise the certificate
     * included in the signature (integrity only, see verifyXml()).
     * Only the supported signature, digest and transform algorithms are accepted.
     *
     * @param DOMDocument $data
     * @return bool
     */
    public function verify(DOMDocument $data)
    {
        $objXMLSecDSig = $this->createVerifierXmlSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($data);
        if (!$objDSig) {
            throw new UnexpectedValueException('Signature DOM element not found.');
        }
        $objXMLSecDSig->canonicalizeSignedInfo();

        // Use the algorithm of the signature, not the one configured to sign.
        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey || !in_array($objKey->getAlgorithm(), static::$signatureAlgorithms, true)) {
            return false;
        }

        if ($this->publicKey) {
            $objKey->loadKey($this->publicKey);
        } else {
            XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);
            if (!$objKey->key) {
                throw new RuntimeException(
                    'There is no set either private key or public key for signature verification.'
                );
            }
        }

        try {
            // Check signature
            if (1 !== $objXMLSecDSig->verify($objKey)) {
                return false;
            }

            // Check references (data)
            $objXMLSecDSig->validateReference();
        } catch (\Exception $e) {
            return false;
        }

        return true;
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
     * Create the XMLSecurityDSig used to verify, restricted to the supported algorithms.
     *
     * @return XMLSecurityDSig
     */
    protected function createVerifierXmlSecurityDSig()
    {
        $objXMLSecDSig = $this->createXmlSecurityDSig();
        $objXMLSecDSig->allowedSignatureAlgorithms = static::$signatureAlgorithms;
        $objXMLSecDSig->allowedDigestAlgorithms = static::$digestAlgorithms;
        $objXMLSecDSig->allowedTransforms = static::$transforms;
        $objXMLSecDSig->allowXPathTransforms = false;

        return $objXMLSecDSig;
    }

    /**
     * Extract the key (and certificate) included in the signature of the document.
     *
     * @param DOMDocument $doc
     *
     * @return XMLSecurityKey|null
     * @throws \Exception
     */
    protected function getKeyFromNode(DOMDocument $doc)
    {
        $objXMLSecDSig = $this->createVerifierXmlSecurityDSig();
        $objDSig = $objXMLSecDSig->locateSignature($doc);
        if (!$objDSig) {
            return null;
        }

        $objKey = $objXMLSecDSig->locateKey();
        if (!$objKey || !in_array($objKey->getAlgorithm(), static::$signatureAlgorithms, true)) {
            return null;
        }

        XMLSecEnc::staticLocateKeyInfo($objKey, $objDSig);

        return $objKey;
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
     *
     * @throws \InvalidArgumentException If the content is not a valid XML document or has a DOCTYPE.
     */
    private function getDocXml($content)
    {
        if (!is_string($content) || trim($content) === '') {
            throw new \InvalidArgumentException('XML content is empty.');
        }

        $doc = new \DOMDocument();
        $previous = libxml_use_internal_errors(true);
        try {
            $loaded = $doc->loadXML($content, LIBXML_NONET);
            $error = libxml_get_last_error();
            libxml_clear_errors();
        } finally {
            libxml_use_internal_errors($previous);
        }

        if (!$loaded) {
            $message = $error ? trim($error->message) : 'unknown error';
            throw new \InvalidArgumentException('Invalid XML content: '.$message);
        }
        if ($doc->doctype !== null) {
            throw new \InvalidArgumentException('XML documents with DOCTYPE are not allowed.');
        }

        return $doc;
    }
}
