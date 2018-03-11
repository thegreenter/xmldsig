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
    const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
    const EXT_NS = 'urn:oasis:names:specification:ubl:schema:xsd:CommonExtensionComponents-2';
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
        $objXMLSecDSig->canonicalizeSignedInfo();

        if (!$this->getPublicKey()) {
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
        $doc = new \DOMDocument();
        $doc->loadXML($content);

        return $doc;
    }
}
