<?php
/**
 * Created by PhpStorm.
 * User: Administrador
 * Date: 14/02/2018
 * Time: 04:39 PM
 */

namespace Greenter\XMLSecLibs\Tool;

/**
 * Class PfxConverter
 */
class PfxConverter
{
    /**
     * @var string
     */
    private $pfx;
    /**
     * @var string
     */
    private $password;

    /**
     * @var string
     */
    private $result;
    /**
     * @var string
     */
    private $error;

    /**
     * PfxConverter constructor.
     * @param string $pfx Pfx Content
     * @param string $password
     */
    public function __construct($pfx, $password)
    {
        $this->pfx = $pfx;
        $this->password = $password;
    }

    /**
     * @return $this
     */
    public function toPem()
    {
        $this->joinCerts(['pkey', 'cert']);

        return $this;
    }

    /**
     * @return $this
     */
    public function toCer()
    {
        $this->joinCerts(['cert']);

        return $this;
    }

    /**
     * Get Result of last operation
     *
     * @return string
     */
    public function getResult()
    {
        return $this->result;
    }

    /**
     * Get las error message
     *
     * @return string
     */
    public function getError()
    {
        return $this->error;
    }

    private function joinCerts(array $keys)
    {
        $certs = $this->getCerts();
        if (empty($certs)) {
            return;
        }

        $data = '';
        foreach ($keys as $key) {
            if (isset($certs[$key])) {
                $data .= $certs[$key];
            }
        }

        $this->result = $data;
    }

    /**
     * @return array
     */
    private function getCerts()
    {
        $success = openssl_pkcs12_read($this->pfx, $certs, $this->password);

        if ($success === false) {
            $this->error = openssl_error_string();
            return [];
        }

        return $certs;
    }
}