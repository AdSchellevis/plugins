<?php
/**
*    Copyright (C) 2019 Deciso B.V.
*
*    All rights reserved.
*
*    Redistribution and use in source and binary forms, with or without
*    modification, are permitted provided that the following conditions are met:
*
*    1. Redistributions of source code must retain the above copyright notice,
*       this list of conditions and the following disclaimer.
*
*    2. Redistributions in binary form must reproduce the above copyright
*       notice, this list of conditions and the following disclaimer in the
*       documentation and/or other materials provided with the distribution.
*
*    THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
*    INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
*    AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
*    AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
*    OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
*    SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
*    INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
*    CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
*    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
*    POSSIBILITY OF SUCH DAMAGE.
*
*/
namespace OPNsense\pfSenseImport;

use \OPNsense\Core\Config;

abstract class ImportType
{
    private $configured_interfaces = array();
    private $configured_interface_groups = array();
    protected $sourceXml = null;
    protected $importErrors = array();
    protected $insertCount = 0;
    protected $updateCount = 0;
    protected $ifdetails = array();

    public function __construct($source)
    {
        if (file_exists($source)) {
            $this->sourceXml = simplexml_load_file($source);
        }
        if (!empty(Config::getInstance()->object()->interfaces)) {
            foreach (Config::getInstance()->object()->interfaces->children() as $ifname => $ifcnf) {
                $this->configured_interfaces[] = $ifname;
            }
        }
        if (!empty(Config::getInstance()->object()->ifgroups)) {
            foreach (Config::getInstance()->object()->ifgroups->children() as $ifcnf) {
                $this->configured_interface_groups[] = $ifcnf->ifname;
            }
        }
    }

    public function setInterfaceDetails($ifdetails)
    {
        $this->ifdetails = $ifdetails;
    }

    protected function replaceXmlNode(\SimpleXMLElement $source, \SimpleXMLElement $target)
    {
        $targetDom = dom_import_simplexml($target);
        $sourceDom  = dom_import_simplexml($source);
        $nodeImport  = $targetDom->ownerDocument->importNode($sourceDom, TRUE);
        $targetDom->parentNode->replaceChild($nodeImport, $targetDom);
    }

    protected function hasInterface($name)
    {
        return !empty($name) && in_array($name, $this->configured_interfaces);
    }

    protected function hasInterfaceGroup($name)
    {
        return !empty($name) && in_array($name, $this->configured_interface_groups);
    }

    protected function pconfigToString($adr)
    {
        $result = !empty($adr->not) ? "!" : "";
        if (isset($adr->any)) {
            $result .= "any";
        } else {
            if (!empty($adr->network)) {
                $result .= $adr->network;
            } elseif (!empty($adr->address)) {
                $result .= $adr->address;
            }
            if (!empty($adr->port)) {
                $result .= ":" . $adr->port;
            }
        }
        return $result;
    }

    public function import()
    {
        throw new \Exception("Unsupported type");
    }

    public function getReport()
    {
        return array(
            "inserted" => $this->insertCount,
            "updated" => $this->updateCount,
            "errors" => $this->importErrors,
        );
    }

    public function printReport()
    {
        echo "[".get_class($this)."]\n";
        echo "inserted : {$this->insertCount}\n";
        echo "updated : {$this->updateCount}\n";
        if (!empty($this->importErrors)) {
            echo "import errors (per identifier):\n";
            foreach ($this->importErrors as $error) {
                echo "\t{$error['name']} : {$error['message']}\n";
            }
        }
    }
}
