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

class Alias
{
    private $sourceXml = null;
    private $importErrors = array();
    private $insertCount = 0;
    private $updateCount = 0;
    public function __construct($source)
    {
        if (file_exists($source)) {
            $this->sourceXml = simplexml_load_file($source);
        }
    }
    public function import()
    {
        $this->insertCount = 0;
        $this->updateCount = 0;
        $this->importErrors = array();
        $aliasImportMap = array();
        $aliasUuidMap = array();
        $aliasMdl = new \OPNsense\Firewall\Alias();
        if (!empty($this->sourceXml->aliases) && !empty($this->sourceXml->aliases->alias)) {
            Config::getInstance()->lock();
            foreach ($this->sourceXml->aliases->alias as $srcAlias) {
                if (empty($srcAlias->name)) {
                    $this->importErrors[] = array(
                        "name" => null,
                        "details" => json_encode($srcAlias),
                        "message" => "missing alias name"
                      );
                    continue;
                } elseif (!empty($aliasImportMap[(string)$srcAlias->name])) {
                    $this->importErrors[] = array(
                        "name" => (string)$srcAlias->name,
                        "details" => json_encode($srcAlias),
                        "message" => "duplicate alias name"
                    );
                    continue;
                } elseif ($alias=$aliasMdl->getByName((string)$srcAlias->name)) {
                    $aliasImportMap[(string)$srcAlias->name] = $alias;
                    $this->updateCount++;
                } else {
                    $alias = $aliasMdl->aliases->alias->Add();
                    $aliasImportMap[(string)$srcAlias->name] = $alias;
                    $this->insertCount++;
                }
                // update target object
                $alias->name = (string)$srcAlias->name;
                $alias->type = (string)$srcAlias->type;
                if ($srcAlias->url) {
                    // url content only contains a single item
                    $alias->content = (string)$srcAlias->url;
                } elseif ($srcAlias->aliasurl) {
                    // aliasurl in legacy config could consist of multiple <aliasurl> entries
                    $content = array();
                    foreach ($srcAlias->aliasurl as $url) {
                        $content[] = (string)$url;
                    }
                    $alias->content = implode("\n", $content);
                } elseif ($srcAlias->address) {
                    // address entries
                    $alias->content = str_replace(" ", "\n", trim((string)$srcAlias->address));
                }
                if ($srcAlias->proto) {
                    $alias->proto = (string)$srcAlias->proto;
                }
                if ($srcAlias->updatefreq) {
                    $alias->updatefreq = (string)$srcAlias->updatefreq;
                }
                $aliasUuidMap[$alias->getAttribute('uuid')] = (string)$srcAlias->name;
            }
            \OPNsense\Firewall\Util::attachAliasObject($aliasMdl);
            foreach ($aliasMdl->performValidation() as $msg) {
                $parts = explode('.', $msg->getField());
                $uuid = $parts[count($parts)-2];
                $this->importErrors[] = array(
                    "uuid" => $uuid,
                    "name" => $aliasUuidMap[$uuid],
                    "details" => null,
                    "message" => $msg->getMessage()
                );
            }
            // remove invalid entries from set
            foreach ($this->importErrors as $error) {
                if (!empty($error['uuid'])) {
                    $aliasMdl->aliases->alias->del($error['uuid']);
                }
            }
            $aliasMdl->serializeToConfig();
            Config::getInstance()->save();
        }
    }

    public function getReport()
    {
        return array(
            "inserted" => $this->insertCount,
            "updated" => $this->updateCount,
            "errors" => $this->importErrors,
        );
    }
}
