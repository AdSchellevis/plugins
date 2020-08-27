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
use \OPNsense\Firewall\Util;

class Certificates extends ImportType
{
    public function import()
    {
        Config::getInstance()->lock();
        $targetCfg = Config::getInstance()->object();
        foreach (['cert', 'ca', 'crl'] as $cert_type) {
            if (!empty($this->sourceXml->$cert_type)) {
                foreach ($this->sourceXml->$cert_type as $node) {
                    if (!empty($targetCfg->$cert_type)) {
                        $certEntry = null;
                        foreach ($targetCfg->$cert_type as $dst_node) {
                            if ((string)$dst_node->refid === (string)$node->refid) {
                                $certEntry = $dst_node;
                            }
                        }
                        if ($certEntry === null) {
                            $certEntry = $targetCfg->addChild($cert_type);
                            $this->insertCount++;
                        } else {
                            $this->updateCount++;
                        }
                        foreach (array_keys(iterator_to_array($node->children())) as $tagname) {
                            /**
                             * since https://github.com/pfsense/pfsense/commit/7c4c77ee62cf28ced5043761ece287d29d498cd7
                             * pfSense seems to store the type of certificate, which doesn't have to reflect our reality
                             * it seems. "Server: No" when <type>server</type>
                             */
                            if ($node->$tagname == "" || in_array($tagname, ['type'])) {
                                unset($node->$tagname);
                            }
                        }
                        $this->replaceXmlNode($node, $certEntry);
                    }
                }
            }
        }
        Config::getInstance()->save();
    }
}
