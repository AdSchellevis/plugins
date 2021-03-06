<?php
/**
*    Copyright (C) 2020 Deciso B.V.
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

class Groups extends ImportType
{
    public function import()
    {
        Config::getInstance()->lock();
        $targetCfg = Config::getInstance()->object();
        if (!empty($this->sourceXml->system->group)) {
            $maxgid = (int)$targetCfg->system->nextgid;
            foreach ($this->sourceXml->system->group as $node) {
                $groupEntry = null;
                foreach ($targetCfg->system->group as $dst_node) {
                    if ((string)$dst_node->gid === (string)$node->gid) {
                        $groupEntry = $dst_node;
                    }
                }
                if ($groupEntry === null) {
                    $groupEntry = $targetCfg->system->addChild("group");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                if (isset($node->priv)) {
                    $privs = array();
                    foreach ($node->priv as $priv) {
                        if ((string)$priv == "system-xmlrpc-ha-sync") {
                            $privs[] = "page-xmlrpclibrary";
                        } else {
                            $privs[] = (string)$priv;
                        }
                    }
                    unset($node->priv);
                    foreach ($privs as $priv) {
                        $node->addChild("priv", $priv);
                    }
                }
                $maxgid = max([$maxgid, (int)$node->gid + 1]);
                $this->replaceXmlNode($node, $groupEntry);
            }
            $targetCfg->system->nextgid = (string)$maxgid;
        }
        Config::getInstance()->save();
    }
}
