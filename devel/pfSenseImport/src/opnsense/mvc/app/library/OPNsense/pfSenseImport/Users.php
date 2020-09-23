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

class Users extends ImportType
{
    public function import()
    {
        Config::getInstance()->lock();
        $targetCfg = Config::getInstance()->object();
        if (!empty($this->sourceXml->system->user)) {
            $maxuid = (int)$targetCfg->system->nextuid;
            foreach ($this->sourceXml->system->user as $node) {
                $userEntry = null;
                foreach ($targetCfg->system->user as $dst_node) {
                    if ((string)$dst_node->uid === (string)$node->uid) {
                        $userEntry = $dst_node;
                    }
                }
                if ($userEntry === null) {
                    $userEntry = $targetCfg->system->addChild("user");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                if (isset($node->name) && $node->name == "admin") {
                    $node->name = "root";
                }
                if (!isset($node->{"bcrypt-hash"})) {
                    if ($node->name == "root") {
                        // XXX: not allowed to replace the root user when invalid.
                        $this->importErrors[] = array(
                          "name" => $node->name,
                          "details" => json_encode($node),
                          "message" => "invalid root/admin user, keeping default"
                        );
                        continue;
                    }
                    $node->disabled = 1;
                } else {
                    $node->password = (string)$node->{"bcrypt-hash"};
                    unset($node->{"bcrypt-hash"});
                }
                foreach ([
                    "webguicss",
                    "webguifixedmenu",
                    "webguihostnamemenu",
                    "customsettings",
                    "dashboardcolumns",
                    "interfacessort",
                    "dashboardavailablewidgetspanel",
                    "systemlogsfilterpanel",
                    "systemlogsmanagelogpanel",
                    "statusmonitoringsettingspanel",
                    "webguileftcolumnhyper",
                    "disablealiaspopupdetail",
                    "pagenamefirst"
                    ] as $unsupported) {
                    if (isset($node->$unsupported)) {
                        unset($node->$unsupported);
                    }
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
                $maxuid = max([$maxuid, (int)$node->uid + 1]);
                $this->replaceXmlNode($node, $userEntry);
            }
            $targetCfg->system->nextuid = (string)$maxuid;
        }
        Config::getInstance()->save();
    }
}
