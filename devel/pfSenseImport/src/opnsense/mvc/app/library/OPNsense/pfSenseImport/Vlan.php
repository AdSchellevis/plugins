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

class Vlan extends ImportType
{
    public function import()
    {
        if (!empty($this->sourceXml->vlans) && !empty($this->sourceXml->vlans->vlan)) {
            Config::getInstance()->lock();
            $targetCfg = Config::getInstance()->object();
            $laggs = array();
            if (!empty($targetCfg->laggs) && !empty($targetCfg->laggs->lagg)) {
                foreach ($targetCfg->laggs->lagg as $targetLagg) {
                      $laggs[(string)$targetLagg->laggif] = $targetLagg;
                }
            }
            foreach ($this->sourceXml->vlans->vlan as $srcVlan) {
                // convert interface naming ([dev].[id] vs [dev]_vlan[id])
                $vlanif = !empty($srcVlan->vlanif) ? str_replace('.', '_vlan', (string)$srcVlan->vlanif) : "?";
                $if = (string)$srcVlan->if;

                if (empty($this->ifdetails[$if]) && empty($laggs[$if])) {
                    $this->importErrors[] = array(
                        "name" => $vlanif,
                        "details" => json_encode($srcVlan),
                        "message" => "Interface doesn't exist on this host \"{$vlanif}\""
                      );
                    continue;
                }
                if (strlen($vlanif) > 16) {
                    $this->importErrors[] = array(
                        "name" => $vlanif,
                        "details" => json_encode($srcVlan),
                        "message" => "Interface name too long : \"{$vlanif}\""
                      );
                    continue;
                }
                $vlans = isset($targetCfg->vlans) ? $targetCfg->vlans : $targetCfg->addChild("vlans");
                $vlanEntry = null;
                foreach ($vlans->children() as $vlan) {
                    if ($vlanif == $vlan->vlanif->__toString()) {
                        $vlanEntry = $vlan;
                        break;
                    }
                }
                if ($vlanEntry == null) {
                    $vlanEntry = $vlans->addChild("vlan");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                $vlanEntry->if = $if;
                $vlanEntry->vlanif = $vlanif;
                $vlanEntry->tag = $srcVlan->tag;
                $vlanEntry->descr = isset($srcVlan->descr) ? (string)$srcVlan->descr : "";
                $vlanEntry->pcp = !empty($srcVlan->pcp) ? (string)$srcVlan->pcp : "0";
            }
            Config::getInstance()->save();
        }
    }
}
