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

class Intf extends ImportType
{
    public function import()
    {
        if (!empty($this->sourceXml->interfaces)) {
            Config::getInstance()->lock();
            $targetCfg = Config::getInstance()->object();
            $all_interfaces = array_keys($this->ifdetails);
            if (!empty($targetCfg->laggs) && !empty($targetCfg->laggs->lagg)) {
                foreach ($targetCfg->laggs->lagg as $targetLagg) {
                      $all_interfaces[] = (string)$targetLagg->laggif;
                }
            }
            if (!empty($targetCfg->vlans) && !empty($targetCfg->vlans->vlan)) {
                foreach ($targetCfg->vlans->vlan as $targetVlan) {
                      $all_interfaces[] = (string)$targetVlan->vlanif;
                }
            }

            foreach ($this->sourceXml->interfaces->children() as $srcName => $srcInterface) {
                // rename vlans
                $if = !empty($srcInterface->if) ? str_replace('.', '_vlan', (string)$srcInterface->if) : "?";
                if (!in_array($if, $all_interfaces)) {
                    $this->importErrors[] = array(
                        "name" => $srcName,
                        "details" => json_encode($srcInterface),
                        "message" => "Interface doesn't exist on this host \"{$if}\""
                      );
                    continue;
                }

                $interfaces = isset($targetCfg->interfaces) ? $targetCfg->interfaces : $targetCfg->addChild("interfaces");
                if (!isset($interfaces->$srcName)) {
                    $intfEntry = $interfaces->addChild($srcName);
                    $this->insertCount++;
                } else {
                    $intfEntry = $interfaces->$srcName;
                    $this->updateCount++;
                }
                $srcInterface->if = $if;
                $this->replaceXmlNode($srcInterface, $intfEntry);
            }
            Config::getInstance()->save();
        }
    }
}
