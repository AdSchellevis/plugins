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

class Ifgroup extends ImportType
{
    public function import()
    {
        if (!empty($this->sourceXml->ifgroups) && !empty($this->sourceXml->ifgroups->ifgroupentry)) {
            Config::getInstance()->lock();
            $targetCfg = Config::getInstance()->object();
            foreach ($this->sourceXml->ifgroups->ifgroupentry as $srcGroup) {
                $members = explode(' ', $srcGroup->members);
                foreach ($members as $member) {
                    if (!$this->hasInterface($member)) {
                        $this->importErrors[] = array(
                            "name" => $srcGroup->ifname->__toString(),
                            "details" => json_encode($srcGroup),
                            "message" => "Not all members exist on this host for \"{$srcGroup->ifname}\" ({$srcGroup->members})"
                          );
                        continue 2;
                    }
                }
                if (strlen($srcGroup->ifname) > 16) {
                    $this->importErrors[] = array(
                        "name" => $srcGroup->ifname,
                        "details" => json_encode($srcGroup),
                        "message" => "Interface group name too long : \"{$srcGroup->ifname}\""
                      );
                    continue;
                }
                $ifgroups = isset($targetCfg->ifgroups) ? $targetCfg->ifgroups : $targetCfg->addChild("ifgroups");
                $ifgroupEntry = null;
                foreach ($ifgroups->children() as $ifgroup) {
                    if ($srcGroup->ifname == $ifgroup->ifname->__toString()) {
                        $ifgroupEntry = $ifgroup;
                        break;
                    }
                }
                if ($ifgroupEntry == null) {
                    $ifgroupEntry = $ifgroups->addChild("ifgroupentry");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                $ifgroupEntry->ifname =  $srcGroup->ifname;
                $ifgroupEntry->members =  $srcGroup->members;
                $ifgroupEntry->descr =  $srcGroup->descr;
            }
            Config::getInstance()->save();
        }
    }
}
