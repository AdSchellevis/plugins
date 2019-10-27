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

class Lagg extends ImportType
{
    public function import()
    {
        if (!empty($this->sourceXml->laggs) && !empty($this->sourceXml->laggs->lagg)) {
            Config::getInstance()->lock();
            $targetCfg = Config::getInstance()->object();
            foreach ($this->sourceXml->laggs->lagg as $srcLagg) {
                foreach (explode(",", $srcLagg->members->__toString()) as $member) {
                    if (empty($this->ifdetails[$member])) {
                        $this->importErrors[] = array(
                            "name" => $srcLagg->laggif->__toString(),
                            "details" => json_encode($srcLagg),
                            "message" => "Not all members exist on this host for \"{$srcLagg->laggif}\" ({$srcLagg->members})"
                          );
                        continue 2;
                    }
                }
                $laggs = isset($targetCfg->laggs) ? $targetCfg->laggs : $targetCfg->addChild("laggs");
                $laggEntry = null;
                foreach ($laggs->children() as $lagg) {
                    if ($srcLagg->laggif->__toString() == $lagg->laggif->__toString()) {
                        $laggEntry = $lagg;
                        break;
                    }
                }
                if ($laggEntry == null) {
                    $laggEntry = $laggs->addChild("lagg");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                $laggEntry->members = $srcLagg->members->__toString();
                $laggEntry->descr = $srcLagg->descr->__toString();
                $laggEntry->laggif = $srcLagg->laggif->__toString();
                $laggEntry->proto =  $srcLagg->proto->__toString();
            }
            Config::getInstance()->save();
        }
    }
}
