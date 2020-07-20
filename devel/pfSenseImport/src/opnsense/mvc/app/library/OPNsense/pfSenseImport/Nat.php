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

class Nat extends ImportType
{

    public function import()
    {
        if (!empty($this->sourceXml->nat) && !empty($this->sourceXml->nat->rule)) {
            Config::getInstance()->lock();
            $target = Config::getInstance()->object();
            if (isset($target->nat->rule)) {
                unset($target->nat->rule);
            }
            foreach ($this->sourceXml->nat->rule as $srcRule) {
                if (!$this->hasInterface($srcRule->interface) && !$this->hasInterfaceGroup($srcRule->interface)) {
                    $this->importErrors[] = array(
                        "name" => !empty($srcRule->descr) ? (string)$srcRule->descr : "",
                        "details" => json_encode($srcRule),
                        "message" => "Interface not configured " . $srcRule->interface
                      );
                    continue;
                }
                // add / update rule
                $nat = isset($target->nat) ? $target->nat : $target->addChild("nat");
                $natEntry = $nat->addChild("rule");
                $this->insertCount++;
                $this->replaceXmlNode($srcRule, $natEntry);
            }
            Config::getInstance()->save();
        }
    }
}
