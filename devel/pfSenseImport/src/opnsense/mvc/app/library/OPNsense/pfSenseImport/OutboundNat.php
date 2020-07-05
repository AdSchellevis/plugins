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

class OutboundNat extends ImportType
{
    private function genRuleId($rule)
    {
        $result = (!empty($rule->interface) ? $rule->interface : "?") . "|";
        $result .= (!empty($rule->protocol) ? $rule->protocol : "?") . "|";
        $result .= (!empty($rule->ipprotocol) ? $rule->ipprotocol : "inet") . "|";
        $result .= !empty($rule->source) ? $this->pconfigToString($rule->source) : "?";
        $result .= !empty($rule->sourceport) ? ":" . $rule->sourceport : ":?";
        $result .= "->";
        $result .= !empty($rule->destination) ? $this->pconfigToString($rule->destination) : "?";
        $result .= !empty($rule->dstport) ? ":" . $rule->dstport : ":?";
        return $result;
    }

    public function import()
    {
        if (!empty($this->sourceXml->nat) && !empty($this->sourceXml->nat->outbound)
              && !empty($this->sourceXml->nat->outbound->rule)) {
            Config::getInstance()->lock();
            $target = Config::getInstance()->object();
            $nat = isset($target->nat) ? $target->nat : $target->addChild("nat");
            $outbound = isset($target->nat->outbound) ? $target->nat->outbound : $target->nat->addChild("outbound");
            $outbound->mode = $this->sourceXml->nat->outbound->mode;
            foreach ($this->sourceXml->nat->outbound->rule as $srcRule) {
                $this_id = $this->genRuleId($srcRule);
                if (!$this->hasInterface($srcRule->interface) && !$this->hasInterfaceGroup($srcRule->interface)) {
                    $this->importErrors[] = array(
                        "name" => $this_id,
                        "details" => json_encode($srcRule),
                        "message" => "Interface not configured"
                      );
                    continue;
                }
                // add / update rule
                $natEntry = null;
                foreach ($outbound->children() as $rule) {
                    if ($this->genRuleId($rule) == $this_id) {
                        $natEntry = $rule;
                        break;
                    }
                }
                if ($natEntry == null) {
                    $natEntry = $outbound->addChild("rule");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                if (isset($srcRule->nonat)) {
                    $srcRule->nonat = "1";
                }
                $this->replaceXmlNode($srcRule, $natEntry);
            }
            Config::getInstance()->save();
        }
    }
}
