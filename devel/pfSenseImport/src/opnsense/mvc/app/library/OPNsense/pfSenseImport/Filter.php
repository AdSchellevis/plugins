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

class Filter extends ImportType
{

    public function import()
    {
        if (!empty($this->sourceXml->filter) && !empty($this->sourceXml->filter->rule)) {
            Config::getInstance()->lock();
            $target = Config::getInstance()->object();
            if (isset($target->filter->rule)) {
                unset($target->filter->rule);
            }
            foreach ($this->sourceXml->filter->rule as $srcRule) {
                $floatingIntf = null;
                if (!empty($srcRule->floating)) {
                    $floatingIntf = implode(",", $this->filterKnownInterfaces($srcRule->interface));
                }
                if (!$this->hasInterface($srcRule->interface) && !$this->hasInterfaceGroup($srcRule->interface)
                      && empty($floatingIntf) && !empty($srcRule->interface)) {
                    $this->importErrors[] = array(
                        "name" => !empty($srcRule->descr) ? (string)$srcRule->descr : "",
                        "details" => json_encode($srcRule),
                        "message" => "Interface not configured " . $srcRule->interface
                      );
                    continue;
                }
                // add / update rule
                $filter = isset($target->filter) ? $target->filter : $target->addChild("filter");
                $filterEntry = $filter->addChild("rule");
                $this->insertCount++;
                if (!empty($floatingIntf)) {
                    $srcRule->interface = $floatingIntf;
                }
                if (isset($srcRule->disabled)) {
                    $srcRule->disabled = "1";
                }
                if (isset($srcRule->log)) {
                    $srcRule->log = "1";
                }
                if (empty($srcRule->statetype)) {
                    $srcRule->statetype = "keep state";
                }
                // remove pfSense specific and empty attributes
                if (isset($srcRule->tracker)) {
                    unset($srcRule->tracker);
                }
                if (isset($srcRule->icmptype) && trim((string)$srcRule->icmptype) == "any") {
                    unset($srcRule->icmptype);
                }
                foreach (array_keys(iterator_to_array($srcRule->children())) as $tagname) {
                    if ($srcRule->$tagname == "") {
                        unset($srcRule->$tagname);
                    }
                }
                $this->replaceXmlNode($srcRule, $filterEntry);
            }
            Config::getInstance()->save();
        }
    }
}
