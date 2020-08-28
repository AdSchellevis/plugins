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

class DNSMasq extends ImportType
{
    public function import()
    {
        Config::getInstance()->lock();
        $targetCfg = Config::getInstance()->object();
        if (!empty($this->sourceXml->dnsmasq)) {
            $dnsmasq_target = isset($targetCfg->dnsmasq) ? $targetCfg->dnsmasq : $targetCfg->addChild("dnsmasq");
            if (!empty($this->sourceXml->dnsmasq->hosts)){
                foreach ($this->sourceXml->dnsmasq->hosts as $host) {
                    $hostEntry = null;
                    foreach ($dnsmasq_target->hosts as $dst_host) {
                        if ((string)$dst_host->host == (string)$host->host
                              && (string)$dst_host->domain == (string)$host->domain) {
                            $hostEntry =  $dst_host;
                        }
                    }
                    if ($hostEntry == null) {
                        $hostEntry = $dnsmasq_target->addChild("host");
                        $this->insertCount++;
                    } else {
                        $this->updateCount++;
                    }
                    $this->replaceXmlNode($host, $hostEntry);
                }
            }

            if (!empty($this->sourceXml->dnsmasq->domainoverrides)){
                foreach ($this->sourceXml->dnsmasq->domainoverrides as $domainoverride) {
                    $domainEntry = null;
                    foreach ($dnsmasq_target->domainoverrides as $dst_do) {
                        if ((string)$dst_do->domain == (string)$domainoverride->domain) {
                            $domainEntry =  $dst_do;
                        }
                    }
                    if ($domainEntry == null) {
                        $domainEntry = $dnsmasq_target->addChild("domainoverrides");
                        $this->insertCount++;
                    } else {
                        $this->updateCount++;
                    }
                    $this->replaceXmlNode($domainoverride, $domainEntry);
                }
            }
        }
        Config::getInstance()->save();
    }
}
