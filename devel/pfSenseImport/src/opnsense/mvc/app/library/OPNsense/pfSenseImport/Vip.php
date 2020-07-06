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

class Vip extends ImportType
{
    public function import()
    {
        if (!empty($this->sourceXml->virtualip) && !empty($this->sourceXml->virtualip->vip)) {
            Config::getInstance()->lock();
            foreach ($this->sourceXml->virtualip->vip as $srcVip) {
                $this_id = "[" . (!empty($srcVip->interface) ? $srcVip->interface : "?") . "]";
                $this_id .= !empty($srcVip->subnet) ? $srcVip->subnet : "?";
                $this_id .= "/" . (!empty($srcVip->subnet_bits) ? $srcVip->subnet_bits : "?");
                if (empty($srcVip->interface) || empty($srcVip->subnet) || empty($srcVip->subnet_bits)) {
                    $this->importErrors[] = array(
                        "name" => $this_id,
                        "details" => json_encode($srcVip),
                        "message" => "Incomplete subnet or missing interface"
                      );
                    continue;
                }
                if (!in_array($srcVip->mode, ['ipalias', 'carp', 'proxyarp', 'other'])) {
                    $this->importErrors[] = array(
                        "name" => $this_id,
                        "details" => json_encode($srcVip),
                        "message" => "Unknown mode \"{$srcVip->mode}\""
                      );
                    continue;
                }
                if (!Util::isSubnet($srcVip->subnet . "/" . $srcVip->subnet_bits)) {
                    $this->importErrors[] = array(
                        "name" => $this_id,
                        "details" => json_encode($srcVip),
                        "message" => "Invalid network"
                      );
                    continue;
                }
                if ($srcVip->mode == "carp") {
                    if (empty($srcVip->password) || empty($srcVip->vhid) || $srcVip->interface == 'lo0' ) {
                        $this->importErrors[] = array(
                            "name" => $this_id,
                            "details" => json_encode($srcVip),
                            "message" => "Incomplete or unsupported CARP VIP"
                          );
                        continue;
                    }
                }
                if (!$this->hasInterface($srcVip->interface) && $srcVip->interface != "lo0") {
                    $this->importErrors[] = array(
                        "name" => $this_id,
                        "details" => json_encode($srcVip),
                        "message" => "Interface not configured"
                      );
                    continue;
                }
                $target = Config::getInstance()->object();
                $virtualip = isset($target->virtualip) ? $target->virtualip : $target->addChild("virtualip");
                $vipEntry = null;
                foreach ($virtualip->children() as $vip) {
                    if ($srcVip->subnet->__toString() == $vip->subnet->__toString()
                            && $srcVip->subnet_bits->__toString() == $vip->subnet_bits->__toString()) {
                        $vipEntry = $vip;
                        break;
                    }
                }
                if ($vipEntry == null) {
                    $vipEntry = $virtualip->addChild("vip");
                    $this->insertCount++;
                } else {
                    $this->updateCount++;
                }
                // copy properties
                foreach (['mode', 'interface', 'vhid', 'advskew', 'advbase',
                          'password', 'descr', 'type', 'subnet_bits', 'subnet'] as $prop) {
                    if (isset($srcVip->$prop)) {
                        $vipEntry->$prop = $srcVip->$prop;
                    } elseif (isset($vipEntry->$prop)) {
                        $vipEntry->$prop = null;
                    }
                }
            }
            Config::getInstance()->save();
        }
    }
}
