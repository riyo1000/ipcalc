<#
    .SYNOPSIS
    ipcalc PowerShell版

    .DESCRIPTION
    LinuxのipcalcコマンドのPowerShell実装。

    .INPUTS
    Args[0]: CIDRアドレスまたはIPアドレス
    Args[1]: サブネットマスク (CIDRアドレス指定の場合は無し)

    .OUTPUTS
    Address: IPアドレス(入力値)
    Netmask: サブネットマスク(入力値/算出)
    Wildcard: ワイルドカードマスク(算出)
    CIDR: CIDR(入力値/算出)
    Network: ネットワークアドレス(算出)
    HostMin: 若番で最初のホストアドレス(算出)
    HostMax: 老番で最初のホストアドレス(算出)
    Broadcast: ブロードキャストアドレス(算出)
    Hosts/Net: 総ホスト数(算出)
    Class: IPアドレスクラス(算出)

    .EXAMPLE
    powershell -ExclutionPolicy Bypass ipcalc.ps1 192.168.0.1/24
    powershell -ExclutionPolicy Bypass ipcalc.ps1 192.168.0.1 255.255.255.0
#>

class CalcIP {
    $Class = @(
        @{"Min" = "0.0.0.0";   "Max" = "127.255.255.255"; "Info" = "Class A"},
        @{"Min" = "128.0.0.0"; "Max" = "191.255.255.255"; "Info" = "Class B"},
        @{"Min" = "192.0.0.0"; "Max" = "223.255.255.255"; "Info" = "Class C, Private Internet"},
        @{"Min" = "224.0.0.0"; "Max" = "239.255.255.255"; "Info" = "Class D, Multicast"},
        @{"Min" = "240.0.0.0"; "Max" = "255.255.255.255"; "Info" = "Class E, Reserved"}
    )
    $IP = @{
        "Address" =   [string]"0.0.0.0"
        "Netmask" =   [string]"0.0.0.0"
        "Cidr" =      [int]0
        "Network" =   [string]"0.0.0.0"
        "Broadcast" = [string]"255.255.255.255"
        "Wildcard" =  [string]"0.0.0.0"
        "HostMin" =   [string]"0.0.0.1"
        "HostMax" =   [string]"255.255.255.254" 
    }
    $DecIP = @{
        "Address" =   [uInt32]0
        "Netmask" =   [uInt32]0
        "Network" =   [uInt32]0
        "Broadcast" = [uInt32]4294967295
        "Wildcard" =  [uInt32]0
        "HostMin" =   [uInt32]1
        "HostMax" =   [uInt32]4294967294
    }
    
    CalcIP($addr, $snt="") {
        <#
            .SYNOPSIS
            初期化

            .INPUTS
            addr: IPアドレス / CIDRアドレス
            snt: サブネットマスク(CIDRアドレス入力時は不要)
        #>
        
        # CIDR表記
        if($this.CheckAddress($addr, "CIDR") -And ![bool]$snt) {
            $tmp = $addr -split "/"
            $this.IP["Address"] = $tmp[0]
            $this.IP["Cidr"] = [int]$tmp[1]
            $this.IP["Netmask"] = $this.ToSubnet($this.IP["Cidr"])
        }
        # サブネットマスク表記
        elseif($this.CheckAddress($addr, "ADDR") -And $this.CheckAddress($snt, "ADDR")) {
            $this.IP["Address"] = $addr
            $this.IP["Netmask"] = $snt
            $this.IP["Cidr"] = $this.ToCidr($snt)
        }
        # エラー
        else {
            throw "Format error: $addr $snt"
        }
        $this.CalcNetwork()
        $this.CalcBroadcast()
        $this.CalcWildcard()
        $this.CalcHost()
        $this.CalcDecIP()
    }
    
    [bool] CheckAddress($addr, $type="CIDR") {
        <#
            .SYNOPSIS
            IPアドレス / CIDRアドレス書式確認
        
            .DESCRIPTION
            正規表現で*.*.*.*または*.*.*.*/*の書式にならっているか確認する。
        
            .INPUTS
            addr: IPアドレス / CIDRアドレス
            type: "ADDR" IPアドレスチェックの場合 / "CIDR" CIDRアドレスチェックの場合
        
            .OUTPUTS
            bool: 確認結果
        #>
        $ptn_addr = '^\d+\.\d+\.\d+\.\d+$'
        $ptn_cidr = '^\d+\.\d+\.\d+\.\d+/\d+$'
        if(($type -eq "CIDR") -And ($addr -match $ptn_cidr)) {
            return $true
        }
        elseif(($type -eq "ADDR") -And ($addr -match $ptn_addr)) {
            return $true
        }
        return $false
    }

    [uInt32] ToDec($addr) {
        <#
            .SYNOPSIS
            IPアドレス→10進変換
        
            .DESCRIPTION
            IPアドレスを32bitの10進数に変換する。
        
            .INPUTS
            addr: IPアドレス
        
            .OUTPUTS
            uInt32: 10進変換されたIPアドレス
        #>
        if(!$this.CheckAddress($addr, "ADDR")) {
            throw "Format error: $addr"
        }
        $oct_addr = $addr -split "\."
        return ([uInt32]$oct_addr[0] -shl 24) + ([uInt32]$oct_addr[1] -shl 16) +
               ([uInt32]$oct_addr[2] -shl 8) + ([uInt32]$oct_addr[3])
    }
    
    [string] ToOctet([uInt32]$dec) {
        <#
            .SYNOPSIS
            10進→IPアドレス変換
        
            .DESCRIPTION
            32bitの10進数をIPアドレスに変換する。
        
            .INPUTS
            dec: 10進数
        
            .OUTPUTS
            string: 変換されたIPアドレス
        #>
        $oct_dec = @()
        $oct_dec += ($dec -band $this.ToDec("255.0.0.0")) -shr 24
        $oct_dec += ($dec -band $this.ToDec("0.255.0.0")) -shr 16
        $oct_dec += ($dec -band $this.ToDec("0.0.255.0")) -shr 8
        $oct_dec += ($dec -band $this.ToDec("0.0.0.255"))
        return [string]$oct_dec[0]+"."+[string]$oct_dec[1]+"."+[string]$oct_dec[2]+"."+[string]$oct_dec[3]
    }

    [string] ToBinary($addr) {
        <#
            .SYNOPSIS
            10進またはIPアドレス→2進変換
        
            .DESCRIPTION
            32bitの10進数またはIPアドレスを2進数表記に変換する。
        
            .INPUTS
            addr: 10進またはIPアドレス
        
            .OUTPUTS
            string: 変換された2進数表記
        #>
        if($addr.GetType().FullName -eq "System.String") {
            # 入力値がIPアドレスなら書式確認
            if(!$this.CheckAddress($addr, "ADDR")) {
                throw "Format error: $addr"
            }
        }
        elseif($addr -match "^\d+$") {
            # 入力値が10進数ならオクテット変換
            $addr = $this.ToOctet($addr)
        }
        $bin_addr = ""
        $oct_addr = $addr -split "\."
        for($i=0;$i -lt 4;$i++) {
            $bin_addr += "{0:00000000}" -f [int][Convert]::ToString($oct_addr[$i], 2)
            if($i -ne 3) {
                $bin_addr += "."
            }
        }
        return $bin_addr
    }
    
    [string] ToSubnet($cdr) {
        <#
            .SYNOPSIS
            CIDR→サブネットマスク変換
        
            .DESCRIPTION
            CIDR値をサブネットマスクに変換する。
        
            .INPUTS
            cdr: CIDR値(0-32)
        
            .OUTPUTS
            string: 変換されたサブネットマスク
        #>
        $snt = ""
        # 8の倍数単位でオクテット値を冪乗計算
        for($i=0;$i -lt 4;$i++) {
            if($cdr -ge 8) {
                $snt += "255"
                $cdr -= 8
            }
            elseif($cdr -le 0) {
                $snt += "0"
                $cdr = 0
            }
            else {
                $oct = 256 - [Math]::Pow(2, 8-$Cdr)
                $snt += [string]$oct
                $cdr = 0
            }
            if($i -ne 3) {
                $snt += "."
            }
        }
        return $snt
    }
    
    [int] ToCidr($snt) {
        <#
            .SYNOPSIS
            サブネットマスク→CIDR変換
        
            .DESCRIPTION
            サブネットマスクをCIDR値に変換する。
        
            .INPUTS
            snt: サブネットマスク
        
            .OUTPUTS
            int: 変換されたCIDR値
        #>
        if(!$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $snt"
        }
        $cdr = 0
        $tmp = $snt -split "\."
        # オクテット毎に2進数表記にしてCIDRを計算
        for($i=0;$i -lt 4;$i++) {
            $bit = [Convert]::ToString([int]$tmp[$i], 2)
            for($j=0;$j -lt 8;$j++) {
                if($bit[$j] -eq "1") {
                    $cdr++
                }
            }
        }
        return [int]$cdr
    }
    
    [string] CalcNetwork($addr, $snt) {
        <#
            .SYNOPSIS
            ネットワークアドレス算出
        
            .DESCRIPTION
            IPアドレス、サブネットマスクからネットワークアドレスを算出する。
        
            .INPUTS
            addr: IPアドレス
            snt: サブネットマスク 
        
            .OUTPUTS
            算出されたネットワークアドレス
        #>
        if(!$this.CheckAddress($addr, "ADDR") -Or !$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $addr $snt"
        }
        $nwk = ""
        $oct_addr = $addr -split "\."
        $oct_snt = $snt -split "\."
        for($i=0;$i -lt 4;$i++) {
            # オクテット毎にサブネット値とのANDを取る
            $nwk += [string]([int]$oct_addr[$i] -band [int]$oct_snt[$i])
            if($i -ne 3) {
                $nwk += "."
            }
        }
        return $nwk
    }
    CalcNetwork() {
        <#
            .SYNOPSIS
            クラス内呼出用オーバーロード
        #>
        $this.IP["Network"] = $this.CalcNetwork($this.IP["Address"], $this.IP["Netmask"])
    }
    
    [string] CalcBroadcast($nwk, $snt) {
        <#
            .SYNOPSIS
            ブロードキャストアドレス算出
        
            .DESCRIPTION
            ネットワークアドレス、サブネットマスクからブロードキャストアドレスを算出
        
            .INPUTS
            nwk: ネットワークアドレス
            snt: サブネットマスク
        
            .OUTPUTS
            string: ブロードキャストアドレス
        #>
        if(!$this.CheckAddress($nwk, "ADDR") -Or !$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $nwk $snt"
        }
        $bct = ""
        $oct_nwk = $nwk -split "\."
        $oct_snt = $snt -split "\."
        for($i=0;$i -lt 4;$i++) {
            # サブネットマスクの反転(255とのXOR)とネットワークアドレスとのXORを取る
            $bct += [string]([int]$oct_nwk[$i] -bxor ([int]$oct_snt[$i] -bxor 255))
            if($i -ne 3) {
                $bct += "."
            }
        }
        return $bct
    }
    CalcBroadcast() {
        <#
            .SYNOPSIS
            クラス内呼出用オーバーロード
        #>
        $this.IP["Broadcast"] = $this.CalcBroadcast($this.IP["Network"], $this.IP["Netmask"])
    }

    [string] CalcWildcard($snt) {
        <#
            .SYNOPSIS
            ワイルドカード算出
        
            .DESCRIPTION
            サブネットマスクからワイルドカードマスクを算出
        
            .INPUTS
            snt: サブネットマスク
        
            .OUTPUTS
            string: ワイルドカードマスク
        #>
        if(!$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $snt"
        }
        $wdk = ""
        $oct_snt = $snt -split "\."
        for($i=0;$i -lt 4;$i++) {
            # サブネットマスクの反転(255とのXOR)を取る
            $wdk += [string]([int]$oct_snt[$i] -bxor 255)
            if($i -ne 3) {
                $wdk += "."
            }
        }
        return $wdk
    }
    CalcWildcard() {
        <#
            .SYNOPSIS
            クラス内呼出用オーバーロード
        #>
        $this.IP["Wildcard"] = $this.CalcWildcard($this.IP["Netmask"])
    }
    
    CalcHost() {
        <#
            .SYNOPSIS
            最小/最大ホストアドレス算出
        
            .DESCRIPTION
            ネットワークアドレス、ブロードキャストアドレスから最小/最大ホストアドレスを算出する。
            CIDR=0または32の時は特殊なので直接記載。
        #>
        if($this.IP["Cidr"] -eq 0) {
            $this.IP["HostMin"] = "0.0.0.1"
            $this.IP["HostMax"] = "255.255.255.254"
        }
        elseif($this.IP["Cidr"] -eq 32) {
            $this.IP["HostMin"] = $this.IP["Address"]
            $this.IP["HostMax"] = $this.IP["Address"]
        }
        else {
            $this.IP["HostMin"] = $this.ToOctet($this.ToDec($this.IP["Network"])+1)
            $this.IP["HostMax"] = $this.ToOctet($this.ToDec($this.IP["Broadcast"])-1)
        }
    }

    CalcDecIP() {
        <#
            .SYNOPSIS
            アドレスの10進変換
        
            .DESCRIPTION
            収集した各種アドレスを10進数に変換する。
        #>
        $dec_ip = @{}
        foreach($k in $this.DecIP.Keys) {
            $dec_ip[$k] = $this.ToDec($this.IP[$k])
        }
        $this.DecIP = $dec_ip
    }

    [string] CheckAddressClass($addr) {
        <#
            .SYNOPSIS
            IPアドレスのアドレスクラス確認
        
            .DESCRIPTION
            IPアドレスからClass A～Eいずれか確認する。
        
            .INPUTS
            addr: IPアドレス
        
            .OUTPUTS
            string: アドレスクラス
        #>
        foreach($val in $this.Class) {
            if(($this.ToDec($addr) -ge $this.ToDec($val["Min"])) -And ($this.ToDec($addr) -le $this.ToDec($val["Max"]))) {
                return $val["Info"]
            }
        }
        return ""
    }

    [string] Print() {
        <#
            .SYNOPSIS
            結果出力
        #>
        $ret =  "Address:    {0,-24}{1,-36}`n" -f $this.IP["Address"], $this.ToBinary($this.IP["Address"])
        $ret += "Netmask:    {0,-16} = {1,-5}{2,-36}`n" -f $this.IP["Netmask"], $this.IP["Cidr"], $this.ToBinary($this.IP["Netmask"])
        $ret += "Wildcard:   {0,-24}{1,-36}`n" -f $this.IP["Wildcard"], $this.ToBinary($this.IP["Wildcard"])
        $ret += "=>`n"
        $ret += "Network:    {0,-24}{1,-36}`n" -f $this.IP["Network"], $this.ToBinary($this.IP["Network"])
        $ret += "HostMin:    {0,-24}{1,-36}`n" -f $this.IP["HostMin"], $this.ToBinary($this.IP["HostMin"])
        $ret += "HostMax:    {0,-24}{1,-36}`n" -f $this.IP["HostMax"], $this.ToBinary($this.IP["HostMax"])
        $ret += "Broadcast:  {0,-24}{1,-36}`n" -f $this.IP["Broadcast"], $this.ToBinary($this.IP["Broadcast"])
        $ret += "Hosts/Net:  {0,-24}{1}" -f ($this.DecIP["HostMax"]-$this.DecIP["HostMin"]+1), $this.CheckAddressClass($this.IP["Address"])
        #$ret += "Hosts/Net:  {0,-60}" -f ($this.DecIP["HostMax"]-$this.DecIP["HostMin"]+1)
        return $ret
    }
}

$CalcIP = New-Object -TypeName "CalcIP" -ArgumentList $Args[0], $Args[1]
$CalcIP.Print()
