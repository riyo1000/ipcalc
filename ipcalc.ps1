<#
    .SYNOPSIS
    ipcalc PowerShell��

    .DESCRIPTION
    Linux��ipcalc�R�}���h��PowerShell�����B

    .INPUTS
    Args[0]: CIDR�A�h���X�܂���IP�A�h���X
    Args[1]: �T�u�l�b�g�}�X�N (CIDR�A�h���X�w��̏ꍇ�͖���)

    .OUTPUTS
    Address: IP�A�h���X(���͒l)
    Netmask: �T�u�l�b�g�}�X�N(���͒l/�Z�o)
    Wildcard: ���C���h�J�[�h�}�X�N(�Z�o)
    CIDR: CIDR(���͒l/�Z�o)
    Network: �l�b�g���[�N�A�h���X(�Z�o)
    HostMin: ��Ԃōŏ��̃z�X�g�A�h���X(�Z�o)
    HostMax: �V�Ԃōŏ��̃z�X�g�A�h���X(�Z�o)
    Broadcast: �u���[�h�L���X�g�A�h���X(�Z�o)
    Hosts/Net: ���z�X�g��(�Z�o)
    Class: IP�A�h���X�N���X(�Z�o)

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
            ������

            .INPUTS
            addr: IP�A�h���X / CIDR�A�h���X
            snt: �T�u�l�b�g�}�X�N(CIDR�A�h���X���͎��͕s�v)
        #>
        
        # CIDR�\�L
        if($this.CheckAddress($addr, "CIDR") -And ![bool]$snt) {
            $tmp = $addr -split "/"
            $this.IP["Address"] = $tmp[0]
            $this.IP["Cidr"] = [int]$tmp[1]
            $this.IP["Netmask"] = $this.ToSubnet($this.IP["Cidr"])
        }
        # �T�u�l�b�g�}�X�N�\�L
        elseif($this.CheckAddress($addr, "ADDR") -And $this.CheckAddress($snt, "ADDR")) {
            $this.IP["Address"] = $addr
            $this.IP["Netmask"] = $snt
            $this.IP["Cidr"] = $this.ToCidr($snt)
        }
        # �G���[
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
            IP�A�h���X / CIDR�A�h���X�����m�F
        
            .DESCRIPTION
            ���K�\����*.*.*.*�܂���*.*.*.*/*�̏����ɂȂ���Ă��邩�m�F����B
        
            .INPUTS
            addr: IP�A�h���X / CIDR�A�h���X
            type: "ADDR" IP�A�h���X�`�F�b�N�̏ꍇ / "CIDR" CIDR�A�h���X�`�F�b�N�̏ꍇ
        
            .OUTPUTS
            bool: �m�F����
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
            IP�A�h���X��10�i�ϊ�
        
            .DESCRIPTION
            IP�A�h���X��32bit��10�i���ɕϊ�����B
        
            .INPUTS
            addr: IP�A�h���X
        
            .OUTPUTS
            uInt32: 10�i�ϊ����ꂽIP�A�h���X
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
            10�i��IP�A�h���X�ϊ�
        
            .DESCRIPTION
            32bit��10�i����IP�A�h���X�ɕϊ�����B
        
            .INPUTS
            dec: 10�i��
        
            .OUTPUTS
            string: �ϊ����ꂽIP�A�h���X
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
            10�i�܂���IP�A�h���X��2�i�ϊ�
        
            .DESCRIPTION
            32bit��10�i���܂���IP�A�h���X��2�i���\�L�ɕϊ�����B
        
            .INPUTS
            addr: 10�i�܂���IP�A�h���X
        
            .OUTPUTS
            string: �ϊ����ꂽ2�i���\�L
        #>
        if($addr.GetType().FullName -eq "System.String") {
            # ���͒l��IP�A�h���X�Ȃ珑���m�F
            if(!$this.CheckAddress($addr, "ADDR")) {
                throw "Format error: $addr"
            }
        }
        elseif($addr -match "^\d+$") {
            # ���͒l��10�i���Ȃ�I�N�e�b�g�ϊ�
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
            CIDR���T�u�l�b�g�}�X�N�ϊ�
        
            .DESCRIPTION
            CIDR�l���T�u�l�b�g�}�X�N�ɕϊ�����B
        
            .INPUTS
            cdr: CIDR�l(0-32)
        
            .OUTPUTS
            string: �ϊ����ꂽ�T�u�l�b�g�}�X�N
        #>
        $snt = ""
        # 8�̔{���P�ʂŃI�N�e�b�g�l��p��v�Z
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
            �T�u�l�b�g�}�X�N��CIDR�ϊ�
        
            .DESCRIPTION
            �T�u�l�b�g�}�X�N��CIDR�l�ɕϊ�����B
        
            .INPUTS
            snt: �T�u�l�b�g�}�X�N
        
            .OUTPUTS
            int: �ϊ����ꂽCIDR�l
        #>
        if(!$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $snt"
        }
        $cdr = 0
        $tmp = $snt -split "\."
        # �I�N�e�b�g����2�i���\�L�ɂ���CIDR���v�Z
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
            �l�b�g���[�N�A�h���X�Z�o
        
            .DESCRIPTION
            IP�A�h���X�A�T�u�l�b�g�}�X�N����l�b�g���[�N�A�h���X���Z�o����B
        
            .INPUTS
            addr: IP�A�h���X
            snt: �T�u�l�b�g�}�X�N 
        
            .OUTPUTS
            �Z�o���ꂽ�l�b�g���[�N�A�h���X
        #>
        if(!$this.CheckAddress($addr, "ADDR") -Or !$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $addr $snt"
        }
        $nwk = ""
        $oct_addr = $addr -split "\."
        $oct_snt = $snt -split "\."
        for($i=0;$i -lt 4;$i++) {
            # �I�N�e�b�g���ɃT�u�l�b�g�l�Ƃ�AND�����
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
            �N���X���ďo�p�I�[�o�[���[�h
        #>
        $this.IP["Network"] = $this.CalcNetwork($this.IP["Address"], $this.IP["Netmask"])
    }
    
    [string] CalcBroadcast($nwk, $snt) {
        <#
            .SYNOPSIS
            �u���[�h�L���X�g�A�h���X�Z�o
        
            .DESCRIPTION
            �l�b�g���[�N�A�h���X�A�T�u�l�b�g�}�X�N����u���[�h�L���X�g�A�h���X���Z�o
        
            .INPUTS
            nwk: �l�b�g���[�N�A�h���X
            snt: �T�u�l�b�g�}�X�N
        
            .OUTPUTS
            string: �u���[�h�L���X�g�A�h���X
        #>
        if(!$this.CheckAddress($nwk, "ADDR") -Or !$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $nwk $snt"
        }
        $bct = ""
        $oct_nwk = $nwk -split "\."
        $oct_snt = $snt -split "\."
        for($i=0;$i -lt 4;$i++) {
            # �T�u�l�b�g�}�X�N�̔��](255�Ƃ�XOR)�ƃl�b�g���[�N�A�h���X�Ƃ�XOR�����
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
            �N���X���ďo�p�I�[�o�[���[�h
        #>
        $this.IP["Broadcast"] = $this.CalcBroadcast($this.IP["Network"], $this.IP["Netmask"])
    }

    [string] CalcWildcard($snt) {
        <#
            .SYNOPSIS
            ���C���h�J�[�h�Z�o
        
            .DESCRIPTION
            �T�u�l�b�g�}�X�N���烏�C���h�J�[�h�}�X�N���Z�o
        
            .INPUTS
            snt: �T�u�l�b�g�}�X�N
        
            .OUTPUTS
            string: ���C���h�J�[�h�}�X�N
        #>
        if(!$this.CheckAddress($snt, "ADDR")) {
            throw "Format error: $snt"
        }
        $wdk = ""
        $oct_snt = $snt -split "\."
        for($i=0;$i -lt 4;$i++) {
            # �T�u�l�b�g�}�X�N�̔��](255�Ƃ�XOR)�����
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
            �N���X���ďo�p�I�[�o�[���[�h
        #>
        $this.IP["Wildcard"] = $this.CalcWildcard($this.IP["Netmask"])
    }
    
    CalcHost() {
        <#
            .SYNOPSIS
            �ŏ�/�ő�z�X�g�A�h���X�Z�o
        
            .DESCRIPTION
            �l�b�g���[�N�A�h���X�A�u���[�h�L���X�g�A�h���X����ŏ�/�ő�z�X�g�A�h���X���Z�o����B
            CIDR=0�܂���32�̎��͓���Ȃ̂Œ��ڋL�ځB
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
            �A�h���X��10�i�ϊ�
        
            .DESCRIPTION
            ���W�����e��A�h���X��10�i���ɕϊ�����B
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
            IP�A�h���X�̃A�h���X�N���X�m�F
        
            .DESCRIPTION
            IP�A�h���X����Class A�`E�����ꂩ�m�F����B
        
            .INPUTS
            addr: IP�A�h���X
        
            .OUTPUTS
            string: �A�h���X�N���X
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
            ���ʏo��
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
