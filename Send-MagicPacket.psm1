Using Namespace System.Net
Using Namespace System.Net.NetworkInformation
Using Namespace System.Net.Sockets
Using Namespace System.Diagnostics
Using Namespace System.Management.Automation

# Do-Loop内のタイムリミット
$TIMELIMIT = 60

<#

#>
Enum UdpWellKnownPort {
    ICMPEcho = 7
    MagicPacket = 9
    DNS = 53
}

<#
.Synopsis
    指定マシンにマジックパケットを送出します。
.DESCRIPTION
    指定マシンにWakeOnLanマジックパケットを送出します。
    厳密に言えば送出先はブロードキャストです。マジックパケットを受け取ったマシンのうち、
    パケット内データに自分のMACアドレスが16回連続で現れた場合に電源を起動します。
    これはWakeOnLanの既定の動作です。
.EXAMPLE
    Send-MagicPacket  00-50-56-C0-00-01 -verbose
.EXAMPLE
    Send-MagicPacket 192.168.1.1
.INPUTS
    [String]Addr  IPアドレスまたはMACアドレス文字列
.OUTPUTS
    [IPAddress]起動したマシンのSystem.Net.IPAddressを返します。
.NOTES
    ※注意：IPアドレスを渡す場合、ARPの静的エントリが必要です。
    　本コマンドレットではマシンに保持されるARPテーブルを参照します。
#>
function Send-MagicPacket {
    [CmdletBinding(DefaultParameterSetName='Addr', 
                  SupportsShouldProcess=$true, 
                  PositionalBinding=$false,
                  ConfirmImpact='Medium')]
    [Alias()]
    [OutputType([IPAddress])]
    Param
    (
        [Parameter(Mandatory=$true, 
                   ValueFromPipeline=$true,
                   ValueFromPipelineByPropertyName=$true, 
                   ValueFromRemainingArguments=$false, 
                   Position=0,
                   ParameterSetName='Address')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [ValidateCount(7,17)]
        [Alias("Address")]
        [String]$Addr
    )

    Begin {
        # 引数AddrがMACアドレスかIPアドレスかの判定用
        $OutputEncoding = [Text.Encoding]::UTF8
        [PhysicalAddress]$MACAddress = [PhysicalAddress]::None
        [IPAddress]$IPAddress = [IPAddress]::None

        # AddrはIPアドレス文字列か？
        If ( ![IPAddress]::TryParse( $Addr, [ref]$IPAddress ) ) {

            # AddrはMACアドレス文字列か？
            try {
                $MACAddress = [PhysicalAddress]::Parse( $Addr.toUpper() )
            } catch [FormatException] {
                Write-Error -Message "Addr引数の解析中にエラーが発生しました。" -CategoryReason "渡されたアドレス文字列は正しいIPアドレス記述でもMACアドレス記述でもありません。" -Exception $_.Exception
                exit 1
            }
        } else {
            # IPアドレスからMACAddressの取得を試みる
            If ( $IPAddress -ne [ipaddress]::None ) {
                try {
                    $arp_result = Get-NetNeighbor $IPAddress.ToString() -ErrorAction Stop
                    $MACAddress = [PhysicalAddress]::Parse( $arp_result.LinkLayerAddress )
                } catch [CimJobException] {
                    If ( $_.CategoryInfo.Category -eq [ErrorCategory]::ObjectNotFound ) {
                        Write-Error -Message "渡されたアドレス文字列はARPエントリに見つかりませんでした。"
                        exit 2
                    }
                }
            }
        }
        
        # この時点でMACAddressを取得できていない場合は異常終了とする
        If ( $MACAddress -eq [PhysicalAddress]::None ) {
            Write-Error -Message "プログラムが異常終了しました。MACアドレスが得出来ませんでした。" -TargetObject $Addr
            exit 3
        }
    }

    Process {

        # マジックパケットの生成
        [Byte[]]$MACtoBytes = $MACAddress.GetAddressBytes()
        [Byte[]]$MagicPacket = ( [Byte[]](@( "0xff" ) * 6 ) ) + $MACtoBytes * 16
        [UdpClient]$UdpClient = [UdpClient]::new()
        $UdpClient.Connect( [IPAddress]::Broadcast, [UdpWellKnownPort]::MagicPacket )

        $SendSize = $UdpClient.Send( $MagicPacket, $MagicPacket.Length )
        Write-Host ( "送出したパケットサイズ：{0}バイト" -f $SendSize )
        Write-Verbose ( "`n" + ( ( $MagicPacket | Format-Hex ) -join "`n" ) )
    }

    End {
        $UdpClient.Close()

        # RARPのためのMACアドレス文字の組み立て
        [String]$MACWithHyphen = ($MACtoBytes | %{ $_.toString("X") } | %{ If( $_.length -eq 1 ){ "0{0}" -f $_ } else { $_ } } ) -join "-"

        # 疑似RARPでIPアドレスを取得する
        $rarp_result = $null
        $StopWatch = [StopWatch]::StartNew()
        Do {
            $rarp_result = Get-NetNeighbor -LinkLayerAddress $MACWithHyphen -ErrorAction Ignore
            If ( $StopWatch.Elapsed.Seconds -ge $TIMELIMIT ) {
                Write-Error -CategoryActivity "起動確認エラー" -CategoryReason "マジックパケットは送出できましたが、時間内にRARP解決できませんでした。" -TargetObject $MACWithHyphen
                exit 4
            }

            Write-Progress -Activity マジックパケット送出 -CurrentOperation 疑似RARPの実施中 `
                            -Status ("{0}秒中{1}秒待っています。" -f $TIMELIMIT, $StopWatch.Elapsed.Seconds ) `
                            -PercentComplete ([Math]::Truncate($StopWatch.Elapsed.Seconds * 100 / $TIMELIMIT))

        } Until ( [IPAddress]::TryParse( $rarp_result.IPAddress, [ref]$IPAddress ) )

        # 念のため疎通確認
        $Ping = [Ping]::new()
        $StopWatch.Restart()
        Do {
            $ping_reply = $Ping.Send( $IPAddress )
            Write-Verbose ( "ping結果=>`n`tターゲット`t`t`t`t：{0}`n`tステータス`t`t`t`t：{1}`n`tラウンドトリップタイム`t：{2}" -f $ping_reply.Address, $ping_reply.Status, $ping_reply.RoundtripTime )
            If ( $StopWatch.Elapsed.Seconds -ge $TIMELIMIT ) {
                Write-Error -Message "Pingの実行中にタイムアウトしました。ホストが起動しているか確認してください。" -TargetObject $IPAddress
                exit 5
            }
            Write-Progress -Activity マジックパケット送出 -CurrentOperation Ping応答確認中 `
                            -Status ("{0}秒中{1}秒待っています。" -f $TIMELIMIT, $StopWatch.Elapsed.Seconds ) `
                            -PercentComplete ([Math]::Truncate($StopWatch.Elapsed.Seconds * 100 / $TIMELIMIT))
        } Until ( $ping_reply.Status -eq [IPStatus]::Success )

        $OutputEncoding = [Text.Encoding]::Default
        return $IPAddress
    }
}

Export-ModuleMember -Function Send-MagicPacket