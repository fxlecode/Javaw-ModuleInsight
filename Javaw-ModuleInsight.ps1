Add-Type @"
using System;
using System.Runtime.InteropServices;
public class MemStuff {
    [DllImport("kernel32.dll")] public static extern IntPtr OpenProcess(uint a, bool b, int c);
    [DllImport("kernel32.dll")] public static extern bool ReadProcessMemory(IntPtr a, IntPtr b, byte[] c, int d, out int e);
    [DllImport("kernel32.dll")] public static extern bool VirtualQueryEx(IntPtr a, IntPtr b, out MEMORY c, uint d);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr a);
    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY {
        public IntPtr Base; public IntPtr AllocBase; uint AllocProtect;
        public IntPtr Size; public uint State; public uint Protect; public uint Type;
    }
    public const uint QUERY = 0x0400, READ = 0x0010, COMMIT = 0x1000, EXRW = 0x40;
}
"@

function Get-Entropia {
    param([byte[]]$datos)
    if ($datos.Length -eq 0) { return 0 }
    $frec = @{}
    foreach ($b in $datos) { $frec[$b]++ }
    $entropia = 0.0
    $len = $datos.Length
    foreach ($v in $frec.Values) {
        $p = $v / $len
        if ($p -gt 0) { $entropia -= $p * [Math]::Log($p, 2) }
    }
    return $entropia
}

function Test-Ofuscacion {
    param([string]$path, [byte[]]$bytesDirectos)
    
    $resultado = @{
        Ofuscado = $false
        Tipo = "Ninguno"
        Entropia = 0
        Razones = @()
    }
    
    try {
        $bytes = if ($bytesDirectos) { $bytesDirectos } else { [System.IO.File]::ReadAllBytes($path) }
        if ($bytes.Length -lt 64) { return $resultado }
        
        
        $entropiaHeader = Get-Entropia $bytes[0..255]
        $resultado.Entropia = [Math]::Round($entropiaHeader, 2)
        
        if ($entropiaHeader -gt 6.8) {
            $resultado.Ofuscado = $true
            $resultado.Tipo = "HIGH_ENTROPY"
            $resultado.Razones += "Entropia PE header: $entropiaHeader (cifrado)"
        }
        
        
        $peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
        if ($peOffset -gt 0 -and $peOffset -lt $bytes.Length - 100) {
            $numSecciones = [BitConverter]::ToUInt16($bytes, $peOffset + 6)
            $optHeaderSize = [BitConverter]::ToUInt16($bytes, $peOffset + 20)
            $seccionTabla = $peOffset + 24 + $optHeaderSize
            
            for ($i = 0; $i -lt [Math]::Min($numSecciones, 20); $i++) {
                $secOffset = $seccionTabla + ($i * 40)
                if ($secOffset + 40 -gt $bytes.Length) { break }
                
                $nombreBytes = $bytes[$secOffset..($secOffset+7)]
                $nombre = [System.Text.Encoding]::ASCII.GetString($nombreBytes).Trim("`0")
                $rawSize = [BitConverter]::ToInt32($bytes, $secOffset + 16)
                $rawAddr = [BitConverter]::ToInt32($bytes, $secOffset + 20)
                
                
                $nombresSospechosos = @("UPX", "ASPACK", "PECompact", ".vmp", ".themida", ".enigma", 
                ".obs", "crypt", "cypher", "protect", "pack", "sec", "textc", "codex")
                foreach ($ns in $nombresSospechosos) {
                    if ($nombre -match $ns) {
                        $resultado.Ofuscado = $true
                        $resultado.Tipo = "PACKER_DETECTADO"
                        $resultado.Razones += "Seccion: $nombre"
                    }
                }
                
               
                if ($rawSize -gt 512 -and $rawAddr -gt 0 -and ($rawAddr + $rawSize) -lt $bytes.Length) {
                    $secData = $bytes[$rawAddr..($rawAddr + [Math]::Min($rawSize, 65536))]
                    $entSec = Get-Entropia $secData
                    
                    
                    if ($nombre -eq ".text" -and $entSec -gt 7.0) {
                        $resultado.Ofuscado = $true
                        $resultado.Tipo = "CODE_ENCRYPTED"
                        $resultado.Razones += ".text cifrado (entropia: $([Math]::Round($entSec,2)))"
                    }
                    
                   
                    if ($nombre -in @(".data",".rdata",".text") -and $entSec -gt 7.5) {
                        $resultado.Ofuscado = $true
                        $resultado.Tipo = "SUSPICIOUS_SECTION"
                        $resultado.Razones += "$nombre con entropia anormal ($([Math]::Round($entSec,2)))"
                    }
                }
            }
        }
        
        # Buscar imports dinamicas (LoadLibrary/GetProcAddress) - tecnica de ofuscacion
        $ascii = [System.Text.Encoding]::ASCII.GetString($bytes)
        if ($ascii -like "*LoadLibrary*" -and $ascii -like "*GetProcAddress*") {
            if ($ascii -split "LoadLibrary" | Select-Object -Skip 1 | Where { $_ -match "GetProcAddress" -and $_ -match "0x" }) {
                $resultado.Ofuscado = $true
                $resultado.Razones += "Resolucion dinamica de APIs (ocultamiento de imports)"
            }
        }
        
       $currentProcess = [System.Diagnostics.Process]::GetCurrentProcess()
       $handle = $currentProcess.Handle
    
       Write-Host "[*] Preparando privilegios de acceso..." -Fore Gray
        
        $stringsLegibles = 0
        $totalChunks = 0
        for ($i = 0; $i -lt $bytes.Length - 100; $i += 100) {
            $chunk = $bytes[$i..($i+99)]
            $ent = Get-Entropia $chunk
            $totalChunks++
            if ($ent -lt 5.0) { $stringsLegibles++ }
        }
        $ratio = $stringsLegibles / $totalChunks
        if ($ratio -lt 0.1 -and $bytes.Length -gt 10000) {
            $resultado.Ofuscado = $true
            $resultado.Razones += "Casi sin strings legibles (ratio: $([Math]::Round($ratio,2)))"
        }
        
    } catch {}
    
    return $resultado
}

function Test-Minecraft {
param([switch]$Exportar, [string]$Ruta = "$env:USERPROFILE\Desktop\MC_Ofusc_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv")

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Error "Necesitas admin"; return }

$sysPath = "C:\Sysinternals"
$stringsExe = Get-Command "strings.exe" -EA SilentlyContinue
if (-not $stringsExe) { $stringsExe = Get-ChildItem -Path $sysPath -Filter "strings.exe" -EA SilentlyContinue | Select -First 1 }

if (-not $stringsExe) {
    Write-Host "Descargando Sysinternals..." -Fore Yellow
    try {
        $zip = "$env:TEMP\sys.zip"
        Invoke-WebRequest "https://download.sysinternals.com/files/SysinternalsSuite.zip" -OutFile $zip -UseBasicParsing
        Expand-Archive $zip $sysPath -Force
        Remove-Item $zip
        $stringsExe = "$sysPath\strings.exe"
    } catch {
        Write-Host "Fallo descarga" -Fore Yellow
    }
}

$procesos = Get-Process -Name @("javaw","java") -EA SilentlyContinue | Where { 
    $_.MainWindowTitle -match "Minecraft|Lunar|Badlion|Forge|Fabric|OptiFine" -or 
    $_.Modules.ModuleName -match "lwjgl|minecraft|forge|fabric"
}

if (-not $procesos) { Write-Host "No hay Minecraft" -Fore Red; return }

$hallazgos = @()

foreach ($proc in $procesos) {
    Write-Host "`nAnalizando PID $($proc.Id)" -Fore Cyan
    
    $hProc = [MemStuff]::OpenProcess([MemStuff]::QUERY -bor [MemStuff]::READ, $false, $proc.Id)
    if ($hProc -eq [IntPtr]::Zero) { continue }

    $mem = New-Object MemStuff+MEMORY
    $addr = [IntPtr]::Zero
    $regiones = @()

    
Write-Host "[*] Privilegios confirmados. Iniciando escaneo de 100GB (esto puede tardar)..." -Fore Gray
    Write-Host "[*] Iniciando escaneo de memoria dinámica..." -Fore Gray

    while ([MemStuff]::VirtualQueryEx($hProc, $addr, [ref]$mem, [System.Runtime.InteropServices.Marshal]::SizeOf($mem))) {
        if ($mem.State -eq [MemStuff]::COMMIT -and ($mem.Protect -eq [MemStuff]::EXRW -or $mem.Protect -eq 0x40)) {
            $sizeMB = [Math]::Round($mem.Size.ToInt64() / 1MB, 2)
            
            if ($sizeMB -gt 0.02 -and $sizeMB -lt 300) {
                $buf = New-Object byte[] ([Math]::Min(8192, $mem.Size.ToInt64()))
                $read = 0
                [void][MemStuff]::ReadProcessMemory($hProc, $mem.Base, $buf, $buf.Length, [ref]$read)
                
                $isPE = ($buf[0] -eq 0x4D -and $buf[1] -eq 0x5A)
                $tieneCodigoSus = $false
                $patrones = @()
                
                if ($isPE) {
                    $analisisMem = Test-Ofuscacion -bytesDirectos $buf
                    if ($analisisMem.Ofuscado) {
                        $tieneCodigoSus = $true
                        $patrones += "OFUSCADO_MEM:$($analisisMem.Tipo)"
                    }
                    
                    
                    
                    for ($i=0; $i -lt $buf.Length-5; $i++) {
                        if ($buf[$i] -eq 0xE9) {
                            $dest = [BitConverter]::ToInt32($buf, $i+1)
                            if ([Math]::Abs($dest) -gt 1000) {
                                $tieneCodigoSus = $true
                                $patrones += "JMP@$i"
                            }
                        }
                    }
                }
                
                
                if ($isPE -or $tieneCodigoSus -or $sizeMB -gt 0.5) {
                    $regiones += @{
                        Dir = "0x$($mem.Base.ToString('X'))"
                        Size = $sizeMB
                        PE = $isPE
                        Sus = $tieneCodigoSus
                        Patrones = $patrones
                        Ofuscado = if ($isPE) { (Test-Ofuscacion -bytesDirectos $buf).Ofuscado } else { $false }
                    }
                }
            }
        }
        
        $addr = [IntPtr]($mem.Base.ToInt64() + $mem.Size.ToInt64())
    }
                        }
                    }
                }
                
                if ($isPE -or $tieneCodigoSus -or $sizeMB -gt 0.5) {
                    $regiones += @{
                        Dir = "0x$($mem.Base.ToString('X'))"
                        Size = $sizeMB
                        PE = $isPE
                        Sus = $tieneCodigoSus
                        Patrones = $patrones
                        Ofuscado = if ($isPE) { (Test-Ofuscacion -bytesDirectos $buf).Ofuscado } else { $false }
                    }
                }
            }
        }
        $addr = [IntPtr]($mem.Base.ToInt64() + $mem.Size.ToInt64())
    }

    [void][MemStuff]::CloseHandle($hProc)

    $mods = @()
    try { $mods = $proc.Modules | Where { $_.ModuleName -like "*.dll" } } catch {}

    foreach ($mod in $mods) {
        $path = $mod.FileName
        if ([string]::IsNullOrEmpty($path)) { continue }

        try {
            $file = Get-Item -Path $path -EA Stop
            $sign = Get-AuthenticodeSignature -FilePath $path
            
            
            $analisis = Test-Ofuscacion -path $path
            
            $riesgo = "Bajo"
            $razones = @()
            $inyeccion = "N/A"

            if ($analisis.Ofuscado) {
                $riesgo = "CRITICO"
                $razones += "DLL OFUSCADO: $($analisis.Tipo) - $($analisis.Razones -join ', ')"
            }

            $nombreEsperado = [System.IO.Path]::GetFileName($path)
            $nombreEnMemoria = $mod.ModuleName
            if ($nombreEsperado -ne $nombreEnMemoria) {
                $riesgo = "CRITICO"
                $razones += "RENOMBRADO: disco=$nombreEsperado mem=$nombreEnMemoria"
            }

            $inicioProc = $proc.StartTime
            $modif = $file.LastWriteTime
            $diff = ($modif - $inicioProc).TotalMinutes
            
            if ($diff -gt 0.5) {
                $riesgo = "CRITICO"
                $razones += "Cargado $([Math]::Round($diff,1))m despues"
                $inyeccion = $modif.ToString("yyyy-MM-dd HH:mm:ss")
            }

            if ($sign.Status -ne "Valid") {
                $riesgo = "CRITICO"
                $razones += "Sin firma"
            }

            
            $sospechoso = $path -match "\\Temp\\|\\TMP\\|\\AppData\\Local\\Temp\\|\\Downloads\\|\\Desktop\\|AppData\\Roaming\\[^\\]+\\.+\.dll$|AppData\\Local\\[^\\]+\\.+\.dll$"
            if ($sospechoso) {
                $riesgo = "CRITICO"
                $razones += "Ruta sospechosa"
            }

            
            $hooks = @()
            if ($mod.ModuleName -in @("ws2_32.dll","wininet.dll","kernel32.dll","opengl32.dll","user32.dll")) {
                try {
                $pe = [BitConverter]::ToUInt32($disk, 0x3C)
                $ep = [BitConverter]::ToUInt32($disk, $pe + 0x28)
                $base = [BitConverter]::ToInt64($disk, $pe + 0x30)
                    $epOff = $ep - $base + $pe + 24
                    if ($epOff -gt 0) {
                        $diskB = $disk[$epOff..($epOff+5)]
                        $h2 = [MemStuff]::OpenProcess([MemStuff]::READ, $false, $proc.Id)
                        $memB = New-Object byte[] 6
                        $r = 0
                        $epM = [IntPtr]::Add($mod.BaseAddress, $ep - $base)
                        [void][MemStuff]::ReadProcessMemory($h2, $epM, $memB, 6, [ref]$r)
                        [void][MemStuff]::CloseHandle($h2)
                        
                        for ($i=0; $i -lt 6; $i++) {
                            if ($diskB[$i] -ne $memB[$i]) {
                                $hooks += "EP+$i"
                                $riesgo = "CRITICO"
                            }
                        }
                        if ($hooks) { $razones += "HOOK ACTIVO" }
                    }
                } catch {}
            }

            $existe = Test-Path $path
            if (-not $existe) {
                $riesgo = "CRITICO"
                $razones += "DLL FANTASMA"
            }

            $tamKB = [Math]::Round($mod.ModuleMemorySize / 1KB, 2)

            $hallazgos += [PSCustomObject]@{
                PID = $proc.Id
                Tipo = if ($analisis.Ofuscado) { "DLL_OFUSCADO" } else { "DLL_Normal" }
                NombreMemoria = $nombreEnMemoria
                NombreDisco = $nombreEsperado
                Riesgo = $riesgo
                Razones = ($razones -join " | ")
                Path = $path
                Inyeccion = $inyeccion
                Firmado = if ($sign.Status -eq "Valid") { "Si" } else { "NO" }
                Entidad = if ($sign.SignerCertificate) { $sign.SignerCertificate.Subject.Split(',')[0].Replace('CN=','') } else { "N/A" }
                Hash = (Get-FileHash -Path $path -Algorithm SHA256 -EA SilentlyContinue).Hash
                Hooks = ($hooks -join ",")
                Base = "0x$($mod.BaseAddress.ToString('X'))"
                TamanoKB = $tamKB
                ExisteDisco = $existe
                Ofuscado = $analisis.Ofuscado
                TipoOfuscacion = $analisis.Tipo
                Entropia = $analisis.Entropia
            }
        } catch {}
    }

    foreach ($reg in $regiones) {
        $tipoStr = if ($reg.Ofuscado) { "OFUSCADO_REFLECTIVO" } elseif ($reg.PE) { "PE_REFLECTIVO" } else { "CODIGO_EWR" }
        
        $hallazgos += [PSCustomObject]@{
            PID = $proc.Id
            Tipo = $tipoStr
            NombreMemoria = "NO_MAPEADO"
            NombreDisco = "N/A"
            Riesgo = "CRITICO"
            Razones = "Memoria ejecutable privada. $($reg.Patrones -join ', ')"
            Path = "MEM:$($reg.Dir)"
            Inyeccion = "REALTIME"
            Firmado = "N/A"
            Entidad = "N/A"
            Hash = "N/A"
            Hooks = ""
            Base = $reg.Dir
            TamanoKB = [Math]::Round($reg.Size * 1024, 2)
            ExisteDisco = $false
            Ofuscado = $reg.Ofuscado
            TipoOfuscacion = if ($reg.Ofuscado) { "Memoria" } else { "Ninguno" }
            Entropia = 0
        }
    }
}

$orden = @{ "CRITICO" = 0; "MEDIO" = 1; "Bajo" = 2 }
$result = $hallazgos | Sort { $orden[$_.Riesgo] }, PID

Write-Host "`n========== RESULTADOS ==========" -Fore Cyan

$ofuscados = $result | Where { $_.Ofuscado -eq $true }
if ($ofuscados) {
    Write-Host "`n!!! DLLs OFUSCADOS DETECTADOS !!!" -Fore Magenta
    $ofuscados | Format-Table PID, NombreMemoria, TipoOfuscacion, Entropia -Auto
}

$crit = $result | Where { $_.Riesgo -eq "CRITICO" -and $_.Ofuscado -eq $false }
if ($crit) {
    Write-Host "`nOtros criticos:" -Fore Red
    $crit | Select -First 5 | Format-Table PID, NombreMemoria, Razores -Auto
}

Write-Host "`nTotal: $($hallazgos.Count) | Ofuscados: $(($ofuscados).Count) | Criticos: $(($hallazgos | Where {$_.Riesgo -eq 'CRITICO'}).Count)" -Fore White

if ($Exportar) {
    $result | Export-Csv -Path $Ruta -NoType -Encoding UTF8
    Write-Host "Guardado: $Ruta" -Fore Green
}

$result | Out-GridView -Title "Minecraft Forensic - Ofuscacion Detection"
}


Test-Minecraft -Exportar








