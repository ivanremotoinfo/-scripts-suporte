# ListarCertificados.ps1
# Lista certificados digitais instalados no Windows com nome, validade e
# se tem chave privada (o que indica certificado utilizavel para assinar).
# Somente leitura: nao altera nada.

param(
    [string]$Store = 'My',              # My, Root, CA, TrustedPeople, etc.
    [string]$Location = '',             # vazio = CurrentUser e LocalMachine
    [switch]$ExpiradosApenas,
    [switch]$ProximosAVencer,
    [int]$DiasParaVencer = 30
)

function Get-StatusValidade {
    param([datetime]$DataExpiracao)

    $hoje = Get-Date
    $diasRestantes = ($DataExpiracao - $hoje).Days

    if ($DataExpiracao -lt $hoje) {
        return @{ Status = 'EXPIRADO'; Cor = 'Red'; DiasRestantes = $diasRestantes }
    } elseif ($diasRestantes -le $DiasParaVencer) {
        return @{ Status = 'VENCE EM BREVE'; Cor = 'Yellow'; DiasRestantes = $diasRestantes }
    } else {
        return @{ Status = 'Valido'; Cor = 'Green'; DiasRestantes = $diasRestantes }
    }
}

function Get-CN {
    param([string]$Nome)
    if ($Nome -match 'CN=([^,]+)') { return $Matches[1].Trim() }
    return $Nome
}

function Get-CPFCNPJ {
    param([string]$Subject)
    if ($Subject -match ':(\d{14})\b') {
        $n = $Matches[1]
        return 'CNPJ ' + $n.Substring(0,2) + '.' + $n.Substring(2,3) + '.' + $n.Substring(5,3) + '/' + $n.Substring(8,4) + '-' + $n.Substring(12,2)
    }
    if ($Subject -match ':(\d{11})\b') {
        $n = $Matches[1]
        return 'CPF ' + $n.Substring(0,3) + '.' + $n.Substring(3,3) + '.' + $n.Substring(6,3) + '-' + $n.Substring(9,2)
    }
    return ''
}

# O certificado de token (A3) so aparece na loja enquanto o token estiver
# espetado e o middleware carregado. Ausencia aqui nao quer dizer que o
# certificado nao exista - pode ser token desconectado.
$locais = if ($Location) { @($Location) } else { @('CurrentUser', 'LocalMachine') }

$totalGeral = 0

foreach ($loc in $locais) {
    $caminho = "Cert:\$loc\$Store"

    Write-Host ''
    Write-Host "Certificados Digitais - $loc\$Store" -ForegroundColor Cyan
    Write-Host ('=' * 80) -ForegroundColor Cyan

    try {
        $certificados = @(Get-ChildItem -Path $caminho -ErrorAction Stop)
    } catch {
        Write-Host "Nao foi possivel acessar '$caminho': $($_.Exception.Message)" -ForegroundColor Red
        continue
    }

    if ($certificados.Count -eq 0) {
        Write-Host "Nenhum certificado encontrado em '$caminho'." -ForegroundColor Yellow
        continue
    }

    $lista = foreach ($cert in $certificados) {
        $sv = Get-StatusValidade -DataExpiracao $cert.NotAfter

        if ($ExpiradosApenas -and $sv.Status -ne 'EXPIRADO')       { continue }
        if ($ProximosAVencer -and $sv.Status -ne 'VENCE EM BREVE') { continue }

        $temChave = $false
        try { $temChave = $cert.HasPrivateKey } catch { }

        [PSCustomObject]@{
            Nome          = Get-CN $cert.Subject
            Identificador = Get-CPFCNPJ $cert.Subject
            Emissor       = Get-CN $cert.Issuer
            ValidoDe      = $cert.NotBefore.ToString('dd/MM/yyyy')
            ValidoAte     = $cert.NotAfter.ToString('dd/MM/yyyy')
            DiasRestantes = $sv.DiasRestantes
            Status        = $sv.Status
            ChavePrivada  = $temChave
            Thumbprint    = $cert.Thumbprint
            _Cor          = $sv.Cor
        }
    }

    $lista = @($lista)

    if ($lista.Count -eq 0) {
        Write-Host 'Nenhum certificado corresponde ao filtro aplicado.' -ForegroundColor Yellow
        continue
    }

    foreach ($item in ($lista | Sort-Object { $_.Status -ne 'Valido' }, ValidoAte)) {
        Write-Host ''
        Write-Host "Nome       : $($item.Nome)" -ForegroundColor White
        if ($item.Identificador) {
            Write-Host "Documento  : $($item.Identificador)" -ForegroundColor Gray
        }
        Write-Host "Emissor    : $($item.Emissor)" -ForegroundColor Gray
        Write-Host "Valido de  : $($item.ValidoDe)  ate  $($item.ValidoAte)" -ForegroundColor Gray
        Write-Host "Status     : $($item.Status) ($($item.DiasRestantes) dias)" -ForegroundColor $item._Cor
        if ($item.ChavePrivada) {
            Write-Host 'Chave priv.: SIM - pode assinar documentos' -ForegroundColor Green
        } else {
            Write-Host 'Chave priv.: nao - somente a parte publica (nao assina)' -ForegroundColor DarkGray
        }
        Write-Host "Thumbprint : $($item.Thumbprint)" -ForegroundColor DarkGray
        Write-Host ('-' * 80) -ForegroundColor DarkGray
    }

    $comChave = @($lista | Where-Object { $_.ChavePrivada }).Count
    Write-Host ''
    Write-Host "Total em $loc : $($lista.Count) certificado(s)  |  com chave privada: $comChave" -ForegroundColor Cyan
    $totalGeral += $lista.Count
}

Write-Host ''
Write-Host ('=' * 80) -ForegroundColor Cyan
Write-Host "Total geral encontrado: $totalGeral certificado(s)" -ForegroundColor Cyan
Write-Host 'Token A3 so aparece com o token conectado e o middleware instalado.' -ForegroundColor DarkGray
Write-Host 'Gerenciar manualmente: Win+R > certmgr.msc (usuario) ou certlm.msc (maquina)' -ForegroundColor DarkGray
Write-Host ''
