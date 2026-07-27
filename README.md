# SuporteADV — ferramentas de suporte técnico

Conjunto de scripts PowerShell usado pela [suporte.adv.br](https://suporte.adv.br) no
atendimento a escritórios de advocacia: manutenção, diagnóstico, reparos e o
ambiente jurídico (certificado digital, token, Java, PJe).

## Como usar

No computador do cliente, abra o **PowerShell como Administrador** e rode:

```powershell
irm https://raw.githubusercontent.com/ivanremotoinfo/-scripts-suporte/main/SuporteADV.ps1 | iex
```

O menu abre com as opções numeradas. Digite o número, ENTER.

> A opção **45 (Simular)** roda a manutenção completa sem alterar nada: mostra o
> que seria feito e quanto espaço seria liberado. Boa para rodar antes, com o
> cliente junto.

## O que tem aqui

| Arquivo | Papel |
|---|---|
| `SuporteADV.ps1` | O menu. Cada opção chama o motor com um parâmetro ou baixa um sub-script. |
| `ManutencaoCompleta.ps1` | O motor. Manutenção completa (16 etapas) e ~35 ferramentas avulsas. |
| os demais `.ps1` | Sub-scripts chamados por opções específicas do menu. |

### O motor

```powershell
# manutenção completa (16 etapas + diagnóstico + relatório)
.\ManutencaoCompleta.ps1

# uma ferramenta só
.\ManutencaoCompleta.ps1 -Ferramenta diagnostico

# não altera nada, só relata
.\ManutencaoCompleta.ps1 -SomenteRelatorio
```

Ferramentas: `diagnostico`, `protecaovirus`, `consoles`, `abrirappdata`,
`memoriavirtual`, `temp`, `lixeira`, `miniaturas`, `windowsupdate`,
`navegadores`, `appcache`, `anydesk`, `winsxs`, `inicializacao`, `appdata`,
`efeitos`, `rede`, `horario`, `defender`, `spooler`, `explorer`, `chkdsk`,
`appx`, `gpupdate`, `ip`, `proxy`, `otimizar`, `sfc`, `smart`, `perfis`,
`topprocessos`, `programas`, `desinstalar`.

Modos independentes: `-EscanearVirus` (ClamAV + VirusTotal),
`-RestaurarQuarentena`, `-DesativarDefender`, `-DesativarFirewall`,
`-ReativarTudo`.

## Princípios que o código segue

- **Senhas e sessões de navegador nunca são apagadas.** A limpeza só entra numa
  lista branca de pastas de cache, e ainda passa por duas verificações que
  barram `Login Data`, `Cookies`, `logins.json`, DPAPI e afins. No fim da
  manutenção as credenciais são conferidas contra uma foto tirada no início.
- **Nada destrutivo sem confirmação S/N**, com a consequência escrita antes da
  pergunta.
- **Sem acentos no código.** O console do Windows em codepage 850/1252 quebra a
  exibição.
- **O que não dá para fazer por script, abre a tela do Windows** com o passo a
  passo (ex.: Proteção contra Adulteração do Defender).
- **Relatórios abrem em arquivo temporário** no Bloco de Notas e não ficam
  salvos. Backups necessários para reverter (registro, credenciais) são
  mantidos na pasta de log.

## Para quem for alterar

Os fontes ficam em `C:\suporteti`, que é este repositório. Antes de publicar:

```powershell
powershell -ExecutionPolicy Bypass -File C:\suporteti\TESTAR.ps1
```

O `TESTAR.ps1` valida sintaxe, BOM, acentos, as referências do menu (se a opção
aponta para arquivo e ferramenta que existem), a largura das colunas e se algum
segredo escapou para o repositório. Com `-Completo`, executa todas as
ferramentas em modo simulação.

**Cuidado com BOM:** grave sempre em UTF-8 **sem BOM**. O raw do GitHub devolve
o BOM como caractere e o `param()` deixa de ser a primeira instrução, quebrando
o script no cliente.

## Aviso

Estes scripts alteram configurações do Windows e removem arquivos. Foram
escritos para uso próprio em atendimento técnico, com o operador acompanhando.
Leia o que cada opção faz antes de rodar em máquina de terceiros.
