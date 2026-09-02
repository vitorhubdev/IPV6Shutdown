<p align="center">
  <img src="docs/logo.png" alt="IPV6Shutdown" width="128">
</p>

<h1 align="center">IPV6Shutdown</h1>

<p align="center">
  Bloqueio total de IPv6 no Windows — com Tailscale e Prefer IPv4 para sites dual-stack.
</p>

<p align="center">
  <a href="https://github.com/vitorhubdev/IPV6Shutdown/releases/latest"><img src="https://img.shields.io/github/v/release/vitorhubdev/IPV6Shutdown" alt="Release"></a>
  <a href="https://github.com/vitorhubdev/IPV6Shutdown/actions/workflows/publish-aot.yml"><img src="https://github.com/vitorhubdev/IPV6Shutdown/actions/workflows/publish-aot.yml/badge.svg" alt="Publish AOT"></a>
  <a href="https://github.com/vitorhubdev/IPV6Shutdown"><img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows" alt="Windows"></a>
  <a href="https://dot.net/"><img src="https://img.shields.io/badge/.NET-11-512BD4?logo=dotnet" alt=".NET 11"></a>
</p>

---

## Índice

- [O que faz](#o-que-faz)
- [Recursos](#recursos)
- [Download](#download)
- [Uso](#uso)
- [Como funciona](#como-funciona)
- [Compilar e testar](#compilar-e-testar)
- [Códigos de saída](#códigos-de-saída)
- [Avisos](#avisos)
- [Licença](#licença)

## O que faz

Aplicativo de console **somente Windows** (.NET 11, Native AOT, Spectre.Console) que **bloqueia IPv6 na máquina** — bindings, firewall e proteção contínua — mantendo o **IPv6 privado do Tailscale** (ULA `fd7a:115c:a1e0::/48`) funcionando.

Sites dual-stack (ex.: com registro A e AAAA) continuam acessíveis via IPv4 quando o IPv6 está desativado ou bloqueado, graças ao **Prefer IPv4** (`DisabledComponents` bit `0x20`).

## Recursos

- Desativa binding `ms_tcpip6` em adaptadores (exceto Tailscale)
- Regras de firewall IPv6 entrada/saída (exceto ULA Tailscale)
- Tarefa agendada `IPV6Shutdown-Watchdog` (SYSTEM, Highest) no boot + a cada 2 min, com recuperação de execuções perdidas
- **Prefer IPv4** (`DisabledComponents | 0x20`) no `--disable` — sem `0xFF` aqui
- Modo **FULL** (`--full`): túneis de transição, `0xFF` e IP Helper (se sem Tailscale)
- Reversão completa com `-e` / `--enable`
- Status sem elevação (`-s` / `--status`)
- Interface em português (pt-BR)

## Download

**Releases:** https://github.com/vitorhubdev/IPV6Shutdown/releases

| Arquivo | Uso |
|---------|-----|
| `IPV6Shutdown-win-x64.exe` | Windows 64-bit (recomendado) |
| `IPV6Shutdown-win-x86.exe` | Windows 32-bit |

Publicados automaticamente pelo workflow [Publish AOT](.github/workflows/publish-aot.yml) em tags `v*` (Native AOT `win-x64` + `win-x86`).

## Uso

**Requer Administrador**, exceto `--status`. O modo interativo solicita elevação via UAC.

### Menu interativo

```text
IPV6Shutdown.exe
```

Abre o menu (precisa de terminal com stdin). Sem argumentos em ambiente sem entrada, use as opções de linha de comando.

### Linha de comando

| Opção | Descrição |
|-------|-----------|
| *(sem args)* | Menu interativo (eleva via UAC) |
| `--disable` | Bindings + firewall + Prefer IPv4 `0x20`; IPv6 Tailscale preservado |
| `--full` | Como `--disable` + túneis + `0xFF` + IP Helper (se sem Tailscale) |
| `-e`, `--enable` | Reverte tudo (bindings, firewall, watchdog, `0x20`, etc.) |
| `-s`, `--status` | Mostra status (não precisa de Admin) |
| `--nofirewall` | Não cria regras de firewall (nem watchdog) |
| `-h`, `--help` | Ajuda |

Exemplos:

```powershell
IPV6Shutdown.exe --disable
IPV6Shutdown.exe --full
IPV6Shutdown.exe -e
IPV6Shutdown.exe -s
```

## Como funciona

### `--disable` (padrão)

1. **Bindings** — `Disable-NetAdapterBinding` em `ms_tcpip6`, exceto adaptadores Tailscale
2. **Firewall** — bloqueia IPv6 entrada/saída exceto ULA Tailscale (`AllIpv6SemUla` no código)
3. **Watchdog** — tarefa `IPV6Shutdown-Watchdog` como SYSTEM (Highest), com trigger no boot + reconciliação a cada 2 min e `StartWhenAvailable`; reaplica bindings + firewall se WARP, reboot, atualização de driver ou novo adaptador reabilitar IPv6
4. **Prefer IPv4** — grava `DisabledComponents = current | 0x20` (não usa `0xFF` aqui). **Reinício recomendado** para a pilha TCP/IP aplicar plenamente. Evita que sites dual-stack “travem” quando o DNS devolve AAAA mas IPv6 está bloqueado/desvinculado

### `--full`

Tudo do `--disable`, mais:

- Desativa Teredo, 6to4, ISATAP, IP-HTTPS
- **Sem Tailscale:** `DisabledComponents = 0xFF` + para/desabilita IP Helper (`iphlpsvc`) + firewall extra (Teredo UDP 3544, protocolo 41)
- **Com Tailscale:** pula `0xFF` e IP Helper (Tailscale depende de `iphlpsvc`); ainda aplica `0x20` do `--disable`

### Tailscale

Interfaces cujo nome ou descrição contém “Tailscale” mantêm IPv6 ativo. O firewall não bloqueia a faixa ULA privada do tailnet.

### Reverter (`-e` / `--enable`)

Remove watchdog, regras de firewall, reativa bindings, restaura túneis, limpa bit `0x20` em `DisabledComponents` (remove a propriedade se o valor fica 0 ou era `0xFF`), reativa IP Helper.

## Compilar e testar

```bash
dotnet build IPV6Shutdown.slnx
dotnet test IPV6Shutdown.slnx
```

**Publish AOT** (produção): requer **Windows**, .NET 11 (preview) e MSVC — ver [publish-aot.yml](.github/workflows/publish-aot.yml).

```bash
dotnet publish IPV6Shutdown.csproj -c Release -r win-x64 --self-contained -p:PublishAot=true
```

## Códigos de saída

| Código | Significado |
|--------|-------------|
| `0` | Sucesso |
| `1` | Ajuda / argumentos inválidos / cancelamento |
| `2` | Menu interativo cancelado repetidamente |
| `101` | `powershell.exe` não encontrado |
| `102` | Timeout do PowerShell |
| `103` | Comando PowerShell falhou |
| `199` | Erro inesperado |

## Avisos

- **Administrador** obrigatório para desativar/reverter (exceto `--status`)
- Altera **firewall**, **bindings de adaptador**, **tarefas agendadas** e, no modo FULL, **registro** e **IP Helper**
- **Prefer IPv4 (`0x20`)** e **`0xFF`** exigem **reinício** para efeito completo na pilha TCP/IP
- Em PC só IPv4, com DNS dual-stack, `0x20` faz o Windows **preferir registros A** em vez de tentar AAAA primeiro

## Licença

Este repositório **ainda não declara uma LICENSE**. Consulte o autor antes de redistribuir ou modificar.
