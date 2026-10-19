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

- Desativa binding `ms_tcpip6` em adaptadores — **exceto VPNs/overlays** (Cloudflare WARP, Tailscale, WireGuard, OpenVPN/TAP, NordLynx, ProtonVPN…; extensível com `--protect`)
- Regras de firewall IPv6 entrada/saída (nunca bloqueiam loopback, link-local, ULA do Tailscale nem a ULA/DNS local do Cloudflare WARP)
- Tarefa agendada `IPV6Shutdown-Watchdog` (SYSTEM, Highest) no boot + a cada 2 min, com recuperação de execuções perdidas
- **Prefer IPv4** (`DisabledComponents | 0x20`) no `--disable` — sem `0xFF` aqui
- Modo **FULL** (`--full`): túneis de transição, `0xFF` e IP Helper (se não houver VPN/overlay)
- Reversão **fiel** com `-e` / `--enable`: restaura o estado salvo antes da primeira alteração
- Status **real** sem elevação (`-s` / `--status`): bindings, endereços IPv6, regras de firewall efetivamente ativas, Windows Firewall, watchdog (inclusive última execução), reinício pendente e conexão do WARP
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
| `--disable` | Bindings + firewall + Prefer IPv4 `0x20`; IPv6 de VPNs/overlays preservado |
| `--full` | Como `--disable` + túneis + `0xFF` + IP Helper (se não houver VPN/overlay) |
| `-e`, `--enable` | Reverte tudo (bindings, firewall, watchdog, `0x20`, etc.) |
| `-s`, `--status` | Mostra status (não precisa de Admin) |
| `--nofirewall` | Não cria regras de firewall nem watchdog — e **remove** os que já existiam |
| `--protect <texto>` | Preserva o IPv6 de adaptadores cujo nome/descrição contenham o texto (repetível; fica salvo e vale para o watchdog) |
| `-h`, `--help` | Ajuda |

Exemplos:

```powershell
IPV6Shutdown.exe --disable
IPV6Shutdown.exe --full
IPV6Shutdown.exe --disable --protect "MinhaVPN"
IPV6Shutdown.exe -e
IPV6Shutdown.exe -s
```

## Como funciona

### `--disable` (padrão)

0. **Snapshot** — antes de qualquer alteração grava `%ProgramData%\IPV6Shutdown\state.json` (bindings que serão desativados, `DisabledComponents`, estado dos túneis e do IP Helper)
1. **Bindings** — `Disable-NetAdapterBinding` em `ms_tcpip6`, exceto adaptadores de VPN/overlay (se algum estiver com IPv6 desligado, ele é religado: o WARP, por exemplo, usa IPv6 interno para o DNS local)
2. **Firewall** — bloqueia IPv6 entrada/saída exceto loopback, link-local, ULA do Tailscale (`fd7a:115c:a1e0::/48`) e ULA do WARP (`fd01:db8:1111::/64`); as faixas são calculadas por `Ipv6Ranges`
3. **Watchdog** — tarefa `IPV6Shutdown-Watchdog` como SYSTEM (Highest), com trigger no boot + reconciliação a cada 2 min e `StartWhenAvailable`; só age quando algo está errado e usa a mesma lista de VPNs protegidas — não "briga" com o WARP
4. **Prefer IPv4** — grava `DisabledComponents = current | 0x20` (não usa `0xFF` aqui). **Reinício recomendado** para a pilha TCP/IP aplicar plenamente. Evita que sites dual-stack “travem” quando o DNS devolve AAAA mas IPv6 está bloqueado/desvinculado

### `--full`

Tudo do `--disable`, mais:

- Desativa Teredo, 6to4, ISATAP, IP-HTTPS
- **Sem VPN/overlay:** `DisabledComponents = 0xFF` + para/desabilita IP Helper (`iphlpsvc`)
- **Com VPN/overlay (WARP, Tailscale…):** pula `0xFF` e IP Helper (VPNs dependem deles); ainda aplica `0x20` do `--disable`
- Firewall extra (Teredo UDP 3544, protocolo 41)

### VPNs e overlays (Cloudflare WARP, Tailscale, WireGuard…)

Adaptadores cujo nome ou descrição casem com a lista conhecida (ou com `--protect`) **mantêm o IPv6** e o firewall não bloqueia as faixas internas deles. Assim o WARP continua conectando e resolvendo DNS (usa `fd01:db8:1111::2/3`), e o MagicDNS do Tailscale continua funcionando (o fallback `*.ts.net` no WARP é configurado automaticamente quando ambos existem).

### Reverter (`-e` / `--enable`)

Remove watchdog e regras de firewall e **restaura o estado original salvo no snapshot**: reativa só os bindings que a ferramenta desativou, devolve os túneis, `DisabledComponents` e o tipo de inicialização do IP Helper ao valor anterior. Sem snapshot (instalação anterior à v1.4.0) usa o comportamento legado e avisa.

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
