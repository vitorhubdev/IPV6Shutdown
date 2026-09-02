# Changelog

Todas as alterações notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.1.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

## [1.3.1] - 2026-09-02

### Corrigido
- Watchdog agora possui trigger explícito no boot além da reconciliação a cada 2 minutos.
- `StartWhenAvailable` habilitado para recuperar execuções temporais perdidas após desligamento/reinício.
- Status do watchdog valida configuração real (estado, triggers, principal SYSTEM, RunLevel e ação) em vez de considerar apenas a existência da tarefa.
- Descoberta de `MagicDNSSuffix` usa o CLI nativo do Tailscale sem parâmetros inválidos do PowerShell.

### Alterado
- CI executa a suíte de testes antes de publicar binários Native AOT.

---

## [1.3.0] - 2026-08-31

### Adicionado
- **Integração Cloudflare WARP + Tailscale MagicDNS:**
  - Detecção automática da presença simultânea do Tailscale e do Cloudflare WARP.
  - Configuração automática de **DNS Fallback** no Cloudflare WARP (`ts.net` e `*.ts.net`), liberando o acesso a todas as máquinas da rede Tailscale pelo MagicDNS.
  - Descoberta dinâmica e inclusão do sufixo de domínio específico da tailnet ativa (ex: `*.tailc8f42.ts.net`).
  - Nova opção no menu interativo para aplicar a resolução de conflito de DNS sob demanda.
  - Novo argumento de linha de comando `-w, --warp-tailscale` para execução dedicada via CLI.
  - Exibição em tempo real do status de integração na tabela de *Proteções extras* (`Cloudflare WARP + Tailscale DNS`).
- Aplicação automática da correção de DNS ao executar a desativação padrão (`--disable`) ou modo FULL (`--full`).

---

## [1.2.0] - 2026-08-12

### Adicionado
- Aplicação de `Prefer IPv4` (`DisabledComponents | 0x20`) no registro do Windows ao desativar o IPv6.
- Atualização e expansão da documentação README gold-standard em pt-BR.

---

## [1.1.0] - 2026-08-12

### Corrigido
- Verificação robusta e instalação aprimorada da tarefa agendada do watchdog sem parâmetros inválidos de duração.
- Mensagens de feedback claras e tratamento de erros aprimorado para o usuário.

---

## [1.0.0] - 2026-08-12

### Adicionado
- Bloqueio completo de IPv6 em todas as interfaces de rede físicas e virtuais via bindings e firewall.
- Preservação da pilha IPv6 em interfaces do **Tailscale** (faixa privada ULA `fd7a:115c:a1e0::/48`).
- Modo FULL com desativação de túneis de transição (Teredo, 6to4, ISATAP, IP-HTTPS), chave `DisabledComponents` (0xFF) e serviço IP Helper.
- Watchdog agendado (`IPV6Shutdown-Watchdog`) a cada 2 minutos para impedir que novos adaptadores ou serviços reativem o IPv6.
- Interface interativa no terminal utilizando Spectre.Console.
- Pipeline de compilação Native AOT multiplataforma (win-x64 e win-x86) via GitHub Actions.
