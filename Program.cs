using System.ComponentModel;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.Versioning;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Spectre.Console;

namespace IPV6Shutdown
{
    [SupportedOSPlatform("windows")]
    internal static class Program
    {
        private const string RuleSaida = "IPV6Shutdown - Bloquear IPv6 (Saida)";
        private const string RuleEntrada = "IPV6Shutdown - Bloquear IPv6 (Entrada)";
        private const string RuleTeredo = "IPV6Shutdown - Bloquear Teredo (UDP 3544)";
        private const string Rule6in4 = "IPV6Shutdown - Bloquear 6in4 (Protocolo 41)";
        private const string RegPath = @"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
        private const string WatchdogTaskName = "IPV6Shutdown-Watchdog";
        private const int PsTimeoutMs = 60_000;
        private const int BindingBatchSize = 40;
        private const int KillWaitMs = 5_000;

        // Todo IPv6 exceto loopback, link-local e as ULAs de Tailscale/Cloudflare WARP (ver Ipv6Ranges).
        private static readonly string BlockedRemote = Ipv6Ranges.BuildBlockedRanges(Ipv6Ranges.DefaultExclusions);
        private static readonly string PowerShellExe = ResolvePowerShellPath();

        private static readonly HashSet<string> KnownArgs = new(StringComparer.OrdinalIgnoreCase)
        {
            "-e", "--enable", "-s", "--status", "--full", "--disable",
            "--nofirewall", "--pause", "-h", "--help", "/?",
            "-w", "--warp-tailscale"
        };

        private static List<string> _cliProtect = [];
        private static OriginalState? _state;
        private static bool _stateLoaded;
        private static List<BindingInfo>? _bindingsCache;

        private static int Main(string[] args)
        {
            Console.Title = "IPV6Shutdown — bloqueio total de IPv6 | github.com/vitorhubdev";
            Console.OutputEncoding = Encoding.UTF8;

            if (!TryParseArgs(args, out string[] flags, out List<string> protect))
            {
                ShowHelp();
                return 1;
            }
            _cliProtect = protect;

            bool enable = flags.Any(a => a is "-e" or "--enable");
            bool statusOnly = flags.Any(a => a is "-s" or "--status");
            bool full = flags.Any(a => a is "--full");
            bool disable = flags.Any(a => a is "--disable");
            bool noFirewall = flags.Any(a => a is "--nofirewall");
            bool pause = flags.Any(a => a is "--pause");
            bool warpTailscale = flags.Any(a => a is "-w" or "--warp-tailscale");

            if (flags.Any(a => a is "-h" or "--help" or "/?"))
            {
                ShowHelp();
                return 0;
            }

            if (flags.Any(a => !KnownArgs.Contains(a)))
            {
                ShowHelp();
                return 1;
            }

            bool isAdmin = IsAdministrator();

            if (args.Length == 0)
                return RunInteractive();

            if (!statusOnly && !isAdmin)
            {
                if (!TryElevate(args))
                    return 1;
                return 0;
            }

            RenderHeader();
            try
            {
                if (statusOnly)
                {
                    RenderStatus();
                }
                else if (warpTailscale)
                {
                    FixWarpTailscaleStandalone();
                    RenderStatus();
                }
                else if (enable)
                {
                    Revert();
                    RenderStatus();
                }
                else if (full)
                {
                    DisableFull(noFirewall);
                    RenderStatus();
                }
                else if (disable || noFirewall)
                {
                    DisableStandard(noFirewall);
                    RenderStatus();
                }
                else
                {
                    ShowHelp();
                    return 1;
                }
            }
            catch (PowerShellException ex)
            {
                RenderError(ex);
                if (pause)
                    SafePause();
                return ex.Code;
            }
            catch (Exception ex)
            {
                RenderUnexpected(ex);
                if (pause)
                    SafePause();
                return 199;
            }

            if (pause)
            {
                AnsiConsole.MarkupLine("\n[grey]Pressione qualquer tecla para sair...[/]");
                SafePause();
            }
            return 0;
        }

        /// <summary>Separa "--protect valor" / "--protect=valor" dos demais argumentos.</summary>
        private static bool TryParseArgs(string[] args, out string[] flags, out List<string> protect)
        {
            var rest = new List<string>();
            protect = [];
            for (int i = 0; i < args.Length; i++)
            {
                string arg = args[i];
                string value;
                if (arg.Equals("--protect", StringComparison.OrdinalIgnoreCase))
                {
                    if (i + 1 >= args.Length)
                    {
                        flags = [.. rest];
                        return false;
                    }
                    value = args[++i];
                }
                else if (arg.StartsWith("--protect=", StringComparison.OrdinalIgnoreCase))
                {
                    value = arg["--protect=".Length..];
                }
                else
                {
                    rest.Add(arg);
                    continue;
                }

                if (!AdapterProtection.IsValidCustomPattern(value))
                {
                    flags = [.. rest];
                    return false;
                }
                protect.Add(value.Trim().ToLowerInvariant());
            }
            flags = [.. rest];
            return true;
        }

        private static string ResolvePowerShellPath()
        {
            // Caminho absoluto (programa roda elevado: nada de procurar powershell.exe no diretório do .exe/PATH).
            // Processo de 32 bits em Windows de 64 bits usa Sysnative para obter o PowerShell de 64 bits.
            string windir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string sub = Environment.Is64BitOperatingSystem && !Environment.Is64BitProcess ? "Sysnative" : "System32";
            string path = Path.Combine(windir, sub, "WindowsPowerShell", "v1.0", "powershell.exe");
            return File.Exists(path) ? path : "powershell.exe";
        }

        private static OriginalState? GetState()
        {
            if (!_stateLoaded)
            {
                _state = OriginalState.Load();
                _stateLoaded = true;
            }
            return _state;
        }

        private static void SetState(OriginalState? state)
        {
            _state = state;
            _stateLoaded = true;
        }

        private static List<string> CustomProtect() =>
            (GetState()?.CustomProtect ?? []).Concat(_cliProtect)
                .Select(p => p.Trim().ToLowerInvariant())
                .Where(AdapterProtection.IsValidCustomPattern)
                .Distinct(StringComparer.Ordinal)
                .ToList();

        private static IReadOnlyList<string> ProtectPatterns() => AdapterProtection.Normalize(CustomProtect());

        private static string? ProtectionReason(BindingInfo b) =>
            AdapterProtection.FindMatch(b.Name, b.Description, CustomProtect());

        private static bool IsProtectedAdapter(BindingInfo b) => ProtectionReason(b) is not null;

        private static bool HasProtectedVpn() =>
            GetBindings().Any(IsProtectedAdapter) || GetTailscaleCliPath() != null || GetWarpCliPath() != null;

        private static int RunInteractive()
        {
            if (Console.IsInputRedirected)
            {
                AnsiConsole.MarkupLine("[red]Modo interativo requer um terminal com entrada disponível.[/]");
                AnsiConsole.MarkupLine("[grey]Use as opções de linha de comando: --disable, --full, -e, -s, -h[/]");
                return 1;
            }
            if (!IsAdministrator())
            {
                if (!TryElevate(null))
                {
                    AnsiConsole.MarkupLine("[grey]Pressione qualquer tecla para sair...[/]");
                    SafePause();
                    return 1;
                }
                return 0;
            }

            int cancelCount = 0;
            while (true)
            {
                try
                {
                    AnsiConsole.Clear();
                    RenderHeader();
                    RenderStatus();
                    AnsiConsole.MarkupLine("[grey]Nota: as interfaces do Tailscale mantêm o IPv6 ativo (faixa privada fd7a:115c:a1e0::/48) — necessário para o tailnet funcionar.[/]");
                    AnsiConsole.WriteLine();

                    var choices = new List<string>
                    {
                        "Desativar IPv6 (bindings + firewall — Tailscale preservado)",
                        "Modo FULL (bindings + firewall + túneis + registro + IP Helper — Tailscale preservado)"
                    };

                    if (HasTailscale() && HasCloudflareWarp())
                    {
                        choices.Add("Corrigir DNS Cloudflare WARP + Tailscale (fallback *.ts.net)");
                    }

                    choices.Add("Reverter tudo (reativar IPv6 e desfazer bloqueios)");
                    choices.Add("Sair");

                    string choice;
                    try
                    {
                        choice = AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("[bold]O que deseja fazer?[/]")
                                .HighlightStyle(new Style(Color.Red))
                                .AddChoices(choices));
                    }
                    catch (OperationCanceledException)
                    {
                        if (++cancelCount >= 3)
                        {
                            AnsiConsole.MarkupLine("[grey]Muitos cancelamentos consecutivos. Encerrando...[/]");
                            return 2;
                        }
                        continue;
                    }
                    cancelCount = 0;

                    if (choice == "Sair")
                        return 0;

                    AnsiConsole.Clear();
                    RenderHeader();

                    if (choice.StartsWith("Desativar", StringComparison.Ordinal))
                        DisableStandard(noFirewall: false);
                    else if (choice.StartsWith("Modo FULL", StringComparison.Ordinal))
                        DisableFull(noFirewall: false);
                    else if (choice.StartsWith("Corrigir DNS", StringComparison.Ordinal))
                        FixWarpTailscaleStandalone();
                    else
                        Revert();

                    RenderStatus();
                    AnsiConsole.MarkupLine("[grey]Pressione qualquer tecla para voltar ao menu...[/]");
                    SafePause();
                }
                catch (PowerShellException ex)
                {
                    RenderError(ex);
                    SafePause();
                }
                catch (Exception ex)
                {
                    RenderUnexpected(ex);
                    SafePause();
                }
            }
        }

        private static bool TryElevate(string[]? args)
        {
            AnsiConsole.Write(new Panel("[bold]Esta ação precisa de permissão de Administrador.\nO Windows vai mostrar o aviso de UAC e abrir uma nova janela elevada — isso é normal e esperado.[/]")
                .Header("[yellow]Elevação necessária[/]")
                .BorderColor(Color.Yellow));
            bool confirm;
            try
            {
                confirm = AnsiConsole.Confirm("Solicitar elevação agora?", defaultValue: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException or OperationCanceledException)
            {
                confirm = false;
            }
            if (!confirm)
            {
                AnsiConsole.MarkupLine("[grey]Operação cancelada. Nada foi alterado.[/]");
                return false;
            }
            try
            {
                string newArgs = args is { Length: > 0 }
                    ? string.Join(' ', args.Where(a => a != "--pause").Select(QuoteArg)) + " --pause"
                    : "";
                using Process? elevated = Process.Start(new ProcessStartInfo
                {
                    FileName = Environment.ProcessPath!,
                    Arguments = newArgs,
                    UseShellExecute = true,
                    Verb = "runas"
                });
                return true;
            }
            catch (Exception ex) when (ex is Win32Exception or OperationCanceledException)
            {
                AnsiConsole.MarkupLine("[red]Elevação cancelada. Nada foi alterado.[/]");
                return false;
            }
        }

        private static void RenderHeader()
        {
            AnsiConsole.Write(new FigletText("IPV6").Color(Color.Red).LeftJustified());
            AnsiConsole.Write(new Rule("[bold]IPV6 Shutdown — bloqueio total de IPv6[/]").RuleStyle("grey").LeftJustified());
            AnsiConsole.MarkupLine($"[grey]v{Markup.Escape(GetAppVersion())}[/]");
            AnsiConsole.WriteLine();
        }

        private static string GetAppVersion()
        {
            Assembly assembly = Assembly.GetExecutingAssembly();
            string? info = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
            if (!string.IsNullOrWhiteSpace(info))
                return info.Split('+')[0];
            Version? version = assembly.GetName().Version;
            return version is null ? "?" : $"{version.Major}.{version.Minor}.{version.Build}";
        }

        private static void RenderStatus()
        {
            List<BindingInfo> bindings = GetBindings(fresh: true);
            ExtraStatus extra = GetExtraStatus();
            OriginalState? state = OriginalState.Load();
            SetState(state);
            (WatchdogConfigurationState? watchdogState, string watchdogMarkup, bool watchdogLastRunFailed) = GetWatchdogStatus();

            var table = new Table().Border(TableBorder.Rounded).Title("[bold]Interfaces de rede[/]");
            table.AddColumn("Interface");
            table.AddColumn("IPv6");
            table.AddColumn("End.");
            table.AddColumn("Observação");
            foreach (BindingInfo b in bindings)
            {
                string? reason = ProtectionReason(b);
                string status = b.Enabled
                    ? (reason is null ? "[red]● ATIVO[/]" : "[yellow]● ATIVO (protegido)[/]")
                    : "[green]● DESATIVADO[/]";
                var notes = new List<string>();
                if (reason is not null)
                    notes.Add($"VPN/overlay ({reason})");
                if (!b.Hardware)
                    notes.Add("virtual");
                if (!string.IsNullOrEmpty(b.Status) && !b.Status.Equals("Up", StringComparison.OrdinalIgnoreCase))
                    notes.Add(b.Status.ToLowerInvariant());
                table.AddRow(
                    $"{Markup.Escape(b.Name)}\n[grey]{Markup.Escape(b.Description)}[/]",
                    status,
                    b.Ipv6Addresses.ToString(),
                    Markup.Escape(string.Join(" · ", notes)));
            }
            AnsiConsole.Write(table);

            int expectedRules = state is null ? extra.FirewallRules : state.Mode == "full" ? 4 : 2;
            bool firewallEffective = extra.FirewallService == "Running" && extra.FirewallProfilesOff == 0;
            bool rebootPending = IsRebootPending(state, extra);

            var grid = new Table().Border(TableBorder.Rounded).Title("[bold]Proteções extras[/]");
            grid.AddColumn("Item");
            grid.AddColumn("Status");
            grid.AddRow("Teredo", StateMarkup(extra.Teredo));
            grid.AddRow("6to4", StateMarkup(extra.SixToFour));
            grid.AddRow("ISATAP", StateMarkup(extra.Isatap));
            grid.AddRow("IP-HTTPS", StateMarkup(extra.IpHttps));
            grid.AddRow("DisabledComponents (registro)",
                DisabledComponentsPolicy.FormatStatusMarkup(extra.DisabledComponents)
                + (rebootPending ? " [yellow](reinício pendente)[/]" : ""));
            grid.AddRow("Serviço IP Helper (iphlpsvc)", extra.IpHelper == "Stopped"
                ? $"[green]Parado ({Markup.Escape(extra.IpHelperStart)})[/]"
                : $"[grey]{Markup.Escape(extra.IpHelper)} ({Markup.Escape(extra.IpHelperStart)})[/]");
            grid.AddRow("Regras de firewall IPV6Shutdown", extra.FirewallRules == 0
                ? "[grey]nenhuma[/]"
                : extra.FirewallActive >= expectedRules
                    ? $"[green]{extra.FirewallActive}/{expectedRules} ativa(s)[/]"
                    : $"[yellow]{extra.FirewallActive}/{expectedRules} ativa(s) — incompleto[/]");
            if (extra.FirewallRules > 0)
            {
                grid.AddRow("Windows Firewall", firewallEffective
                    ? "[green]ativo[/]"
                    : extra.FirewallService != "Running"
                        ? $"[red]serviço {Markup.Escape(extra.FirewallService)} — regras sem efeito[/]"
                        : $"[yellow]{extra.FirewallProfilesOff} perfil(is) desativado(s) — regras sem efeito nele(s)[/]");
            }
            grid.AddRow("Watchdog (proteção contínua)", watchdogMarkup);

            List<string> protectedNames = bindings.Where(IsProtectedAdapter).Select(b => b.Name).ToList();
            if (protectedNames.Count > 0 || GetTailscaleCliPath() != null || GetWarpCliPath() != null)
            {
                grid.AddRow("VPNs/overlays preservados", protectedNames.Count > 0
                    ? $"[green]{Markup.Escape(string.Join(", ", protectedNames))}[/] [grey](IPv6 mantido)[/]"
                    : "[grey]instalados, sem adaptador ativo[/]");
            }
            if (HasCloudflareWarp())
                grid.AddRow("Cloudflare WARP (conexão)", GetWarpConnectionMarkup());
            if (HasTailscale() || HasCloudflareWarp())
                grid.AddRow("Cloudflare WARP + Tailscale DNS", GetWarpTailscaleStatus());
            AnsiConsole.Write(grid);

            AnsiConsole.WriteLine();
            int ativos = bindings.Count(b => b.Enabled);
            int ativosNormais = bindings.Count(b => b.Enabled && !IsProtectedAdapter(b));

            var warnings = new List<string>();
            if (extra.FirewallRules > 0)
            {
                if (extra.FirewallActive < expectedRules)
                    warnings.Add("regras de firewall incompletas ou desativadas");
                if (!firewallEffective)
                    warnings.Add("Windows Firewall desativado/parcial — as regras não têm efeito");
                if (watchdogState is not null && watchdogState != WatchdogConfigurationState.Healthy)
                    warnings.Add("watchdog fora do estado saudável");
                else if (watchdogLastRunFailed)
                    warnings.Add("última execução do watchdog falhou");
            }
            if (rebootPending)
                warnings.Add("reinício pendente para o registro (DisabledComponents) valer");

            if (bindings.Count == 0)
            {
                AnsiConsole.MarkupLine("[grey]IPv6: nenhuma interface com binding encontrada — status indisponível[/]");
            }
            else if (ativosNormais > 0)
            {
                AnsiConsole.MarkupLine($"[bold red]IPv6: ATIVO em {ativosNormais} interface(s) não protegida(s)[/]");
            }
            else if (warnings.Count > 0)
            {
                AnsiConsole.MarkupLine("[bold yellow]IPv6: bloqueado nas interfaces, com ressalvas:[/]");
                foreach (string w in warnings)
                    AnsiConsole.MarkupLine($"  [yellow]•[/] {Markup.Escape(w)}");
            }
            else
            {
                AnsiConsole.MarkupLine(ativos == 0
                    ? "[bold green]IPv6: BLOQUEADO em todas as interfaces[/]"
                    : $"[bold green]IPv6: BLOQUEADO nas interfaces comuns[/] [grey](ativo só em VPN/overlay preservada: {Markup.Escape(string.Join(", ", protectedNames))})[/]");
            }
            AnsiConsole.WriteLine();
        }

        private static bool IsRebootPending(OriginalState? state, ExtraStatus extra) =>
            state?.RegistryWrittenUtc is { } written
            && DateTime.TryParse(extra.BootUtc, null, System.Globalization.DateTimeStyles.RoundtripKind, out DateTime boot)
            && boot.ToUniversalTime() < written;

        private static string GetWarpConnectionMarkup()
        {
            string? warpCli = GetWarpCliPath();
            if (warpCli == null)
                return "[grey]WARP CLI ausente[/]";
            try
            {
                string output = RunPowerShell($"& '{EscapePs(warpCli)}' status 2>&1 | Out-String");
                if (output.Contains("Disconnected", StringComparison.OrdinalIgnoreCase))
                    return "[grey]Desconectado[/]";
                if (output.Contains("Connecting", StringComparison.OrdinalIgnoreCase))
                    return "[yellow]Conectando…[/]";
                if (output.Contains("Connected", StringComparison.OrdinalIgnoreCase))
                    return "[green]Conectado (IPv6 do túnel preservado)[/]";
                return $"[grey]{Markup.Escape(Truncate(output, 60))}[/]";
            }
            catch (PowerShellException)
            {
                return "[grey]indisponível[/]";
            }
        }

        private static string StateMarkup(string raw) =>
            raw == "Disabled"
                ? "[green]Desativado[/]"
                : string.IsNullOrEmpty(raw) || raw == "?"
                    ? "[grey]não presente[/]"
                    : $"[red]{Markup.Escape(raw)}[/]";

        private static OriginalState EnsureState(bool full)
        {
            OriginalState? state = OriginalState.Load();
            if (state is null)
            {
                ExtraStatus extra = GetExtraStatus();
                // Regras IPV6Shutdown sem snapshot = máquina já alterada por versão antiga: o original é desconhecido.
                bool legacy = extra.FirewallRules > 0;
                state = new OriginalState { OriginalKnown = !legacy };
                if (!legacy)
                {
                    state.IpHelperStartType = NormalizeStartType(extra.IpHelperStart);
                    state.IpHelperWasRunning = extra.IpHelper == "Running";
                    state.DisabledComponentsPresent = extra.DisabledComponents != 0;
                    state.DisabledComponentsValue = extra.DisabledComponents;
                    foreach ((string key, string value) in new[]
                    {
                        ("Teredo", extra.Teredo), ("SixToFour", extra.SixToFour),
                        ("Isatap", extra.Isatap), ("IpHttps", extra.IpHttps)
                    })
                    {
                        if (IsSafeToken(value))
                            state.Tunnels[key] = value;
                    }
                }
            }

            foreach (string pattern in _cliProtect)
            {
                if (!state.CustomProtect.Contains(pattern, StringComparer.OrdinalIgnoreCase))
                    state.CustomProtect.Add(pattern);
            }
            if (full)
                state.Mode = "full";

            state.Save(); // grava antes de qualquer alteração: a reversão depende disso
            SetState(state);
            return state;
        }

        private static bool IsSafeToken(string? value) =>
            !string.IsNullOrEmpty(value) && value != "?" && value.All(char.IsAsciiLetter);

        private static string? NormalizeStartType(string value) =>
            value is "Automatic" or "Manual" or "Disabled" ? value : null;

        private static void RemoveEnforcement(StatusContext? ctx)
        {
            ctx?.Status("[grey]--nofirewall: removendo regras de firewall e watchdog anteriores...[/]");
            RunPowerShell($"""
                Stop-ScheduledTask -TaskName '{WatchdogTaskName}' -ErrorAction SilentlyContinue
                Unregister-ScheduledTask -TaskName '{WatchdogTaskName}' -Confirm:$false -ErrorAction SilentlyContinue
                Remove-NetFirewallRule -DisplayName 'IPV6Shutdown*' -ErrorAction SilentlyContinue
                """);
        }

        private static string BlockRuleCommand(string name, string direction) =>
            $"New-NetFirewallRule -DisplayName '{name}' -Direction {direction} -Action Block -RemoteAddress '{BlockedRemote}' -Enabled True | Out-Null";

        private static void DisableStandard(bool noFirewall, bool full = false)
        {
            bool preferIpv4RebootNeeded = false;
            var protectedNames = new List<string>();
            var reEnabledProtected = new List<string>();
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Desativando IPv6...[/]", ctx =>
            {
                OriginalState state = EnsureState(full);
                List<BindingInfo> bindings = GetBindings(fresh: true);
                protectedNames.AddRange(bindings.Where(IsProtectedAdapter).Select(b => b.Name));

                List<BindingInfo> toDisable = bindings.Where(b => b.Enabled && !IsProtectedAdapter(b)).ToList();
                if (toDisable.Count > 0)
                {
                    ctx.Status($"[grey]Desativando binding em[/] [bold]{Markup.Escape(string.Join(", ", toDisable.Select(b => b.Name)))}[/]");
                    RunBindingCommands(toDisable.Select(b =>
                        $"Disable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6"));
                    AssertBindings(toDisable.Select(b => b.Name), shouldBeEnabled: false,
                        "Falha ao desativar IPv6 nas interfaces");
                    foreach (BindingInfo b in toDisable)
                    {
                        if (!state.DisabledBindings.Contains(b.Name, StringComparer.OrdinalIgnoreCase))
                            state.DisabledBindings.Add(b.Name);
                    }
                    state.Save();
                }

                reEnabledProtected.AddRange(ProtectAdapters(ctx));

                ctx.Status("[grey]Gravando Prefer IPv4 (DisabledComponents | 0x20)...[/]");
                preferIpv4RebootNeeded = ApplyPreferIpv4Registry(state);
                if (HasTailscale() && HasCloudflareWarp())
                {
                    EnsureWarpTailscaleFallback(ctx, out _);
                }

                if (noFirewall)
                {
                    RemoveEnforcement(ctx);
                }
                else
                {
                    ctx.Status("[grey]Criando regras de firewall (IPv6, exceto loopback/link-local/Tailscale/WARP)...[/]");
                    EnsureFirewallRule(RuleSaida, BlockRuleCommand(RuleSaida, "Outbound"));
                    EnsureFirewallRule(RuleEntrada, BlockRuleCommand(RuleEntrada, "Inbound"));
                    EnsureWatchdogInstalled(ctx);
                }
                state.Save();
            });

            AnsiConsole.MarkupLine("[green]✔ IPv6 desativado nas interfaces" + (noFirewall ? ".[/]" : " e bloqueado no firewall.[/]"));
            if (protectedNames.Count > 0)
            {
                AnsiConsole.MarkupLine($"[green]✔ VPN/overlay preservada (IPv6 mantido):[/] {Markup.Escape(string.Join(", ", protectedNames))}");
            }
            if (reEnabledProtected.Count > 0)
            {
                AnsiConsole.MarkupLine($"[yellow]ℹ IPv6 reativado em VPN/overlay que o exige:[/] {Markup.Escape(string.Join(", ", reEnabledProtected))}");
            }
            if (HasTailscale() && HasCloudflareWarp())
            {
                AnsiConsole.MarkupLine("[green]✔ Cloudflare WARP + Tailscale MagicDNS: fallback *.ts.net verificado.[/]");
            }
            if (noFirewall)
            {
                AnsiConsole.MarkupLine("[grey]ℹ --nofirewall: regras de firewall e watchdog anteriores (se existiam) foram removidos.[/]");
            }
            else
            {
                AnsiConsole.MarkupLine($"[green]✔ Proteção contínua ativa — a tarefa '[bold]{WatchdogTaskName}[/]' reaplica no boot e a cada 2 minutos.[/]");
            }
            if (preferIpv4RebootNeeded)
            {
                AnsiConsole.Write(new Panel("[bold yellow]Prefer IPv4 (DisabledComponents 0x20) foi gravado no registro. Reinicie o computador para a pilha TCP/IP priorizar IPv4 em sites dual-stack.[/]")
                    .Header("[bold]Prefer IPv4 aplicado[/]")
                    .BorderColor(Color.Yellow));
            }
            AnsiConsole.WriteLine();
        }

        private static void DisableFull(bool noFirewall)
        {
            DisableStandard(noFirewall, full: true);

            OriginalState state = GetState() ?? EnsureState(full: true);
            bool regWritten = false;
            bool ipHelperSkipped = false;
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Aplicando bloqueios extras...[/]", ctx =>
            {
                ctx.Status("[grey]Desativando túneis Teredo/6to4/ISATAP/IP-HTTPS...[/]");
                RunPowerShell("""
                    Set-NetTeredoConfiguration -Type Disabled -ErrorAction SilentlyContinue
                    Set-Net6to4Configuration -State Disabled -ErrorAction SilentlyContinue
                    Set-NetIsatapConfiguration -State Disabled -ErrorAction SilentlyContinue
                    Set-NetIPHttpsConfiguration -State Disabled -ErrorAction SilentlyContinue
                    """);

                bool vpn = HasProtectedVpn();
                if (vpn)
                {
                    ctx.Status("[yellow]Pulando DisabledComponents=0xFF — desligaria o IPv6 da VPN/overlay[/]");
                }
                else
                {
                    ctx.Status("[grey]Gravando DisabledComponents = 0xFF no registro...[/]");
                    RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value 255 -Type DWord");
                    state.RegistryWrittenUtc = DateTime.UtcNow;
                    regWritten = true;
                }

                if (vpn)
                {
                    ctx.Status("[yellow]Pulando IP Helper — Tailscale/VPNs dependem de iphlpsvc[/]");
                    ipHelperSkipped = true;
                }
                else
                {
                    ctx.Status("[grey]Parando e desativando o serviço IP Helper...[/]");
                    RunPowerShell("Stop-Service iphlpsvc -Force -ErrorAction SilentlyContinue; Set-Service iphlpsvc -StartupType Disabled");
                }

                if (!noFirewall)
                {
                    ctx.Status("[grey]Bloqueando Teredo (UDP 3544) e 6in4 (protocolo 41) no firewall...[/]");
                    EnsureFirewallRule(RuleTeredo,
                        $"New-NetFirewallRule -DisplayName '{RuleTeredo}' -Direction Outbound -Action Block -Protocol UDP -RemotePort 3544 -Enabled True | Out-Null");
                    EnsureFirewallRule(Rule6in4,
                        $"New-NetFirewallRule -DisplayName '{Rule6in4}' -Direction Outbound -Action Block -Protocol 41 -Enabled True | Out-Null");
                }
                state.Save();
            });

            AnsiConsole.MarkupLine("[green]✔ Túneis de transição desativados" + (regWritten ? ", registro gravado" : "") + (ipHelperSkipped ? " e IP Helper preservado.[/]" : ", IP Helper parado.[/]"));
            AnsiConsole.WriteLine();
            if (regWritten)
            {
                AnsiConsole.Write(new Panel("[bold yellow]Reinicie o computador para o DisabledComponents (0xFF) surtir efeito completo na pilha TCP/IP.[/]")
                    .Header("[bold]Modo FULL aplicado[/]")
                    .BorderColor(Color.Yellow));
            }
            else
            {
                AnsiConsole.Write(new Panel("[bold yellow]DisabledComponents (0xFF) e o serviço IP Helper não foram alterados porque uma VPN/overlay (Tailscale, Cloudflare WARP, WireGuard…) foi detectada: o primeiro desligaria o IPv6 privado dela, e o segundo pararia serviços que dependem do iphlpsvc. Nenhuma reinicialização é necessária por estes motivos.[/]")
                    .Header("[bold]Modo FULL aplicado (VPN protegida)[/]")
                    .BorderColor(Color.Yellow));
            }
            AnsiConsole.WriteLine();
        }

        private static void EnsureWatchdogInstalled(StatusContext? ctx)
        {
            try
            {
                InstallWatchdog(ctx);
                VerifyWatchdogTask();
            }
            catch (PowerShellException ex)
            {
                throw new PowerShellException(PsError.ExitCode, EnhanceWatchdogInstallError(ex.Message), ex);
            }
        }

        private static void InstallWatchdog(StatusContext? ctx)
        {
            ctx?.Status("[grey]Instalando tarefa de proteção contínua (a cada 2 min)...[/]");
            string patternList = string.Join(", ", ProtectPatterns().Select(p => $"'{EscapePs(p)}'"));
            string fullRules = GetState()?.Mode == "full"
                ? $$"""
                    Ensure-BlockRule '{{RuleTeredo}}' @{ Direction = 'Outbound'; Protocol = 'UDP'; RemotePort = '3544' }
                    Ensure-BlockRule '{{Rule6in4}}' @{ Direction = 'Outbound'; Protocol = '41' }
                    """
                : string.Empty;

            // O script só mexe no que está errado (bindings ativos fora da lista protegida, regras ausentes/desativadas)
            // e usa a mesma lista de VPNs protegidas do aplicativo — assim não briga com WARP/Tailscale/etc.
            string script = $$"""
                # {{WatchdogTaskValidation.ScriptMarker}}
                $ErrorActionPreference = 'Continue'
                $protect = @({{patternList}})
                Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {
                    if (-not $_.Enabled) { return $false }
                    $text = ("$($_.Name) $($_.InterfaceDescription)").ToLowerInvariant()
                    foreach ($p in $protect) { if ($text.Contains($p)) { return $false } }
                    return $true
                } | ForEach-Object {
                    Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                }
                function Ensure-BlockRule($name, $extra) {
                    $ok = @(Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Where-Object { $_.Enabled -eq 'True' -and $_.Action -eq 'Block' })
                    if ($ok.Count -gt 0) { return }
                    Remove-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue
                    $params = @{ DisplayName = $name; Action = 'Block'; Enabled = 'True' } + $extra
                    New-NetFirewallRule @params | Out-Null
                }
                $remote = '{{BlockedRemote}}'
                Ensure-BlockRule '{{RuleSaida}}' @{ Direction = 'Outbound'; RemoteAddress = $remote }
                Ensure-BlockRule '{{RuleEntrada}}' @{ Direction = 'Inbound'; RemoteAddress = $remote }
                {{fullRules}}
                """;
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            RunPowerShell($"""
                Unregister-ScheduledTask -TaskName '{WatchdogTaskName}' -Confirm:$false -ErrorAction SilentlyContinue
                $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
                $action = New-ScheduledTaskAction -Execute $exe -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded}'
                $startupTrigger = New-ScheduledTaskTrigger -AtStartup
                $periodicTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 2)
                $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 10) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
                Register-ScheduledTask -TaskName '{WatchdogTaskName}' -Action $action -Trigger @($startupTrigger, $periodicTrigger) -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
                """);
        }

        private static void VerifyWatchdogTask()
        {
            WatchdogConfigurationResult result =
                WatchdogTaskValidation.EvaluateConfiguration(GetWatchdogTaskSnapshot());

            if (result.State != WatchdogConfigurationState.Healthy)
            {
                throw new PowerShellException(PsError.ExitCode,
                    $"Verificação do watchdog falhou: {result.Reason}");
            }
        }

        private static WatchdogTaskSnapshot GetWatchdogTaskSnapshot() =>
            GetWatchdogTaskSnapshot(out _);

        private static WatchdogTaskSnapshot GetWatchdogTaskSnapshot(out WatchdogRunInfo run)
        {
            string json = RunPowerShell($$"""
                $ErrorActionPreference = 'Stop'
                $task = Get-ScheduledTask -TaskName '{{WatchdogTaskName}}' -ErrorAction SilentlyContinue

                if ($null -eq $task) {
                    [ordered]@{
                        Exists = $false
                        Enabled = $false
                        HasStartupTrigger = $false
                        Interval = ''
                        Duration = ''
                        StartWhenAvailable = $false
                        UserId = ''
                        RunLevel = ''
                        ActionExecute = ''
                        ActionArguments = ''
                        LastRun = ''
                        LastResult = 0
                    } | ConvertTo-Json -Compress
                    return
                }

                $triggers = @($task.Triggers)
                $periodic = $triggers | Where-Object {
                    $_.Repetition -and -not [string]::IsNullOrWhiteSpace([string]$_.Repetition.Interval)
                } | Select-Object -First 1
                $hasStartup = @($triggers | Where-Object {
                    $_.CimClass.CimClassName -eq 'MSFT_TaskBootTrigger'
                }).Count -gt 0

                $interval = ''
                $duration = ''
                if ($periodic) {
                    $interval = [string]$periodic.Repetition.Interval
                    $duration = [string]$periodic.Repetition.Duration
                }

                $action = $task.Actions | Select-Object -First 1
                $actionExecute = if ($action) { [string]$action.Execute } else { '' }
                $actionArguments = if ($action) { [string]$action.Arguments } else { '' }

                $info = Get-ScheduledTaskInfo -InputObject $task -ErrorAction SilentlyContinue
                $lastRun = ''
                $lastResult = [int64]0
                if ($info) {
                    if ($info.LastRunTime) { $lastRun = $info.LastRunTime.ToString('s') }
                    $lastResult = [int64]$info.LastTaskResult
                }

                [ordered]@{
                    Exists = $true
                    Enabled = ([string]$task.State -ne 'Disabled')
                    HasStartupTrigger = [bool]$hasStartup
                    Interval = $interval
                    Duration = $duration
                    StartWhenAvailable = [bool]$task.Settings.StartWhenAvailable
                    UserId = [string]$task.Principal.UserId
                    RunLevel = [string]$task.Principal.RunLevel
                    ActionExecute = $actionExecute
                    ActionArguments = $actionArguments
                    LastRun = $lastRun
                    LastResult = $lastResult
                } | ConvertTo-Json -Compress
                """);

            json = ExtractJsonPayload(json);
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;
                run = new WatchdogRunInfo(
                    root.TryGetProperty("LastRun", out JsonElement lr) ? lr.GetString() ?? string.Empty : string.Empty,
                    root.TryGetProperty("LastResult", out JsonElement res) && res.TryGetInt64(out long code) ? code : 0);
                return new WatchdogTaskSnapshot(
                    root.GetProperty("Exists").GetBoolean(),
                    root.GetProperty("Enabled").GetBoolean(),
                    root.GetProperty("HasStartupTrigger").GetBoolean(),
                    root.GetProperty("Interval").GetString() ?? string.Empty,
                    root.GetProperty("Duration").GetString() ?? string.Empty,
                    root.GetProperty("StartWhenAvailable").GetBoolean(),
                    root.GetProperty("UserId").GetString() ?? string.Empty,
                    root.GetProperty("RunLevel").GetString() ?? string.Empty,
                    root.GetProperty("ActionExecute").GetString() ?? string.Empty,
                    root.GetProperty("ActionArguments").GetString() ?? string.Empty);
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                throw new PowerShellException(PsError.ExitCode,
                    $"Verificação do watchdog falhou: resposta inválida do Agendador de Tarefas ({ex.Message}).", ex);
            }
        }

        private static (WatchdogConfigurationState? State, string Markup, bool LastRunFailed) GetWatchdogStatus()
        {
            try
            {
                WatchdogConfigurationResult result =
                    WatchdogTaskValidation.EvaluateConfiguration(GetWatchdogTaskSnapshot(out WatchdogRunInfo run));

                switch (result.State)
                {
                    case WatchdogConfigurationState.Healthy:
                        // 0 = ok · 0x41303 = nunca executou · 0x41301 = executando · 0x41306 = encerrada pelo limite de tempo
                        string last = run.LastResult switch
                        {
                            0 => $"última execução OK{(run.LastRun.Length > 0 ? $" ({Markup.Escape(run.LastRun.Replace('T', ' '))})" : "")}",
                            0x41303 => "ainda não executou",
                            0x41301 => "em execução agora",
                            _ => $"[yellow]última execução falhou (0x{run.LastResult:X})[/]"
                        };
                        bool failed = run.LastResult is not (0 or 0x41303 or 0x41301);
                        return (result.State, $"[green]ativa — boot + a cada 2 min[/] · {last}", failed);
                    case WatchdogConfigurationState.Missing:
                        return (result.State, "[grey]ausente[/]", false);
                    case WatchdogConfigurationState.Disabled:
                        return (result.State, "[red]desativada no Agendador de Tarefas[/]", false);
                    default:
                        return (result.State, $"[yellow]configuração inválida — {Markup.Escape(result.Reason)}[/]", false);
                }
            }
            catch (PowerShellException ex)
            {
                return (null, $"[red]erro ao consultar — {Markup.Escape(ex.Message)}[/]", false);
            }
        }

        private static string EnhanceWatchdogInstallError(string message)
        {
            if (WatchdogTaskValidation.IsInvalidTaskDurationError(message))
                return "Não foi possível instalar a proteção contínua (tarefa agendada no Windows). "
                     + "O Agendador de Tarefas rejeitou a configuração da tarefa — geralmente por um valor de duração inválido no XML da tarefa. "
                     + "Baixe ou compile a versão mais recente do IPV6Shutdown e execute novamente como Administrador. "
                     + $"Detalhes: {message}";
            if (message.Contains("acesso negado", StringComparison.OrdinalIgnoreCase)
                || message.Contains("Access is denied", StringComparison.OrdinalIgnoreCase))
                return $"Falha ao instalar a proteção contínua: permissão insuficiente. Execute o IPV6Shutdown como Administrador. Detalhes: {message}";
            return $"Falha ao instalar a proteção contínua (tarefa agendada). Execute como Administrador se o problema persistir. Detalhes: {message}";
        }

        private static void Revert()
        {
            bool rebootNeeded = false;
            bool usedFallback = false;
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Revertendo...[/]", ctx =>
            {
                OriginalState? state = OriginalState.Load();
                bool known = state is { OriginalKnown: true };
                usedFallback = !known;

                // Com snapshot: só reativa o que ESTA ferramenta desativou. Sem snapshot (versão antiga): comportamento legado.
                List<BindingInfo> Candidates() => GetBindings(fresh: true)
                    .Where(b => !b.Enabled
                        && (!known || state!.DisabledBindings.Contains(b.Name, StringComparer.OrdinalIgnoreCase)))
                    .ToList();

                ctx.Status("[grey]Removendo tarefa de proteção contínua...[/]");
                RunPowerShell($"""
                    Stop-ScheduledTask -TaskName '{WatchdogTaskName}' -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName '{WatchdogTaskName}' -Confirm:$false -ErrorAction SilentlyContinue
                    """);

                ctx.Status("[grey]Reativando bindings IPv6...[/]");
                List<BindingInfo> disabled = Candidates();
                EnableBindings(disabled);

                ctx.Status("[grey]Removendo regras de firewall...[/]");
                RunPowerShell("Remove-NetFirewallRule -DisplayName 'IPV6Shutdown*' -ErrorAction SilentlyContinue");

                ctx.Status("[grey]Restaurando túneis de transição...[/]");
                string TunnelValue(string key) =>
                    known && state!.Tunnels.TryGetValue(key, out string? v) && IsSafeToken(v) ? v : "Default";
                string teredo = TunnelValue("Teredo");
                string sixToFour = TunnelValue("SixToFour");
                string isatap = TunnelValue("Isatap");
                string ipHttps = TunnelValue("IpHttps");
                RunPowerShell($"""
                    Set-NetTeredoConfiguration -Type {teredo} -ErrorAction SilentlyContinue
                    Set-Net6to4Configuration -State {sixToFour} -ErrorAction SilentlyContinue
                    Set-NetIsatapConfiguration -State {isatap} -ErrorAction SilentlyContinue
                    Set-NetIPHttpsConfiguration -State {ipHttps} -ErrorAction SilentlyContinue
                    """);

                ctx.Status("[grey]Restaurando registro DisabledComponents...[/]");
                if (RestoreDisabledComponents(known ? state : null))
                    rebootNeeded = true;

                ctx.Status("[grey]Restaurando serviço IP Helper...[/]");
                string? ipHelperType = known ? NormalizeStartType(state!.IpHelperStartType ?? string.Empty) : null;
                if (ipHelperType is not null)
                {
                    RunPowerShell($"Set-Service iphlpsvc -StartupType {ipHelperType}"
                        + (state!.IpHelperWasRunning ? "; Start-Service iphlpsvc -ErrorAction SilentlyContinue" : ""));
                }
                else
                {
                    // Sem original conhecido: só mexe se o serviço estiver desabilitado (provável efeito do modo FULL antigo).
                    RunPowerShell("if ((Get-Service iphlpsvc).StartType -eq 'Disabled') { Set-Service iphlpsvc -StartupType Automatic; Start-Service iphlpsvc -ErrorAction SilentlyContinue }");
                }

                ctx.Status("[grey]Reaplicando bindings IPv6 (replay contra watchdog em voo)...[/]");
                List<BindingInfo> stillDisabled = Candidates();
                EnableBindings(stillDisabled);
                RunPowerShell("Remove-NetFirewallRule -DisplayName 'IPV6Shutdown*' -ErrorAction SilentlyContinue");
                IEnumerable<string> replayNames = disabled.Select(b => b.Name)
                    .Concat(stillDisabled.Select(b => b.Name))
                    .Distinct(StringComparer.OrdinalIgnoreCase);
                AssertBindings(replayNames, shouldBeEnabled: true,
                    "Falha ao reativar IPv6 nas interfaces");

                OriginalState.Delete();
                SetState(null);
            });

            AnsiConsole.MarkupLine("[green]✔ IPv6 reativado, bloqueios e proteção contínua removidos.[/]");
            if (usedFallback)
            {
                AnsiConsole.MarkupLine("[yellow]ℹ Nenhum snapshot do estado original foi encontrado (instalação anterior à v1.4.0): todos os bindings desativados foram reativados e os padrões do Windows restaurados.[/]");
            }
            AnsiConsole.WriteLine();
            if (rebootNeeded)
            {
                AnsiConsole.Write(new Panel("[bold yellow]O valor DisabledComponents foi restaurado no registro. Reinicie o computador para a pilha TCP/IP voltar ao estado original.[/]")
                    .Header("[bold]Reversão concluída[/]")
                    .BorderColor(Color.Yellow));
                AnsiConsole.WriteLine();
            }
        }

        /// <summary>Restaura DisabledComponents ao valor original gravado; sem original, só desfaz o que a ferramenta grava (0x20/0xFF).</summary>
        private static bool RestoreDisabledComponents(OriginalState? original)
        {
            int? current = ReadDisabledComponents();
            if (current is null)
                return false;

            if (original is { DisabledComponentsPresent: true } o)
            {
                if (current == o.DisabledComponentsValue)
                    return false;
                if (current == (o.DisabledComponentsValue | DisabledComponentsPolicy.PreferIpv4)
                    || current == DisabledComponentsPolicy.DisableAll)
                {
                    RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value {o.DisabledComponentsValue} -Type DWord");
                    return true;
                }
            }

            (int? newValue, bool removeProperty, bool changed) = DisabledComponentsPolicy.RevertPreferIpv4(current.Value);
            if (!changed)
                return false;
            if (removeProperty)
                RunPowerShell($"Remove-ItemProperty -Path '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue");
            else
                RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value {newValue!.Value} -Type DWord");
            return true;
        }

        private static void EnableBindings(List<BindingInfo> adapters)
        {
            if (adapters.Count == 0)
                return;
            RunBindingCommands(adapters.Select(b =>
                $"Enable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6"));
        }

        private static bool IsAdministrator()
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string QuoteArg(string arg) =>
            arg.Length == 0 || arg.Contains(' ') ? $"\"{arg}\"" : arg;

        private static void SafePause()
        {
            try
            {
                Console.ReadKey(intercept: true);
            }
            catch (Exception ex) when (ex is InvalidOperationException or IOException)
            {
            }
        }

        private static string EscapePs(string value) => value.Replace("'", "''");

        private static void RunBindingCommands(IEnumerable<string> commands)
        {
            List<string> list = commands.ToList();
            for (int i = 0; i < list.Count; i += BindingBatchSize)
                RunPowerShell(string.Join(Environment.NewLine, list.Skip(i).Take(BindingBatchSize)));
            InvalidateBindings();
        }

        private static void AssertBindings(IEnumerable<string> names, bool shouldBeEnabled, string failureMessage)
        {
            var expected = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
            if (expected.Count == 0)
                return;
            List<string> mismatches = GetBindings(fresh: true)
                .Where(b => expected.Contains(b.Name) && b.Enabled != shouldBeEnabled)
                .Select(b => b.Name)
                .ToList();
            if (mismatches.Count > 0)
            {
                throw new PowerShellException(PsError.ExitCode,
                    $"{failureMessage}: {string.Join(", ", mismatches)}");
            }
        }

        private static string RunPowerShell(string command)
        {
            string script = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;" + command;
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            var psi = new ProcessStartInfo
            {
                FileName = PowerShellExe,
                Arguments = $"-NoProfile -NonInteractive -NoLogo -EncodedCommand {encoded}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };
            Process process;
            try
            {
                process = Process.Start(psi)
                    ?? throw new PowerShellException(PsError.NotFound, "Não foi possível iniciar o powershell.exe.");
            }
            catch (Win32Exception ex)
            {
                throw new PowerShellException(PsError.NotFound,
                    $"Não foi possível iniciar o powershell.exe: {ex.Message}", ex);
            }

            using (process)
            {
                Task<string> stdoutTask = process.StandardOutput.ReadToEndAsync();
                Task<string> stderrTask = process.StandardError.ReadToEndAsync();

                if (!process.WaitForExit(PsTimeoutMs))
                {
                    try
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                    {
                    }
                    try
                    {
                        process.WaitForExit(KillWaitMs);
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                    {
                    }
                    try
                    {
                        Task.WaitAll([stdoutTask, stderrTask], KillWaitMs);
                    }
                    catch (Exception ex) when (ex is AggregateException or IOException)
                    {
                    }
                    throw new PowerShellException(PsError.Timeout,
                        $"PowerShell não respondeu em {PsTimeoutMs / 1000}s — comando abortado: {Truncate(command, 120)}");
                }

                string stdout, stderr;
                try
                {
                    Task.WaitAll(stdoutTask, stderrTask);
                    stdout = stdoutTask.Result;
                    stderr = stderrTask.Result;
                }
                catch (Exception ex) when (ex is AggregateException or IOException)
                {
                    throw new PowerShellException(PsError.ExitCode,
                        $"Falha ao ler a saída do PowerShell: {ex.GetBaseException().Message}");
                }
                if (process.ExitCode != 0)
                {
                    throw new PowerShellException(PsError.ExitCode,
                        $"PowerShell saiu com código {process.ExitCode}: {CleanStderr(stderr)}");
                }
                return stdout.Trim();
            }
        }

        private static string CleanStderr(string stderr)
        {
            if (string.IsNullOrWhiteSpace(stderr))
                return "sem detalhes no stderr.";
            string clean = stderr.StartsWith("#< CLIXML", StringComparison.Ordinal)
                ? string.Join(' ', Regex.Matches(stderr, @"<S S=""Error"">(.*?)</S>", RegexOptions.Singleline)
                    .Select(m => m.Groups[1].Value))
                : stderr;
            clean = clean.Replace("_x000D__x000A_", " ").ReplaceLineEndings(" ").Trim();
            const int maxLen = 300;
            if (clean.Length <= maxLen)
                return clean;
            if (WatchdogTaskValidation.IsInvalidTaskDurationError(clean))
                return TruncatePreservingTokens(clean, maxLen, "P99999999", "Duration:");
            return clean[..maxLen] + "…";
        }

        private static string TruncatePreservingTokens(string text, int maxLen, params string[] tokens)
        {
            foreach (string token in tokens)
            {
                int idx = text.IndexOf(token, StringComparison.OrdinalIgnoreCase);
                if (idx < 0)
                    continue;
                int start = Math.Max(0, idx - 40);
                string slice = text[start..];
                return slice.Length > maxLen ? slice[..maxLen] + "…" : slice;
            }
            return text[..maxLen] + "…";
        }

        private static string Truncate(string text, int max)
        {
            text = text.ReplaceLineEndings(" ").Trim();
            return text.Length > max ? text[..max] + "…" : text;
        }

        private static void RenderError(PowerShellException ex)
        {
            AnsiConsole.Write(new Panel($"[red]Código {ex.Code} — {Markup.Escape(ex.Message)}[/]")
                .Header("[red]Falha no PowerShell[/]")
                .BorderColor(Color.Red));
            AnsiConsole.WriteLine();
        }

        private static void RenderUnexpected(Exception ex)
        {
            AnsiConsole.Write(new Panel($"[red]Código 199 — {Markup.Escape($"{ex.GetType().Name}: {ex.Message}")}[/]")
                .Header("[red]Erro inesperado[/]")
                .BorderColor(Color.Red));
            AnsiConsole.WriteLine();
        }

        private enum PsError { NotFound = 101, Timeout = 102, ExitCode = 103 }

        private sealed class PowerShellException : Exception
        {
            public int Code { get; }
            public PowerShellException(PsError code, string message, Exception? inner = null)
                : base(message, inner) => Code = (int)code;
        }

        private static string ExtractJsonPayload(string raw)
        {
            int firstBrace = raw.IndexOf('{');
            int firstBracket = raw.IndexOf('[');
            if (firstBrace == -1 && firstBracket == -1)
            {
                throw new PowerShellException(PsError.ExitCode,
                    "PowerShell não retornou JSON.");
            }
            int start = (firstBrace != -1 && firstBracket != -1)
                ? Math.Min(firstBrace, firstBracket)
                : (firstBrace != -1 ? firstBrace : firstBracket);
            return raw[start..];
        }

        private static void InvalidateBindings() => _bindingsCache = null;

        private static List<BindingInfo> GetBindings(bool fresh = false)
        {
            if (!fresh && _bindingsCache is not null)
                return _bindingsCache;

            string json = RunPowerShell("""
                $ErrorActionPreference = 'SilentlyContinue'
                $adapters = @{}
                Get-NetAdapter | ForEach-Object { $adapters[$_.Name] = $_ }
                $counts = @{}
                Get-NetIPAddress -AddressFamily IPv6 | Where-Object {
                    $_.IPAddress -notlike 'fe80*' -and $_.IPAddress -ne '::1' -and [string]$_.AddressState -eq 'Preferred'
                } | Group-Object InterfaceAlias | ForEach-Object { $counts[$_.Name] = $_.Count }
                Get-NetAdapterBinding -ComponentID ms_tcpip6 | ForEach-Object {
                    $a = $adapters[$_.Name]
                    [pscustomobject]@{
                        Name = $_.Name
                        InterfaceDescription = $_.InterfaceDescription
                        Enabled = [bool]$_.Enabled
                        Hardware = [bool]($a -and $a.HardwareInterface)
                        Status = $(if ($a) { [string]$a.Status } else { '' })
                        Ipv6 = [int]$counts[$_.Name]
                    }
                } | ConvertTo-Json -Compress
                """);
            var list = new List<BindingInfo>();
            if (!string.IsNullOrWhiteSpace(json))
            {
                json = ExtractJsonPayload(json);
                try
                {
                    using JsonDocument doc = JsonDocument.Parse(json);
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        list.AddRange(doc.RootElement.EnumerateArray().Select(ParseBinding));
                    else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                        list.Add(ParseBinding(doc.RootElement));
                }
                catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
                {
                    throw new PowerShellException(PsError.ExitCode,
                        $"JSON de bindings inválido: {ex.Message}", ex);
                }
            }
            _bindingsCache = list.OrderBy(b => b.Name, StringComparer.OrdinalIgnoreCase).ToList();
            return _bindingsCache;
        }

        private static BindingInfo ParseBinding(JsonElement el) =>
            new(el.GetProperty("Name").GetString() ?? string.Empty,
                el.GetProperty("InterfaceDescription").GetString() ?? string.Empty,
                el.GetProperty("Enabled").GetBoolean(),
                el.TryGetProperty("Hardware", out JsonElement hw) && hw.ValueKind == JsonValueKind.True,
                el.TryGetProperty("Status", out JsonElement st) ? st.GetString() ?? string.Empty : string.Empty,
                el.TryGetProperty("Ipv6", out JsonElement ips) && ips.TryGetInt32(out int n) ? n : 0);

        private static ExtraStatus GetExtraStatus()
        {
            string json = RunPowerShell($$"""
                $ErrorActionPreference = 'SilentlyContinue'
                $rules = @(Get-NetFirewallRule -DisplayName 'IPV6Shutdown*')
                $o = [ordered]@{
                  Teredo = "$((Get-NetTeredoConfiguration).Type)"
                  SixToFour = "$((Get-Net6to4Configuration).State)"
                  Isatap = "$((Get-NetIsatapConfiguration).State)"
                  IpHttps = "$((Get-NetIPHttpsConfiguration).State)"
                  DisabledComponents = (Get-ItemProperty '{{RegPath}}' -Name DisabledComponents).DisabledComponents
                  IpHelper = "$((Get-Service iphlpsvc).Status)"
                  IpHelperStart = "$((Get-Service iphlpsvc).StartType)"
                  FirewallRules = $rules.Count
                  FirewallActive = @($rules | Where-Object { [string]$_.Enabled -eq 'True' -and [string]$_.Action -eq 'Block' }).Count
                  FirewallProfilesOff = @(Get-NetFirewallProfile | Where-Object { [string]$_.Enabled -eq 'False' }).Count
                  FirewallService = "$((Get-Service mpssvc).Status)"
                  BootUtc = "$((Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('o'))"
                }
                $o | ConvertTo-Json -Compress
                """);
            json = ExtractJsonPayload(json);
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement r = doc.RootElement;
                JsonElement dc = r.GetProperty("DisabledComponents");
                return new ExtraStatus(
                    r.GetProperty("Teredo").GetString() ?? "?",
                    r.GetProperty("SixToFour").GetString() ?? "?",
                    r.GetProperty("Isatap").GetString() ?? "?",
                    r.GetProperty("IpHttps").GetString() ?? "?",
                    dc.ValueKind == JsonValueKind.Number && dc.TryGetInt32(out int disabledComponentsValue) ? disabledComponentsValue : 0,
                    r.GetProperty("IpHelper").GetString() ?? "?",
                    r.GetProperty("IpHelperStart").GetString() ?? "?",
                    r.GetProperty("FirewallRules").GetInt32(),
                    r.GetProperty("FirewallActive").GetInt32(),
                    r.GetProperty("FirewallProfilesOff").GetInt32(),
                    r.GetProperty("FirewallService").GetString() ?? "?",
                    r.GetProperty("BootUtc").GetString() ?? string.Empty);
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                throw new PowerShellException(PsError.ExitCode,
                    $"JSON de status extra inválido: {ex.Message}", ex);
            }
        }

        private static bool ApplyPreferIpv4Registry(OriginalState state)
        {
            int current = ReadDisabledComponents() ?? 0;
            (int newValue, bool newlySet) = DisabledComponentsPolicy.ApplyPreferIpv4(current);
            if (!newlySet)
                return false;
            RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value {newValue} -Type DWord");
            state.RegistryWrittenUtc = DateTime.UtcNow;
            return true;
        }

        /// <summary>Valor atual de DisabledComponents, ou null se o valor não existe no registro.</summary>
        private static int? ReadDisabledComponents()
        {
            string raw = RunPowerShell(
                $"$v = (Get-ItemProperty '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue).DisabledComponents; if ($null -ne $v) {{ [int]$v }}");
            return int.TryParse(raw.Trim(), out int value) ? value : null;
        }

        private static void EnsureFirewallRule(string displayName, string createCommand)
        {
            RunPowerShell($"Remove-NetFirewallRule -DisplayName '{EscapePs(displayName)}' -ErrorAction SilentlyContinue; {createCommand}");
        }

        private static bool IsTailscaleAdapter(BindingInfo b) =>
            b.Name.Contains("Tailscale", StringComparison.OrdinalIgnoreCase) ||
            b.Description.Contains("Tailscale", StringComparison.OrdinalIgnoreCase);

        private static string? GetTailscaleCliPath()
        {
            string[] candidates =
            [
                @"C:\Program Files\Tailscale\tailscale.exe",
                @"C:\Program Files (x86)\Tailscale\tailscale.exe"
            ];
            return candidates.FirstOrDefault(File.Exists);
        }

        private static bool HasTailscale() =>
            GetBindings().Any(IsTailscaleAdapter) || GetTailscaleCliPath() != null;

        private static string? GetWarpCliPath()
        {
            string defaultPath = @"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe";
            if (File.Exists(defaultPath))
                return defaultPath;

            string localAppData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Cloudflare\Cloudflare WARP\warp-cli.exe");
            if (File.Exists(localAppData))
                return localAppData;

            return null;
        }

        private static bool HasCloudflareWarp() => GetWarpCliPath() != null;

        private static bool EnsureWarpTailscaleFallback(StatusContext? ctx, out bool changed)
        {
            changed = false;
            if (!HasTailscale() || !HasCloudflareWarp())
                return false;

            string? warpCli = GetWarpCliPath();
            if (warpCli == null)
                return false;

            ctx?.Status("[grey]Verificando integração Cloudflare WARP + Tailscale MagicDNS...[/]");
            string listOutput = RunPowerShell($"& '{EscapePs(warpCli)}' dns fallback list");

            if (!listOutput.Contains("ts.net", StringComparison.OrdinalIgnoreCase))
            {
                ctx?.Status("[grey]Adicionando fallback 'ts.net' (*.ts.net) no Cloudflare WARP...[/]");
                RunPowerShell($"& '{EscapePs(warpCli)}' dns fallback add ts.net");
                changed = true;
            }

            // Tenta descobrir o sufixo específico da tailnet atual para garantir resolução completa
            try
            {
                string? tailscaleCli = GetTailscaleCliPath();
                string tsStatus = tailscaleCli == null
                    ? string.Empty
                    : RunPowerShell($"& '{EscapePs(tailscaleCli)}' status --json; if ($LASTEXITCODE -ne 0) {{ exit $LASTEXITCODE }}");
                if (!string.IsNullOrWhiteSpace(tsStatus) && tsStatus.Contains("MagicDNSSuffix", StringComparison.OrdinalIgnoreCase))
                {
                    using JsonDocument doc = JsonDocument.Parse(ExtractJsonPayload(tsStatus));
                    if (doc.RootElement.TryGetProperty("MagicDNSSuffix", out JsonElement suffixEl))
                    {
                        string? suffix = suffixEl.GetString()?.Trim().TrimEnd('.');
                        if (!string.IsNullOrWhiteSpace(suffix) && !listOutput.Contains(suffix, StringComparison.OrdinalIgnoreCase))
                        {
                            ctx?.Status($"[grey]Adicionando fallback '{Markup.Escape(suffix)}' no Cloudflare WARP...[/]");
                            RunPowerShell($"& '{EscapePs(warpCli)}' dns fallback add {EscapePs(suffix)}");
                            changed = true;
                        }
                    }
                }
            }
            catch
            {
                // ts.net já cobre *.ts.net universalmente
            }

            if (changed)
            {
                RunPowerShell("ipconfig /flushdns");
            }

            return true;
        }

        private static void FixWarpTailscaleStandalone()
        {
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Configurando integração Cloudflare WARP + Tailscale...[/]", ctx =>
            {
                if (!HasTailscale())
                {
                    AnsiConsole.MarkupLine("[yellow]Tailscale não foi detectado neste computador.[/]");
                    return;
                }
                if (!HasCloudflareWarp())
                {
                    AnsiConsole.MarkupLine("[yellow]Cloudflare WARP não foi detectado neste computador.[/]");
                    return;
                }
                EnsureWarpTailscaleFallback(ctx, out bool changed);
                if (changed)
                    AnsiConsole.MarkupLine("[green]✔ Fallback de DNS para todas as redes Tailscale (*.ts.net + ts.net) adicionado com sucesso no Cloudflare WARP.[/]");
                else
                    AnsiConsole.MarkupLine("[green]✔ O fallback para Tailscale (*.ts.net + ts.net) já está ativo e configurado no Cloudflare WARP.[/]");
            });
            AnsiConsole.WriteLine();
        }

        private static string GetWarpTailscaleStatus()
        {
            if (!HasTailscale() && !HasCloudflareWarp())
                return "[grey]não detectados[/]";
            if (!HasTailscale())
                return "[grey]Tailscale ausente[/]";
            if (!HasCloudflareWarp())
                return "[grey]Cloudflare WARP ausente[/]";

            string? warpCli = GetWarpCliPath();
            if (warpCli == null)
                return "[grey]WARP CLI ausente[/]";

            try
            {
                string listOutput = RunPowerShell($"& '{EscapePs(warpCli)}' dns fallback list");
                if (listOutput.Contains("ts.net", StringComparison.OrdinalIgnoreCase))
                    return "[green]Ativo (*.ts.net liberado no WARP)[/]";
                return "[yellow]Pendente (conflito — falta ts.net)[/]";
            }
            catch
            {
                return "[red]Erro ao consultar WARP[/]";
            }
        }

        /// <summary>Garante o IPv6 ligado nas VPNs/overlays protegidas (WARP, Tailscale…). Retorna as que precisaram ser religadas.</summary>
        private static List<string> ProtectAdapters(StatusContext? ctx)
        {
            List<BindingInfo> off = GetBindings(fresh: true).Where(b => IsProtectedAdapter(b) && !b.Enabled).ToList();
            if (off.Count == 0)
                return [];
            ctx?.Status($"[grey]Mantendo IPv6 na VPN/overlay[/] [bold]{Markup.Escape(off[0].Name)}[/]");
            RunBindingCommands(off.Select(b =>
                $"Enable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6"));
            AssertBindings(off.Select(b => b.Name), shouldBeEnabled: true,
                "Falha ao preservar IPv6 na VPN/overlay");
            return off.Select(b => b.Name).ToList();
        }

        private static void ShowHelp()
        {
            RenderHeader();
            AnsiConsole.MarkupLine("[bold]Uso:[/] IPV6Shutdown [[opções]]");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("  [grey](sem opções)[/]       Abre o menu interativo.");
            AnsiConsole.MarkupLine("  [grey]--disable[/]          Desativa o IPv6 (bindings + firewall) e prefere IPv4 (0x20).");
            AnsiConsole.MarkupLine("                     IPv6 da Tailscale preservado.");
            AnsiConsole.MarkupLine("  [grey]--full[/]             Modo completo: bindings + firewall + túneis de transição");
            AnsiConsole.MarkupLine("                     (Teredo/6to4/ISATAP/IP-HTTPS) + DisabledComponents=0xFF + IP Helper.");
            AnsiConsole.MarkupLine("  [grey]-w, --warp-tailscale[/] Resolve conflito Cloudflare WARP + Tailscale: adiciona o fallback");
            AnsiConsole.MarkupLine("                     de DNS (*.ts.net + ts.net) no WARP para o MagicDNS funcionar.");
            AnsiConsole.MarkupLine("  [grey]-e, --enable[/]       Reverte tudo: reativa o IPv6 e remove todos os bloqueios.");
            AnsiConsole.MarkupLine("  [grey]-s, --status[/]       Apenas mostra o status (não precisa de Administrador).");
            AnsiConsole.MarkupLine("  [grey]--nofirewall[/]       Não cria regras de firewall nem watchdog (e remove os anteriores).");
            AnsiConsole.MarkupLine("  [grey]--protect <texto>[/]  Preserva o IPv6 de adaptadores cujo nome/descrição contenham o texto");
            AnsiConsole.MarkupLine("                     (pode repetir; fica salvo e vale também para o watchdog).");
            AnsiConsole.MarkupLine("                     Já protegidos: Tailscale, Cloudflare WARP, WireGuard, OpenVPN/TAP, NordLynx,");
            AnsiConsole.MarkupLine("                     ProtonVPN, Mullvad, ZeroTier, AnyConnect, GlobalProtect e outros.");
            AnsiConsole.MarkupLine("  [grey]Watchdog[/]           Ao desativar, instala a tarefa agendada 'IPV6Shutdown-Watchdog'");
            AnsiConsole.MarkupLine("                     (no boot + a cada 2 min, como SYSTEM): se o WARP ou outro adaptador novo");
            AnsiConsole.MarkupLine("                     reabilitar o IPv6, o binding é rebloqueado automaticamente.");
            AnsiConsole.MarkupLine("                     Removida no 'Reverter tudo'.");
            AnsiConsole.MarkupLine("  [grey]VPNs[/]                As interfaces de VPN/overlay são sempre preservadas. O firewall nunca bloqueia");
            AnsiConsole.MarkupLine("                     loopback, link-local, a ULA do Tailscale (fd7a:115c:a1e0::/48) nem a do");
            AnsiConsole.MarkupLine("                     Cloudflare WARP (fd01:db8:1111::/64, DNS local). No modo FULL, com VPN presente,");
            AnsiConsole.MarkupLine("                     DisabledComponents=0xFF e IP Helper são pulados (dependências de VPN).");
            AnsiConsole.MarkupLine("  [grey]Reverter[/]            Restaura o estado salvo antes da 1ª alteração (bindings, túneis, registro,");
            AnsiConsole.MarkupLine("                     IP Helper), em %ProgramData%\\IPV6Shutdown\\state.json.");
            AnsiConsole.MarkupLine("  [grey]WARP + Tailscale[/]    Se ambos estiverem instalados, o fallback para *.ts.net e ts.net");
            AnsiConsole.MarkupLine("                     é configurado automaticamente no Cloudflare WARP, liberando o MagicDNS.");
            AnsiConsole.MarkupLine("  [grey]-h, --help[/]         Mostra esta ajuda.");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("  [grey]Códigos de saída:[/] 101 (PS não encontrado) · 102 (timeout) · 103 (comando falhou) · 199 (erro inesperado)");
            AnsiConsole.WriteLine();
        }

        private sealed record BindingInfo(
            string Name, string Description, bool Enabled, bool Hardware, string Status, int Ipv6Addresses);

        private sealed record WatchdogRunInfo(string LastRun, long LastResult);

        private sealed record ExtraStatus(
            string Teredo, string SixToFour, string Isatap, string IpHttps,
            int DisabledComponents, string IpHelper, string IpHelperStart, int FirewallRules,
            int FirewallActive, int FirewallProfilesOff, string FirewallService, string BootUtc);
    }
}
