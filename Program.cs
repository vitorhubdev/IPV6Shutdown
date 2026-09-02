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
        private const string AllIpv6SemUla = "::-fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff,fd7a:115c:a1e1::-ffff:ffff:ffff:ffff:ffff:ffff:ffff";
        private const string RegPath = @"HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters";
        private const string WatchdogTaskName = "IPV6Shutdown-Watchdog";
        private const int PsTimeoutMs = 60_000;
        private const int BindingBatchSize = 40;
        private const int KillWaitMs = 5_000;

        private static readonly HashSet<string> KnownArgs = new(StringComparer.OrdinalIgnoreCase)
        {
            "-e", "--enable", "-s", "--status", "--full", "--disable",
            "--nofirewall", "--pause", "-h", "--help", "/?",
            "-w", "--warp-tailscale"
        };

        private static int Main(string[] args)
        {
            Console.Title = "IPV6Shutdown — bloqueio total de IPv6 | github.com/vitorhubdev";
            Console.OutputEncoding = Encoding.UTF8;

            bool enable = args.Any(a => a is "-e" or "--enable");
            bool statusOnly = args.Any(a => a is "-s" or "--status");
            bool full = args.Any(a => a is "--full");
            bool disable = args.Any(a => a is "--disable");
            bool noFirewall = args.Any(a => a is "--nofirewall");
            bool pause = args.Any(a => a is "--pause");
            bool warpTailscale = args.Any(a => a is "-w" or "--warp-tailscale");

            if (args.Any(a => a is "-h" or "--help" or "/?"))
            {
                ShowHelp();
                return 0;
            }

            if (args.Length > 0 && args.Any(a => !KnownArgs.Contains(a)))
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
                Process.Start(new ProcessStartInfo
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
            Version? version = Assembly.GetExecutingAssembly().GetName().Version;
            return version is null ? "1.3.1" : $"{version.Major}.{version.Minor}.{version.Build}";
        }

        private static void RenderStatus()
        {
            List<BindingInfo> bindings = GetBindings();
            ExtraStatus extra = GetExtraStatus();

            var table = new Table().Border(TableBorder.Rounded).Title("[bold]Interfaces de rede[/]");
            table.AddColumn("Interface");
            table.AddColumn("Descrição");
            table.AddColumn("IPv6");
            foreach (BindingInfo b in bindings)
            {
                string status = b.Enabled ? "[red]● ATIVO[/]" : "[green]● DESATIVADO[/]";
                table.AddRow(Markup.Escape(b.Name), Markup.Escape(b.Description), status);
            }
            AnsiConsole.Write(table);

            var grid = new Table().Border(TableBorder.Rounded).Title("[bold]Proteções extras[/]");
            grid.AddColumn("Item");
            grid.AddColumn("Status");
            grid.AddRow("Teredo", StateMarkup(extra.Teredo));
            grid.AddRow("6to4", StateMarkup(extra.SixToFour));
            grid.AddRow("ISATAP", StateMarkup(extra.Isatap));
            grid.AddRow("IP-HTTPS", StateMarkup(extra.IpHttps));
            grid.AddRow("DisabledComponents (registro)", DisabledComponentsPolicy.FormatStatusMarkup(extra.DisabledComponents));
            grid.AddRow("Serviço IP Helper (iphlpsvc)", extra.IpHelper == "Stopped"
                ? $"[green]Parado ({Markup.Escape(extra.IpHelperStart)})[/]"
                : $"[red]{Markup.Escape(extra.IpHelper)} ({Markup.Escape(extra.IpHelperStart)})[/]");
            grid.AddRow("Regras de firewall IPV6Shutdown", extra.FirewallRules == 0
                ? "[red]nenhuma[/]"
                : $"[green]{extra.FirewallRules} regra(s) ativa(s)[/]");
            grid.AddRow("Watchdog (proteção contínua)", GetWatchdogStatusMarkup());
            if (HasTailscale() || HasCloudflareWarp())
            {
                grid.AddRow("Cloudflare WARP + Tailscale DNS", GetWarpTailscaleStatus());
            }
            AnsiConsole.Write(grid);

            AnsiConsole.WriteLine();
            int ativos = bindings.Count(b => b.Enabled);
            int ativosNormais = bindings.Count(b => b.Enabled && !IsTailscaleAdapter(b));
            AnsiConsole.MarkupLine(bindings.Count == 0
                ? "[grey]IPv6: nenhuma interface com binding encontrada — status indisponível[/]"
                : ativos == 0
                    ? "[bold green]IPv6: BLOQUEADO em todas as interfaces[/]"
                    : ativosNormais == 0
                        ? "[bold green]IPv6: BLOQUEADO nas interfaces físicas[/] [grey](ativo apenas na Tailscale, protegida)[/]"
                        : $"[bold red]IPv6: ATIVO em {ativos} interface(s)[/]");
            AnsiConsole.WriteLine();
        }

        private static string StateMarkup(string raw) =>
            raw == "Disabled"
                ? "[green]Desativado[/]"
                : string.IsNullOrEmpty(raw) || raw == "?"
                    ? "[grey]não presente[/]"
                    : $"[red]{Markup.Escape(raw)}[/]";

        private static void DisableStandard(bool noFirewall)
        {
            bool preferIpv4RebootNeeded = false;
            bool warpConflictFixed = false;
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Desativando IPv6...[/]", ctx =>
            {
                List<BindingInfo> toDisable = GetBindings().Where(b => b.Enabled && !IsTailscaleAdapter(b)).ToList();
                if (toDisable.Count > 0)
                {
                    foreach (BindingInfo b in toDisable)
                        ctx.Status($"[grey]Desativando binding em[/] [bold]{Markup.Escape(b.Name)}[/]");
                    RunBindingCommands(toDisable.Select(b =>
                        $"Disable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6"));
                    AssertBindings(toDisable.Select(b => b.Name), shouldBeEnabled: false,
                        "Falha ao desativar IPv6 nas interfaces");
                }
                ProtectTailscale(ctx);
                ctx.Status("[grey]Gravando Prefer IPv4 (DisabledComponents | 0x20)...[/]");
                preferIpv4RebootNeeded = ApplyPreferIpv4Registry();
                if (HasTailscale() && HasCloudflareWarp())
                {
                    EnsureWarpTailscaleFallback(ctx, out warpConflictFixed);
                }
                if (!noFirewall)
                {
                    ctx.Status("[grey]Criando regras de firewall (IPv6 toda a faixa, exceto ULA do Tailscale)...[/]");
                    EnsureFirewallRule(RuleSaida,
                        $"New-NetFirewallRule -DisplayName '{RuleSaida}' -Direction Outbound -Action Block -RemoteAddress '{AllIpv6SemUla}' -Enabled True | Out-Null");
                    EnsureFirewallRule(RuleEntrada,
                        $"New-NetFirewallRule -DisplayName '{RuleEntrada}' -Direction Inbound -Action Block -RemoteAddress '{AllIpv6SemUla}' -Enabled True | Out-Null");
                    EnsureWatchdogInstalled(ctx);
                }
            });
            AnsiConsole.MarkupLine("[green]✔ IPv6 desativado nas interfaces" + (noFirewall ? ".[/]" : " e bloqueado no firewall.[/]"));
            if (HasTailscale() && HasCloudflareWarp())
            {
                AnsiConsole.MarkupLine("[green]✔ Conflito Cloudflare WARP + Tailscale MagicDNS resolvido (fallback *.ts.net ativo).[/]");
            }
            if (!noFirewall)
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
            DisableStandard(noFirewall);

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

                bool tailscale = HasTailscale();
                if (tailscale)
                {
                    ctx.Status("[yellow]Pulando DisabledComponents=0xFF — desligaria o IPv6 do Tailscale[/]");
                }
                else
                {
                    ctx.Status("[grey]Gravando DisabledComponents = 0xFF no registro...[/]");
                    RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value 255 -Type DWord");
                    regWritten = true;
                }

                if (tailscale)
                {
                    ctx.Status("[yellow]Pulando IP Helper — o serviço Tailscale depende de iphlpsvc e seria parado junto[/]");
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
                AnsiConsole.Write(new Panel("[bold yellow]DisabledComponents (0xFF) e o serviço IP Helper não foram alterados porque o Tailscale foi detectado: o primeiro desligaria o IPv6 privado do tailnet, e o segundo pararia o Tailscale (que depende do iphlpsvc). Nenhuma reinicialização é necessária por estes motivos.[/]")
                    .Header("[bold]Modo FULL aplicado (Tailscale protegido)[/]")
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
            string script = $$"""
                $ErrorActionPreference = 'Continue'
                Get-NetAdapterBinding -ComponentID ms_tcpip6 | Where-Object {
                    $_.Enabled -and
                    $_.Name -notlike '*Tailscale*' -and
                    $_.InterfaceDescription -notlike '*Tailscale*'
                } | ForEach-Object {
                    Disable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue
                }
                Remove-NetFirewallRule -DisplayName '{{RuleSaida}}' -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName '{{RuleSaida}}' -Direction Outbound -Action Block -RemoteAddress '{{AllIpv6SemUla}}' -Enabled True | Out-Null
                Remove-NetFirewallRule -DisplayName '{{RuleEntrada}}' -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName '{{RuleEntrada}}' -Direction Inbound -Action Block -RemoteAddress '{{AllIpv6SemUla}}' -Enabled True | Out-Null
                """;
            string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
            RunPowerShell($"""
                Unregister-ScheduledTask -TaskName '{WatchdogTaskName}' -Confirm:$false -ErrorAction SilentlyContinue
                $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand {encoded}'
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

        private static WatchdogTaskSnapshot GetWatchdogTaskSnapshot()
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
                } | ConvertTo-Json -Compress
                """);

            json = ExtractJsonPayload(json);
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                JsonElement root = doc.RootElement;
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

        private static string GetWatchdogStatusMarkup()
        {
            try
            {
                WatchdogConfigurationResult result =
                    WatchdogTaskValidation.EvaluateConfiguration(GetWatchdogTaskSnapshot());

                return result.State switch
                {
                    WatchdogConfigurationState.Healthy =>
                        "[green]ativa — boot + a cada 2 min[/]",
                    WatchdogConfigurationState.Missing =>
                        "[red]ausente[/]",
                    WatchdogConfigurationState.Disabled =>
                        "[red]desativada no Agendador de Tarefas[/]",
                    _ =>
                        $"[yellow]configuração inválida — {Markup.Escape(result.Reason)}[/]"
                };
            }
            catch (PowerShellException ex)
            {
                return $"[red]erro ao consultar — {Markup.Escape(ex.Message)}[/]";
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
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Revertendo...[/]", ctx =>
            {
                ctx.Status("[grey]Removendo tarefa de proteção contínua...[/]");
                RunPowerShell($"""
                    Stop-ScheduledTask -TaskName '{WatchdogTaskName}' -ErrorAction SilentlyContinue
                    Unregister-ScheduledTask -TaskName '{WatchdogTaskName}' -Confirm:$false -ErrorAction SilentlyContinue
                    """);

                ctx.Status("[grey]Reativando bindings IPv6...[/]");
                List<BindingInfo> disabled = GetBindings().Where(b => !b.Enabled).ToList();
                EnableBindings(disabled);

                ctx.Status("[grey]Removendo regras de firewall...[/]");
                RunPowerShell("Remove-NetFirewallRule -DisplayName 'IPV6Shutdown*' -ErrorAction SilentlyContinue");

                ctx.Status("[grey]Restaurando túneis de transição...[/]");
                RunPowerShell("""
                    Set-NetTeredoConfiguration -Type Default -ErrorAction SilentlyContinue
                    Set-Net6to4Configuration -State Default -ErrorAction SilentlyContinue
                    Set-NetIsatapConfiguration -State Default -ErrorAction SilentlyContinue
                    Set-NetIPHttpsConfiguration -State Default -ErrorAction SilentlyContinue
                    """);

                ctx.Status("[grey]Restaurando registro DisabledComponents...[/]");
                if (RevertPreferIpv4Registry())
                    rebootNeeded = true;

                ctx.Status("[grey]Reativando serviço IP Helper...[/]");
                RunPowerShell("Set-Service iphlpsvc -StartupType Manual; Start-Service iphlpsvc -ErrorAction SilentlyContinue");

                ctx.Status("[grey]Reaplicando bindings IPv6 (replay contra watchdog em voo)...[/]");
                List<BindingInfo> stillDisabled = GetBindings().Where(b => !b.Enabled).ToList();
                EnableBindings(stillDisabled);
                RunPowerShell("Remove-NetFirewallRule -DisplayName 'IPV6Shutdown*' -ErrorAction SilentlyContinue");
                IEnumerable<string> replayNames = disabled.Select(b => b.Name)
                    .Concat(stillDisabled.Select(b => b.Name))
                    .Distinct(StringComparer.OrdinalIgnoreCase);
                AssertBindings(replayNames, shouldBeEnabled: true,
                    "Falha ao reativar IPv6 nas interfaces");
            });

            AnsiConsole.MarkupLine("[green]✔ IPv6 reativado, bloqueios e proteção contínua removidos.[/]");
            AnsiConsole.WriteLine();
            if (rebootNeeded)
            {
                AnsiConsole.Write(new Panel("[bold yellow]O valor DisabledComponents foi removido do registro. Reinicie o computador para a pilha TCP/IP voltar ao padrão.[/]")
                    .Header("[bold]Reversão concluída[/]")
                    .BorderColor(Color.Yellow));
                AnsiConsole.WriteLine();
            }
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

        private static string QuoteArg(string arg) => arg.Contains(' ') ? $"\"{arg}\"" : arg;

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
        }

        private static void AssertBindings(IEnumerable<string> names, bool shouldBeEnabled, string failureMessage)
        {
            var expected = new HashSet<string>(names, StringComparer.OrdinalIgnoreCase);
            if (expected.Count == 0)
                return;
            List<string> mismatches = GetBindings()
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
                FileName = "powershell.exe",
                Arguments = $"-NoProfile -NonInteractive -EncodedCommand {encoded}",
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
                process = Process.Start(psi)!;
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

        private static List<BindingInfo> GetBindings()
        {
            string json = RunPowerShell("Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Enabled | ConvertTo-Json -Compress");
            var list = new List<BindingInfo>();
            if (string.IsNullOrWhiteSpace(json))
                return list;

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
            return list.OrderBy(b => b.Name, StringComparer.OrdinalIgnoreCase).ToList();
        }

        private static BindingInfo ParseBinding(JsonElement el) =>
            new(el.GetProperty("Name").GetString() ?? string.Empty,
                el.GetProperty("InterfaceDescription").GetString() ?? string.Empty,
                el.GetProperty("Enabled").GetBoolean());

        private static ExtraStatus GetExtraStatus()
        {
            string json = RunPowerShell("""
                $ErrorActionPreference = 'SilentlyContinue'
                $o = [ordered]@{
                  Teredo = "$((Get-NetTeredoConfiguration).Type)"
                  SixToFour = "$((Get-Net6to4Configuration).State)"
                  Isatap = "$((Get-NetIsatapConfiguration).State)"
                  IpHttps = "$((Get-NetIPHttpsConfiguration).State)"
                  DisabledComponents = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents -ErrorAction SilentlyContinue).DisabledComponents
                  IpHelper = "$((Get-Service iphlpsvc).Status)"
                  IpHelperStart = "$((Get-Service iphlpsvc).StartType)"
                  FirewallRules = @(Get-NetFirewallRule -DisplayName 'IPV6Shutdown*' -ErrorAction SilentlyContinue).Count
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
                    r.GetProperty("FirewallRules").GetInt32());
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException or FormatException)
            {
                throw new PowerShellException(PsError.ExitCode,
                    $"JSON de status extra inválido: {ex.Message}", ex);
            }
        }

        private static bool ApplyPreferIpv4Registry()
        {
            int current = ReadDisabledComponents();
            (int newValue, bool newlySet) = DisabledComponentsPolicy.ApplyPreferIpv4(current);
            if (!newlySet)
                return false;
            RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value {newValue} -Type DWord");
            return true;
        }

        private static bool RevertPreferIpv4Registry()
        {
            int current = ReadDisabledComponents();
            if (!GetDisabledComponentsPropertyExists())
                return false;

            (int? newValue, bool removeProperty, bool changed) = DisabledComponentsPolicy.RevertPreferIpv4(current);
            if (!changed)
                return false;

            if (removeProperty)
                RunPowerShell($"Remove-ItemProperty -Path '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue");
            else
                RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value {newValue!.Value} -Type DWord");
            return true;
        }

        private static bool GetDisabledComponentsPropertyExists()
        {
            string check = RunPowerShell(
                $"if (Get-ItemProperty '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue) {{ 'yes' }}");
            return check.Contains("yes", StringComparison.OrdinalIgnoreCase);
        }

        private static int ReadDisabledComponents()
        {
            if (!GetDisabledComponentsPropertyExists())
                return 0;
            string raw = RunPowerShell(
                $"(Get-ItemProperty '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue).DisabledComponents");
            return int.TryParse(raw.Trim(), out int value) ? value : 0;
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

        private static bool ProtectTailscale(StatusContext? ctx)
        {
            List<BindingInfo> tailscale = GetBindings().Where(IsTailscaleAdapter).ToList();
            if (tailscale.Count == 0)
                return false;
            ctx?.Status($"[grey]Mantendo IPv6 na interface Tailscale[/] [bold]{Markup.Escape(tailscale[0].Name)}[/]");
            RunBindingCommands(tailscale.Select(b =>
                $"Enable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6"));
            AssertBindings(tailscale.Select(b => b.Name), shouldBeEnabled: true,
                "Falha ao preservar IPv6 na interface Tailscale");
            return true;
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
            AnsiConsole.MarkupLine("  [grey]--nofirewall[/]       Não cria regras de firewall.");
            AnsiConsole.MarkupLine("  [grey]Watchdog[/]           Ao desativar, instala a tarefa agendada 'IPV6Shutdown-Watchdog'");
            AnsiConsole.MarkupLine("                     (no boot + a cada 2 min, como SYSTEM): se o WARP ou outro adaptador novo");
            AnsiConsole.MarkupLine("                     reabilitar o IPv6, o binding é rebloqueado automaticamente.");
            AnsiConsole.MarkupLine("                     Removida no 'Reverter tudo'.");
            AnsiConsole.MarkupLine("  [grey]Tailscale[/]           As interfaces do Tailscale são sempre protegidas: o IPv6 privado");
            AnsiConsole.MarkupLine("                     (fd7a:115c:a1e0::/48) do tailnet não é desativado, e no modo FULL");
            AnsiConsole.MarkupLine("                     o DisabledComponents=0xFF e o IP Helper são pulados (o Tailscale");
            AnsiConsole.MarkupLine("                     depende do serviço iphlpsvc).");
            AnsiConsole.MarkupLine("  [grey]WARP + Tailscale[/]    Se ambos estiverem instalados, o fallback para *.ts.net e ts.net");
            AnsiConsole.MarkupLine("                     é configurado automaticamente no Cloudflare WARP, liberando o MagicDNS.");
            AnsiConsole.MarkupLine("  [grey]-h, --help[/]         Mostra esta ajuda.");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("  [grey]Códigos de saída:[/] 101 (PS não encontrado) · 102 (timeout) · 103 (comando falhou) · 199 (erro inesperado)");
            AnsiConsole.WriteLine();
        }

        private sealed record BindingInfo(string Name, string Description, bool Enabled);

        private sealed record ExtraStatus(
            string Teredo, string SixToFour, string Isatap, string IpHttps,
            int DisabledComponents, string IpHelper, string IpHelperStart, int FirewallRules);
    }
}
