using System.ComponentModel;
using System.Diagnostics;
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
        private const int PsTimeoutMs = 60_000;

        private static int Main(string[] args)
        {
            Console.Title = "IPV6Shutdown — bloqueio total de IPv6 | github.com/vitorhubdev";
            Console.OutputEncoding = Encoding.UTF8;

            bool enable = args.Any(a => a is "-e" or "--enable");
            bool statusOnly = args.Any(a => a is "-s" or "--status");
            bool full = args.Any(a => a is "--full");
            bool noFirewall = args.Any(a => a is "--nofirewall");
            bool pause = args.Any(a => a is "--pause");

            if (args.Any(a => a is "-h" or "--help" or "/?"))
            {
                ShowHelp();
                return 0;
            }

            bool isAdmin = IsAdministrator();

            if (args.Length == 0)
                return RunInteractive();

            if (!statusOnly && !isAdmin && !TryElevate(args))
                return 1;

            RenderHeader();
            try
            {
                if (statusOnly)
                {
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
                else
                {
                    DisableStandard(noFirewall);
                    RenderStatus();
                }
            }
            catch (PowerShellException ex)
            {
                RenderError(ex);
                if (pause)
                    Console.ReadKey(intercept: true);
                return ex.Code;
            }
            catch (Exception ex)
            {
                RenderUnexpected(ex);
                if (pause)
                    Console.ReadKey(intercept: true);
                return 199;
            }

            if (pause)
            {
                AnsiConsole.MarkupLine("\n[grey]Pressione qualquer tecla para sair...[/]");
                Console.ReadKey(intercept: true);
            }
            return 0;
        }

        private static int RunInteractive()
        {
            if (!IsAdministrator())
            {
                if (!TryElevate(null))
                {
                    AnsiConsole.MarkupLine("[grey]Pressione qualquer tecla para sair...[/]");
                    Console.ReadKey(intercept: true);
                    return 1;
                }
                return 0;
            }

            while (true)
            {
                try
                {
                    AnsiConsole.Clear();
                    RenderHeader();
                    RenderStatus();

                    string choice;
                    try
                    {
                        choice = AnsiConsole.Prompt(
                            new SelectionPrompt<string>()
                                .Title("[bold]O que deseja fazer?[/]")
                                .HighlightStyle(new Style(Color.Red))
                                .AddChoices(
                                    "Desativar IPv6 (bindings + firewall)",
                                    "Modo FULL (bindings + firewall + túneis + registro + IP Helper)",
                                    "Reverter tudo (reativar IPv6 e desfazer bloqueios)",
                                    "Sair"));
                    }
                    catch (OperationCanceledException)
                    {
                        continue;
                    }

                    if (choice == "Sair")
                        return 0;

                    AnsiConsole.Clear();
                    RenderHeader();

                    if (choice.StartsWith("Desativar", StringComparison.Ordinal))
                        DisableStandard(noFirewall: false);
                    else if (choice.StartsWith("Modo FULL", StringComparison.Ordinal))
                        DisableFull(noFirewall: false);
                    else
                        Revert();

                    RenderStatus();
                    AnsiConsole.MarkupLine("[grey]Pressione qualquer tecla para voltar ao menu...[/]");
                    Console.ReadKey(intercept: true);
                }
                catch (PowerShellException ex)
                {
                    RenderError(ex);
                    Console.ReadKey(intercept: true);
                }
                catch (Exception ex)
                {
                    RenderUnexpected(ex);
                    Console.ReadKey(intercept: true);
                }
            }
        }

        private static bool TryElevate(string[]? args)
        {
            AnsiConsole.Write(new Panel("[bold]Esta ação precisa de permissão de Administrador.\nO Windows vai mostrar o aviso de UAC e abrir uma nova janela elevada — isso é normal e esperado.[/]")
                .Header("[yellow]Elevação necessária[/]")
                .BorderColor(Color.Yellow));
            if (!AnsiConsole.Confirm("Solicitar elevação agora?", defaultValue: true))
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
            AnsiConsole.WriteLine();
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
            grid.AddRow("DisabledComponents (registro)", extra.DisabledComponents == 255
                ? "[green]0xFF — IPv6 desativado na pilha[/]"
                : extra.DisabledComponents == 0
                    ? "[red]não definido — IPv6 habilitado na pilha[/]"
                    : $"[yellow]0x{extra.DisabledComponents:X2} — parcial[/]");
            grid.AddRow("Serviço IP Helper (iphlpsvc)", extra.IpHelper == "Stopped"
                ? $"[green]Parado ({Markup.Escape(extra.IpHelperStart)})[/]"
                : $"[red]{Markup.Escape(extra.IpHelper)} ({Markup.Escape(extra.IpHelperStart)})[/]");
            grid.AddRow("Regras de firewall IPV6Shutdown", extra.FirewallRules == 0
                ? "[red]nenhuma[/]"
                : $"[green]{extra.FirewallRules} regra(s) ativa(s)[/]");
            AnsiConsole.Write(grid);

            AnsiConsole.WriteLine();
            int ativos = bindings.Count(b => b.Enabled);
            AnsiConsole.MarkupLine(bindings.Count == 0
                ? "[grey]IPv6: nenhuma interface com binding encontrada — status indisponível[/]"
                : ativos == 0
                    ? "[bold green]IPv6: BLOQUEADO em todas as interfaces[/]"
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
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Desativando IPv6...[/]", ctx =>
            {
                foreach (BindingInfo b in GetBindings().Where(b => b.Enabled))
                {
                    ctx.Status($"[grey]Desativando binding em[/] [bold]{Markup.Escape(b.Name)}[/]");
                    RunPowerShell($"Disable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue");
                }
                if (!noFirewall)
                {
                    ctx.Status("[grey]Criando regras de firewall (IPv6 ::/0)...[/]");
                    EnsureFirewallRule(RuleSaida,
                        $"New-NetFirewallRule -DisplayName '{RuleSaida}' -Direction Outbound -Action Block -RemoteAddress ::/0 -Enabled True | Out-Null");
                    EnsureFirewallRule(RuleEntrada,
                        $"New-NetFirewallRule -DisplayName '{RuleEntrada}' -Direction Inbound -Action Block -RemoteAddress ::/0 -Enabled True | Out-Null");
                }
            });
            AnsiConsole.MarkupLine("[green]✔ IPv6 desativado nas interfaces" + (noFirewall ? ".[/]" : " e bloqueado no firewall.[/]"));
            AnsiConsole.WriteLine();
        }

        private static void DisableFull(bool noFirewall)
        {
            DisableStandard(noFirewall);

            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Aplicando bloqueios extras...[/]", ctx =>
            {
                ctx.Status("[grey]Desativando túneis Teredo/6to4/ISATAP/IP-HTTPS...[/]");
                RunPowerShell("""
                    Set-NetTeredoConfiguration -Type Disabled -ErrorAction SilentlyContinue
                    Set-Net6to4Configuration -State Disabled -ErrorAction SilentlyContinue
                    Set-NetIsatapConfiguration -State Disabled -ErrorAction SilentlyContinue
                    Set-NetIPHttpsConfiguration -State Disabled -ErrorAction SilentlyContinue
                    """);

                ctx.Status("[grey]Gravando DisabledComponents = 0xFF no registro...[/]");
                RunPowerShell($"Set-ItemProperty -Path '{RegPath}' -Name DisabledComponents -Value 255 -Type DWord");

                ctx.Status("[grey]Parando e desativando o serviço IP Helper...[/]");
                RunPowerShell("Stop-Service iphlpsvc -Force -ErrorAction SilentlyContinue; Set-Service iphlpsvc -StartupType Disabled");

                if (!noFirewall)
                {
                    ctx.Status("[grey]Bloqueando Teredo (UDP 3544) e 6in4 (protocolo 41) no firewall...[/]");
                    EnsureFirewallRule(RuleTeredo,
                        $"New-NetFirewallRule -DisplayName '{RuleTeredo}' -Direction Outbound -Action Block -Protocol UDP -RemotePort 3544 -Enabled True | Out-Null");
                    EnsureFirewallRule(Rule6in4,
                        $"New-NetFirewallRule -DisplayName '{Rule6in4}' -Direction Outbound -Action Block -Protocol 41 -Enabled True | Out-Null");
                }
            });

            AnsiConsole.MarkupLine("[green]✔ Túneis de transição desativados, registro gravado e IP Helper parado.[/]");
            AnsiConsole.WriteLine();
            AnsiConsole.Write(new Panel("[bold yellow]Reinicie o computador para o DisabledComponents (0xFF) surtir efeito completo na pilha TCP/IP.[/]")
                .Header("[bold]Modo FULL aplicado[/]")
                .BorderColor(Color.Yellow));
            AnsiConsole.WriteLine();
        }

        private static void Revert()
        {
            bool rebootNeeded = false;
            AnsiConsole.Status().Spinner(Spinner.Known.Dots).Start("[bold]Revertendo...[/]", ctx =>
            {
                ctx.Status("[grey]Reativando bindings IPv6...[/]");
                foreach (BindingInfo b in GetBindings().Where(b => !b.Enabled))
                    RunPowerShell($"Enable-NetAdapterBinding -Name '{EscapePs(b.Name)}' -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue");

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
                string check = RunPowerShell($"if (Get-ItemProperty '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue) {{ 'yes' }}");
                if (check.Contains("yes", StringComparison.OrdinalIgnoreCase))
                {
                    RunPowerShell($"Remove-ItemProperty -Path '{RegPath}' -Name DisabledComponents -ErrorAction SilentlyContinue");
                    rebootNeeded = true;
                }

                ctx.Status("[grey]Reativando serviço IP Helper...[/]");
                RunPowerShell("Set-Service iphlpsvc -StartupType Manual; Start-Service iphlpsvc -ErrorAction SilentlyContinue");
            });

            AnsiConsole.MarkupLine("[green]✔ IPv6 reativado e bloqueios removidos.[/]");
            AnsiConsole.WriteLine();
            if (rebootNeeded)
            {
                AnsiConsole.Write(new Panel("[bold yellow]O valor DisabledComponents foi removido do registro. Reinicie o computador para a pilha TCP/IP voltar ao padrão.[/]")
                    .Header("[bold]Reversão concluída[/]")
                    .BorderColor(Color.Yellow));
                AnsiConsole.WriteLine();
            }
        }

        private static bool IsAdministrator()
        {
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }

        private static string QuoteArg(string arg) => arg.Contains(' ') ? $"\"{arg}\"" : arg;

        private static string EscapePs(string value) => value.Replace("'", "''");

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
                StandardOutputEncoding = Encoding.UTF8
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
                        process.WaitForExit();
                    }
                    catch (Exception ex) when (ex is InvalidOperationException or Win32Exception)
                    {
                    }
                    throw new PowerShellException(PsError.Timeout,
                        $"PowerShell não respondeu em {PsTimeoutMs / 1000}s — comando abortado: {Truncate(command, 120)}");
                }

                Task.WaitAll(stdoutTask, stderrTask);
                if (process.ExitCode != 0)
                {
                    throw new PowerShellException(PsError.ExitCode,
                        $"PowerShell saiu com código {process.ExitCode}: {CleanStderr(stderrTask.Result)}");
                }
                return stdoutTask.Result.Trim();
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
            return clean.Length > 300 ? clean[..300] + "…" : clean;
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

        private static List<BindingInfo> GetBindings()
        {
            string json = RunPowerShell("Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Enabled | ConvertTo-Json -Compress");
            var list = new List<BindingInfo>();
            if (string.IsNullOrWhiteSpace(json) || (json[0] != '{' && json[0] != '['))
                return list;
            try
            {
                using JsonDocument doc = JsonDocument.Parse(json);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    list.AddRange(doc.RootElement.EnumerateArray().Select(ParseBinding));
                else if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    list.Add(ParseBinding(doc.RootElement));
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
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
                  DisabledComponents = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters' -Name DisabledComponents).DisabledComponents
                  IpHelper = "$((Get-Service iphlpsvc).Status)"
                  IpHelperStart = "$((Get-Service iphlpsvc).StartType)"
                  FirewallRules = @(Get-NetFirewallRule -DisplayName 'IPV6Shutdown*').Count
                }
                $o | ConvertTo-Json -Compress
                """);
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
                    dc.ValueKind == JsonValueKind.Number ? dc.GetInt32() : 0,
                    r.GetProperty("IpHelper").GetString() ?? "?",
                    r.GetProperty("IpHelperStart").GetString() ?? "?",
                    r.GetProperty("FirewallRules").GetInt32());
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            {
                return new ExtraStatus("?", "?", "?", "?", 0, "?", "?", 0);
            }
        }

        private static void EnsureFirewallRule(string displayName, string createCommand)
        {
            string exists = RunPowerShell($"if (Get-NetFirewallRule -DisplayName '{EscapePs(displayName)}' -ErrorAction SilentlyContinue) {{ 'yes' }}");
            if (exists.Contains("yes", StringComparison.OrdinalIgnoreCase))
                return;
            RunPowerShell(createCommand);
        }

        private static void ShowHelp()
        {
            RenderHeader();
            AnsiConsole.MarkupLine("[bold]Uso:[/] IPV6Shutdown [[opções]]");
            AnsiConsole.WriteLine();
            AnsiConsole.MarkupLine("  [grey](sem opções)[/]   Abre o menu interativo.");
            AnsiConsole.MarkupLine("  [grey]--disable[/]      Desativa o IPv6 (bindings + firewall). Padrão quando há flags.");
            AnsiConsole.MarkupLine("  [grey]--full[/]         Modo completo: bindings + firewall + túneis de transição");
            AnsiConsole.MarkupLine("                 (Teredo/6to4/ISATAP/IP-HTTPS) + DisabledComponents=0xFF + IP Helper.");
            AnsiConsole.MarkupLine("  [grey]-e, --enable[/]   Reverte tudo: reativa o IPv6 e remove todos os bloqueios.");
            AnsiConsole.MarkupLine("  [grey]-s, --status[/]   Apenas mostra o status (não precisa de Administrador).");
            AnsiConsole.MarkupLine("  [grey]--nofirewall[/]   Não cria regras de firewall.");
            AnsiConsole.MarkupLine("  [grey]-h, --help[/]     Mostra esta ajuda.");
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
