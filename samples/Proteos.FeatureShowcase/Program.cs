using Proteos.FeatureShowcase.Infrastructure;
using Proteos.FeatureShowcase.Scenarios;

var scenarios = new IScenario[]
{
    new Scenario01_SaveAndLoad(),
    new Scenario02_EncryptedSearch(),
    new Scenario03_AuditReport(),
    new Scenario04_StrictMode(),
    new Scenario05_KeyRotation(),
    new Scenario06_RotationAwareSearch(),
    new Scenario07_ReEncrypt(),
    new Scenario08_AzureSetupExample(),
    new Scenario09_AwsSetupExample(),
    new Scenario10_AnalyzerExamples(),
};

PrintMenu();

// The selection comes from the first command-line argument (e.g. `dotnet run -- 5`) or, when none is
// given, from the console. An empty / end-of-input line runs everything, so a piped or non-interactive
// run still does something useful.
var input = args.Length > 0 ? args[0] : Console.ReadLine();
if (!int.TryParse(input, out var choice))
{
    choice = 0;
}

if (choice == 0)
{
    foreach (var scenario in scenarios)
    {
        await RunAsync(scenario);
    }
}
else if (choice >= 1 && choice <= scenarios.Length)
{
    await RunAsync(scenarios[choice - 1]);
}
else
{
    Console.WriteLine($"Unknown selection '{input}'. Choose 0-{scenarios.Length}.");
}

void PrintMenu()
{
    Console.WriteLine("=========================================");
    Console.WriteLine("Proteos Feature Showcase");
    Console.WriteLine("=========================================");
    Console.WriteLine();
    for (var i = 0; i < scenarios.Length; i++)
    {
        Console.WriteLine($"[{i + 1}] {scenarios[i].Title}");
    }

    Console.WriteLine("[0] Run everything");
    Console.WriteLine();
}

async Task RunAsync(IScenario scenario)
{
    Console.WriteLine($"--- {scenario.Title} ---");
    await scenario.ExecuteAsync();
    Console.WriteLine();
}
