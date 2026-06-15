namespace Proteos.FeatureShowcase.Infrastructure;

/// <summary>One self-contained demonstration. The menu lists these and runs them by number.</summary>
public interface IScenario
{
    /// <summary>Short title shown in the menu.</summary>
    string Title { get; }

    /// <summary>Runs the scenario, writing its output to the console.</summary>
    Task ExecuteAsync();
}
