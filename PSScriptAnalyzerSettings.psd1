# PSScriptAnalyzer settings for install.ps1 (CI: Invoke-ScriptAnalyzer -Settings ./PSScriptAnalyzerSettings.psd1).
@{
    Severity     = @('Warning', 'Error')
    ExcludeRules = @(
        # An interactive installer: its progress lines are console output by design.
        'PSAvoidUsingWriteHost',
        # No -WhatIf for an installer; the dangerous step (deleting the distro) asks for confirmation itself.
        'PSUseShouldProcessForStateChangingFunctions',
        # -Yes is read by the functions through the script scope, which the rule does not see.
        'PSReviewUnusedParameter'
    )
}
