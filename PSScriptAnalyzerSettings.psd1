@{
    Severity = @('Error', 'Warning')
    IncludeRules = @(
        'PSUseApprovedVerbs'
        'PSReservedCmdletChar'
        'PSReservedParams'
        'PSAvoidDefaultValueSwitchParameter'
        'PSAvoidDefaultValueForMandatoryParameter'
        'PSAvoidNullOrEmptyHelpMessageAttribute'
        'PSAvoidUsingBrokenHashAlgorithms'
        'PSAvoidUsingCmdletAliases'
        'PSAvoidUsingInvokeExpression'
        'PSAvoidUsingPlainTextForPassword'
        'PSAvoidUsingConvertToSecureStringWithPlainText'
        'PSAvoidUsingComputerNameHardcoded'
        'PSAvoidUsingWMICmdlet'
        'PSAvoidUsingEmptyCatchBlock'
        'PSAvoidOverwritingBuiltInCmdlets'
        'PSUseDeclaredVarsMoreThanAssignments'
        'PSReviewUnusedParameter'
        'PSAvoidAssignmentToAutomaticVariable'
        'PSAvoidUsingUsernameAndPasswordParams'
    )
    # Interactive Write-Host is intentional. ShouldProcess is deferred to Phase 3;
    # changing that CLI contract is explicitly outside this implementation.
}
