$ErrorActionPreference = 'Stop'

$harness = Join-Path $PSScriptRoot 'test_database_concurrency.ps1'
$output = @(& pwsh -NoProfile -File $harness -InjectFailureAfterSetup 2>&1)
$exitCode = $LASTEXITCODE
$outputText = $output -join "`n"

if ($exitCode -eq 0) { throw 'Failure-injection run unexpectedly succeeded.' }
if ($outputText -notmatch 'Intentional F-03 failure injection after fixture setup') {
  throw "Failure-injection run failed for an unexpected reason: $outputText"
}
if ($outputText -notmatch 'cleanup verification found zero synthetic rows') {
  throw "Failure-injection run did not verify cleanup: $outputText"
}

Write-Output 'PASS: intentional post-setup failure returned nonzero after finally cleanup verified zero synthetic fixture and audit rows.'
$global:LASTEXITCODE = 0
