$projects = @("authservice", "gateway", "jokeservice", "quoteservice", "spa")

@("authservice","gateway","jokeservice","quoteservice","spa") |
  ForEach-Object -Parallel {
    Write-Host "Building $_…"
    Push-Location $_
    mvn spring-boot:build-image
    Pop-Location
  } -ThrottleLimit ([Environment]::ProcessorCount)

docker-compose build --parallel
docker-compose up -d
