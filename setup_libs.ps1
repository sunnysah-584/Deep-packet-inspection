$libs = @{
    "flatlaf-3.5.1.jar" = "https://repo1.maven.org/maven2/com/formdev/flatlaf/3.5.1/flatlaf-3.5.1.jar"
    "sqlite-jdbc-3.45.2.0.jar" = "https://repo1.maven.org/maven2/org/xerial/sqlite-jdbc/3.45.2.0/sqlite-jdbc-3.45.2.0.jar"
    "slf4j-api-2.0.12.jar" = "https://repo1.maven.org/maven2/org/slf4j/slf4j-api/2.0.12/slf4j-api-2.0.12.jar"
    "slf4j-simple-2.0.12.jar" = "https://repo1.maven.org/maven2/org/slf4j/slf4j-simple/2.0.12/slf4j-simple-2.0.12.jar"
    "pcap4j-core-1.8.2.jar" = "https://repo1.maven.org/maven2/org/pcap4j/pcap4j-core/1.8.2/pcap4j-core-1.8.2.jar"
    "pcap4j-packetfactory-static-1.8.2.jar" = "https://repo1.maven.org/maven2/org/pcap4j/pcap4j-packetfactory-static/1.8.2/pcap4j-packetfactory-static-1.8.2.jar"
    "jna-5.13.0.jar" = "https://repo1.maven.org/maven2/net/java/dev/jna/jna/5.13.0/jna-5.13.0.jar"
}

New-Item -ItemType Directory -Force -Path "lib"
New-Item -ItemType Directory -Force -Path "src"
New-Item -ItemType Directory -Force -Path "bin"

foreach ($name in $libs.Keys) {
    $url = $libs[$name]
    $dest = Join-Path "lib" $name
    if (-not (Test-Path $dest)) {
        Write-Host "Downloading $name from $url..."
        Invoke-WebRequest -Uri $url -OutFile $dest -UserAgent "Mozilla/5.0"
    } else {
        Write-Host "$name already exists, skipping."
    }
}
Write-Host "All libraries prepared successfully!"
