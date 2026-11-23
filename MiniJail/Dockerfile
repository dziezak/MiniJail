FROM mcr.microsoft.com/dotnet/sdk:10.0

RUN apt-get update && apt-get install -y --no-install-recommends gcc libc6-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN gcc -O2 -static tests/ok.c -o /app/ok \
 && gcc -O2 -static tests/evil_net.c -o /app/evil_net \
 && gcc -O2 -static tests/evil_file.c -o /app/evil_file

RUN dotnet build -c Release
