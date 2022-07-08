# Kusto C2 Client/Server PoC

*Dmitriy Beryoza (@0xd13a)*

(for general discussion and background see https://www.youtube.com/watch?v=PoEVzcSi3bc )

## Setup

To set up the PoC:

1. Configure Azure Log Analytics workspace, application, secret, and proper permissions to run Log Analytics queries as described in 
https://techcommunity.microsoft.com/t5/azure-sentinel/access-azure-sentinel-log-analytics-via-api-part-1/ba-p/1248377

2. Set up a subdomain under your control to point to your server (functionality will not work with an IP address); you can run server functionality on port 80 (default) or allocate a specific port

3. Update `kusto-c2-client.ps1`, setting proper variable values at the beginning of the script on the victim Windows machine

4. Run `python3 kusto-c2-srv.py [PORT]` on the server

5. Run `.\kusto-c2-client.ps1` on the client

6. Interact with the server to issue commands to the client. Commands currently supported:
   
```
  !download         - download file to the client
  !exfil            - exfiltrate file from the client
  !exit             - shut download
  !help             - short help
  any other command - OS command to execute on the client
```
