# Sentinel DNSTwist Solution
The following solution was inspired from reading Don Murdoch's Blue Team Handbook and coming across DNS Twist Algorithim and the amazing work and software written by Marcin Ulikowski

[Research from Blue Team Handbook by Don Murdoch](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898/)

[The DNSTwist GitHub Repository](https://github.com/elceef/dnstwist?tab=readme-ov-file)

The following solution will contain the following

 1. Create a Defender EASM workspace
 2. Create a Log Analytics Workspace
 3. Create a Azure Container and Using DNSTwist
 4. Create a LogicApp or Function that reads the EASM Domain Inventory Data or KQL Query Log Analytics workspace `EasmAsset_CL | where AssetType_s contains "Domain"` for new domains and loads them into DNSTwist, then uses the DNSTwist APIs to generate lists of domain name fuzzing to look for, and export those lists into a Sentinel Watchlist.
 5. A Sentinel Analytic Rule using IM Parsers to match in DNSTwist Domains ?
