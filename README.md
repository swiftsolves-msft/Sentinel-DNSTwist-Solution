# Sentinel DNSTwist Solution
The following solution was inspired from reading Don Murdoch's Blue Team Handbook and coming across DNS Twist Algorithim and the amazing work and software written by Marcin Ulikowski

[Research from Blue Team Handbook by Don Murdoch](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898/)

[The DNSTwist GitHub Repository](https://github.com/elceef/dnstwist?tab=readme-ov-file)

The following solution will contain the following

 1. Create a Defender EASM workspace
 2. Create a Log Analytics Workspace
 3. Create a Azure Container and Using DNSTwist
 4. Create a LogicApp that reads the EASM Domain Inventory Data or KQL Query Log Analytics workspace `EasmAsset_CL | where AssetType_s contains "Domain"` for new domains and loads them into DNSTwist, then uses the DNSTwist APIs to generate lists of domain name fuzzing to look for, and export those lists into a Sentinel Watchlist.
 5. A Sentinel Analytic Rule using IM Parsers to match in DNSTwist Domains ?

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Fswiftsolves-msft%2Fmaster%2FSentinel-DNSTwist-Solution%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAzure%2Fswiftsolves-msft%2Fmaster%2FSentinel-DNSTwist-Solution%2Fazuredeploy.json)

**Additional Post Install Notes:**

Authorize the web.connection APIs deployed into the ResourceGroup.

The Logic App creates and uses a Managed System Identity (MSI) to update the Azure Sentinel Watchlist. 

Assign RBAC 'Azure Sentinel Contributor' role to the Logic App at the Resource Group level of the Log Analytics Workspace.

In Defender EASM  - Data connections blade - add a connection to the newly create log analytics workspace. Set frequency **weekly** and schedule reoccurring on **Sunday**. Logic App runs the next day on Monday. For content you can choose **asset data** at a minimum.
