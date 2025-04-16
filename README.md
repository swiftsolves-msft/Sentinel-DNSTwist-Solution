# Sentinel DNSTwist Solution

The following solution was inspired from reading Don Murdoch's Blue Team Handbook and coming across DNS Twist Algorithm and the amazing work and software written by Marcin Ulikowski , **special thanks** to Andrey Sheremetinskiy for helping unravel some issues and use cases in solution.

[Research from Blue Team Handbook by Don Murdoch](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898/)

[The DNSTwist GitHub Repository by Marcin Ulikowski](https://github.com/elceef/dnstwist?tab=readme-ov-file)

The following solution will contain the following

 1. Create a Defender EASM workspace
 2. Create a Azure Container Instance using DNSTwist WebApp Docker image
 3. Create a Sentinel Watchlist DNSTwist
 4. Create a LogicApp that reads the EASM Domain Inventory Data you export to Log Analytics workspace `EasmAsset_CL | where AssetType_s contains "Domain"` for new domains, then uses the DNSTwist API to generate lists of domain name fuzzing to look for, and export those lists into a Sentinel Watchlist.

Note: Deploy to the same resource group as Microsoft Sentinel.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fswiftsolves-msft%2FSentinel-DNSTwist-Solution%2Frefs%2Fheads%2Fmain%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fswiftsolves-msft%2FSentinel-DNSTwist-Solution%2Frefs%2Fheads%2Fmain%2Fazuredeploy.json)

## Futures:

 - Rework Logic App check domains against EXO/Entra domains listed in customer tenant
	 - match and tag / label in watchlist
	 - use as source for feeding as augment to EASM found Domains
	 - scheduler starts Azure Container Instance and Stops ACI on runs, saving compute costs
 - Develop Python Threat Hunting Notebook version using DNSTwist python library
 - Develop twisting for Cloud AWS / Azure / GCP known domains and hosts ? Ex. xxx.blob.core.windows.net
 - fork and further modification of webapp and dnstwist, and [docker image](https://hub.docker.com/r/swiftsolves/dnstwist_webapp) adjust api response and lookups for NS, A, and MX 
 - General speed improvements in solution, logics

## Additional Post Install Notes:

Upon success the following should be deployed:

![Azure deployment results](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/deploydetails.png)

***Defender EASM Setup:***

Upon opening Defender EASM workspace you will be prompted to enter your organizations name, this may take a few tries with a few names around your companies brand, after entering your name be sure to press enter to search for similar organizations.

![Defender EASM seed your initial organization](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/easmorgcreate.png)

In Defender EASM  - Data connections blade - add a connection to your existing Sentinel workspace. Set frequency **weekly** and schedule reoccurring on **Sunday**. Logic App runs the next day on Monday. For content you can choose **asset data** at a minimum.

![Defender EASM data connections to log analytics workspace](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/easmdataconnect.png)

You will be prompted to obtain on setting up the connection for your Sentinel's Log Analytics workspace key, to obtain this go to your log analytics workspace resource and the Agents tab, copy workspace ID and your primary key.

![Obtain your primary key from a log analytics workspace](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/getlawkey.png)

In the Defender EASM add data connection the field will be called Api key:

![Update the easm data connector to law with the required field data including the primary log analytics workspace key](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/seteasmdataconnect.png)

Wait 15minutes and be sure to check that the EamsAsset_CL table can be queried in the Log Analytics Workspace:

    EasmAsset_CL | Where AssetType_s == "DOMAIN"

![enter image description here](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/testlawquery.png)

***Update-DNSTwistWatchList***

The Logic App creates and uses a Managed System Identity (MSI) to update the Azure Sentinel Watchlist. 

Assign RBAC 'Azure Sentinel Contributor' role to the Logic App at the Resource Group level of the Log Analytics Workspace.
![On Logic App click on the Settings and Identity blade to assign a Sentinel Contributor role](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/logicappassignrolecreate.png)
![Assign the managed identity of the Logic App as a Sentinel Contributor](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/logicappassignrole.png)



***DNS Twist WebApp and API***
Test the following WebApp by going to the Public IP address of your Azure Container Instance using Http:// and port :8000 | http://xx.xx.xx.xx:8000 , enter a domain and press start. 

![Test and ensure DNS Twist is up and running](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/testacidnstwist.png)

If you want to learn more abot the APIs hosted refer to this [Open API Swagger document](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/blob/main/dnstwist_swagger.yaml).

***Run Logic App***
At this point you should now be able to run the Logic App with the prerequistes being met:

***Warning:*** Currently the initial load this may take 2 - 4 hours to complete the job

![ReRun the Logic App](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/rerunlogicapp.png)

***Microsoft Sentinel***

Be sure to look into threat hunting scenarios against your Firewall, Network Flow, DNS, and Proxy Logs. As an example using the VMConnection table from VMInsights Solution installed on Azure or Arc Connected servers:

![Sentinel Threat Hunting](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/threat%20hunting.png)

    let DNSTwistDomains = _GetWatchlist('DNSTwist')
	    | where fuzzer != "*original" //and TimeGenerated >= ago(30d)
	    | project domain;
    VMConnection
	    | where TimeGenerated >= ago(7d)
	    | extend DstDomain = iff(isnotempty(RemoteDnsQuestions), tostring(parse_json(RemoteDnsQuestions)[0]), "")
	    | where isnotempty(DstDomain) and DstDomain in~ (DNSTwistDomains)
	    | summarize Count = count(), Domains = make_set(DstDomain) by Computer, ProcessName, SourceIp, DestinationIp, DestinationPort, RemoteCountry

![enter image description here](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/raw/refs/heads/main/images/example.png)

## Fuzzers used

*More details* [can be found here](https://github.com/swiftsolves-msft/Sentinel-DNSTwist-Solution/blob/main/permutationstypes.csv)

| **Fuzzer**       | **Explanation**                                                                 |
|-------------------|---------------------------------------------------------------------------------|
| homoglyph        | Replaces characters with visually similar ones (e.g., "o" with "0" or "l" with "1"). |
| replacement      | Substitutes a character with another, often nearby on the keyboard (e.g., "a" to "s"). |
| omission         | Removes a single character from the domain (e.g., "google" to "gogle").          |
| transposition    | Swaps two adjacent characters (e.g., "google" to "goggle").                      |
| subdomain        | Adds a subdomain to the original domain (e.g., "google.com" to "login.google.com"). |
| *original        | Includes the original domain as entered, unchanged.                             |
| tld-swap         | Changes the top-level domain (e.g., "google.com" to "google.net").               |
| dictionary       | Adds words from a dictionary to the domain (e.g., "google" to "google-login").   |
| plural           | Adds an "s" or other plural forms to the domain (e.g., "google" to "googles").   |
| bitsquatting     | Alters a character to simulate a single-bit error (e.g., "google" to "goggle").  |
| repetition       | Repeats a character in the domain (e.g., "google" to "googgle").                 |
| hyphenation      | Inserts a hyphen in the domain (e.g., "google" to "goo-gle").                    |
| vowel-swap       | Replaces a vowel with another vowel (e.g., "google" to "guugle").                |
| insertion        | Inserts a single character into the domain (e.g., "google" to "googgle").        |
| addition         | Appends a character to the domain (e.g., "google" to "googlea").                 |
| various          | Combines multiple techniques for miscellaneous domain variations (e.g., "google" to "g0og1e"). |
