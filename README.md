# Sentinel DNSTwist Solution

### *Work in Progress - final solution and steps may be different*

The following solution was inspired from reading Don Murdoch's Blue Team Handbook and coming across DNS Twist Algorithim and the amazing work and software written by Marcin Ulikowski

[Research from Blue Team Handbook by Don Murdoch](https://www.amazon.com/Blue-Team-Handbook-Condensed-Operations/dp/1091493898/)

[The DNSTwist GitHub Repository](https://github.com/elceef/dnstwist?tab=readme-ov-file)

The following solution will contain the following

 1. Create a Defender EASM workspace
 2. Create a Log Analytics Workspace
 3. Create a Azure Container and Using DNSTwist
 4. Create a LogicApp that reads the EASM Domain Inventory Data or KQL Query Log Analytics workspace `EasmAsset_CL | where AssetType_s contains "Domain"` for new domains and loads them into DNSTwist, then uses the DNSTwist APIs to generate lists of domain name fuzzing to look for, and export those lists into a Sentinel Watchlist.
 5. A Sentinel Analytic Rule using IM Parsers to match in DNSTwist Domains ?

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fswiftsolves-msft%2Fmaster%2FSentinel-DNSTwist-Solution%2Fazuredeploy.json)
[![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fswiftsolves-msft%2Fmaster%2FSentinel-DNSTwist-Solution%2Fazuredeploy.json)

**Additional Post Install Notes:**

Authorize the web.connection APIs deployed into the ResourceGroup.

The Logic App creates and uses a Managed System Identity (MSI) to update the Azure Sentinel Watchlist. 

Assign RBAC 'Azure Sentinel Contributor' role to the Logic App at the Resource Group level of the Log Analytics Workspace.

In Defender EASM  - Data connections blade - add a connection to the newly create log analytics workspace. Set frequency **weekly** and schedule reoccurring on **Sunday**. Logic App runs the next day on Monday. For content you can choose **asset data** at a minimum.

## Fuzzers used

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
