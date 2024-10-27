# Project name tbd

## Idea: 
**Input:** Gitlab SAST-Scan output .json file
(provide path to file as argument when running application)

--> read file
--> Extract each listed vulnerability 
--> write each vulnerability into a SQLite-database
--> provide commands to fetch vulnerabilities from db
--> list fetched vulnerabilities with comfy-table crate