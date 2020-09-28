# ![App icon](static/appIcon.png) Fuzzylookup - Splunk App by [Deductiv](https://www.deductiv.net/)  

This app allows you to apply fuzzy logic to lookups from your search result fields for near-matches.  Use cases include:  

- Domain analysis (lookalike domains)  
- Blacklist similarity  
- Typo identification  

##### Supported Splunk versions: 7.3.x, 8.0.x
##### Configuration Steps: N/A
* * *
## Fuzzylookup search command (fuzzylookup)  
### Syntax:  
	search | fuzzylookup 
		[ prefix=<string> ]
		[ addmetrics=[True|False] ]
		[ lookupfilter=<kvpairs> ]
		[ mask=<regex> ]
		[ delete=<regex> ]
		<lookup-table-name> 
		( <lookup-field> [AS <event-field>] ) 
		[ OUTPUT | OUTPUTNEW (<lookup-destfield> [AS <event-destfield>] ) ... ]

### Description
Cross-reference your search fields against lookup data for non-exact matches, with the fields from the lookup entry/entries with the best score being appended to the event. 

- The Levenstein algorithm (from the jellyfish library) is applied to compute a match score.  
	- If there are multiple entries with the same score, the tie is broken by how many characters are exact matches.  
	- If multiple entries still have the same result, the lookup data is added to the event as multivalue fields.  
- Lookups can be filtered to limit comparisons with event fields and improve performance. Wildcards are supported.  
	- Static filters apply for the entire lookup and limit the global dataset being used.  
	- Dynamic filters take data from each search result into account, and reference event field names.  
	- The following example contains a static filter followed by a dynamic filter, which references the *email\_domain* field in each event:  
##
	lookupfilter="LookupField1=\"local admin\" Lookupfield2=\"*@$email_domain$\""  
- Data filtering is supported to limit the number of comparisons being made.  
	- For example, a email address comparisons can be limited to those where the domains match:  
- Text masking and deletion is supported via regex. This masks or deletes the event field data and the lookup data in memory, prior to any comparisons being made.  
	- Data can be sanitized before comparison to treat certain character classes equally. The following example deletes the domain from an email address, deletes dot (.) and underscore (\_), and masks all numbers. 
##
	delete="(@[^@]+$|\\.|_)" mask="[0-9]"

### Arguments  
- #### Prefix  
	**Syntax:** prefix=&lt;prefix_text&gt;  
	**Description:** Text to prefix all output field names with. Helpful for applying to every lookup field without aliasing each one.  
- #### Add Metrics  
	**Syntax:** addmetrics=[True|False]  
	**Description:** Add fuzzy match metrics to each result (score, matching characters, similarity score, consecutive match length).  
	**Default:** False
- #### Lookup Filter  
	**Syntax:** lookupfilter="&lt;lookup_field&gt;=\\"lookup_value\\&quot; &lt;lookup_field&gt;=\\"$event_field$\\""  
	**Description:** Filter for data in the specified lookup to reduce the number of comparisons  
- #### Text Masking  
	**Syntax:** mask="&lt;regular expression&gt;"  
	**Description:** Mask pattern for both compared sets of values. Masks the regex matched text before comparing.  
- #### Text Deletion  
	**Syntax:** delete="&lt;regular expression&gt;"  
	**Description:** Deletion pattern for both compared sets of values. Removes the regex matched text before comparing.  
- ### Standard lookup operators (see *Syntax*)  

# Support  

Having trouble with the app? Feel free to [email us](mailto:contact@deductiv.net) and we’ll help you sort it out. You can also [reach the author](https://splunk-usergroups.slack.com/team/U30E9LS79) on the Splunk Community Slack.  

# Features  

We love hearing your feedback and ideas for our apps.  Please [email](mailto:contact@deductiv.net) your suggestions!  

# Blogs  

Check out our blog article on the topic: [Gettin' Fuzzy With It](https://www.deductiv.net/blog/gettin-fuzzy-with-it).  
