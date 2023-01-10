The purpose of this app to to query urls to determine if they are present in the APWG database. 

The filters determine how the url is looked up in the database.
	URL_exact - query the database exactly with the url provided
	domain - query the database using only the domain of the url
	url - query the database using everything before the path of the url. This will return many results if https:// or any other common URL components are included 
	
Sanitize_url - removes the path of the url, this is to exclude any sensitive information that might be in the the url. THIS DOES NOT WORK WITH URL_exact

