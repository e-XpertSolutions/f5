when RULE_INIT {
	set static::tracking_id "UA-XXXXX-Y"
	set static::siteid "XXXXX"
	set static::piwik_url "https://www.piwik.url/piwik/piwik"
}
 
when HTTP_REQUEST {
	HTTP::header remove "Accept-Encoding"
}
 
when HTTP_RESPONSE {
	if { [HTTP::header Content-Type] contains "text/html" } {
		if { [HTTP::header exists "Content-Length"] } {
			set content_length [HTTP::header "Content-Length"]
		} else {
			set content_length 1000000
		}
		if { $content_length > 0 } {
			HTTP::collect $content_length
		}
	}
}
when HTTP_RESPONSE_DATA { 
    set search "</head>"
    HTTP::payload replace 0 $content_length [string map [list $search "[subst -nocommands -nobackslashes [ifile get google.js]]</head>"] [HTTP::payload]]
    HTTP::release
}