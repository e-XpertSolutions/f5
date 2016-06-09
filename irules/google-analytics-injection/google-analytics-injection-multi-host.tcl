when RULE_INIT {
    set static::default_trackingid "UA-XXXXX-Y"
}

when HTTP_REQUEST {
    HTTP::header remove "Accept-Encoding"
    set host [HTTP::host]
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
    set tracking_id [class match -value -- $host equals HOST_TRACKING_MAPPING]
    if { $tracking_id eq "" } {
        set tracking_id $static::default_trackingid
    }
    HTTP::payload replace 0 $content_length [string map [list $search "[subst -nocommands -nobackslashes [ifile get google.js]]</head>"] [HTTP::payload]]
    HTTP::release
}