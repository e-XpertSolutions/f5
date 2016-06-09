when RULE_INIT {
	set static::holdtime 3600
	set static::login_url "/login"
	set static::sideband_vs "VS_EXTERNAL_AUTH_PROVIDER"
}
 
when HTTP_REQUEST {
	if { [HTTP::cookie exists SessionCook] and [table lookup -subtable "active_sessions" [HTTP::cookie SessionCook]] != "" } {
		return
	} else {
		if { [HTTP::path] eq $static::login_url } {
			if { [HTTP::method] eq "POST" } {
				if {[HTTP::header "Content-Length"] ne "" && [HTTP::header "Content-Length"] <= 1048576}{
					set content_length [HTTP::header "Content-Length"]
				} else {
					set content_length 1048576
				}
				if { $content_length > 0} {
					HTTP::collect $content_length
				}
			} else {
				HTTP::respond 200 content [ifile get login.html] "Cache-Control" "no-cache, must-revalidate" "Content-Type" "text/html"
			}
		} else {
			HTTP::respond 302 noserver "Location" $static::login_url "Cache-Control" "no-cache, must-revalidate" Set-Cookie "SessionCook=$result;domain=[HTTP::host];path=/"
		}
	}	
}
 
when HTTP_REQUEST_DATA {
	set payload [HTTP::payload]
	set username ""
	set password ""
	regexp {Login1\%3AtxtUserName\=(.*)\&Login1\%3AtxtPassword\=(.*)\&Login1\%3AbtnSubmit\=(.*)} $payload -> username password garbage
	  
	if {[catch {connect -timeout 1000 -idle 30 -status conn_status $static::sideband_vs} conn_id] == 0 && $conn_id ne ""}{
		log local0. "Connect returns: $conn_id and conn status: $conn_status"
	} else {
		log local0. "Connection could not be established to sideband_virtual_server"
	}
	
	set content [subst -nocommands -nobackslashes [ifile get soap_body]]
	set length [string length $content]
	set data "POST /apppath/webservicename.asmx HTTP/1.1\r\nHost: www.hostname.com\r\nContent-Type: text/xml; charset=utf-8\r\nContent-Length: $length\r\nSOAPAction: http://schemas.microsoft.com/sqlserver/2004/SOAP\r\n\r\n$content"
	
	set send_bytes [send -timeout 1000 -status send_status $conn_id $data]
	set recv_data [recv -timeout 1000 $conn_id]
 
	# parse response to retrieve the authentication result, it gives 0 if authentication failed or a session_id if it succeed 
	regexp {<authResult>(.*)</authResult>(.*)} $recv_data -> result garbage
 
	unset content
	unset length
	unset data
	unset recv_data
	close $conn_id
	
	# add a custom alert notification to the login page
	
	
	if { $result == 0 } {
		set alert "<div class=\"alert alert-danger\"><strong> Invalid credentials.</strong></div>"
		HTTP::respond 200 content [subst -nocommands -nobackslashes [ifile get login.html]] "Cache-Control" "no-cache, must-revalidate" "Content-Type" "text/html" Set-Cookie "SessionCook=deleted;expires=Thu, 01-Jan-1970 00:00:10 GMT;domain=[HTTP::host];path=/"
	} else {
		HTTP::respond 302 noserver "Location" "/" "Cache-Control" "no-cache, must-revalidate" Set-Cookie "SessionCook=$result;domain=[HTTP::host];path=/"
		
		# save the cookie value in a cache for fast checking
		table add -subtable "active_sessions" $result $username indef $static::holdtime	
	}
}