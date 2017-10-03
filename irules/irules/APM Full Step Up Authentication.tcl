when RULE_INIT {
	# to be changed prior to any publishing
	set passphrase "hEuoYjmFUpB4PcpO3bUdQtLP4ic7jjm"
}

when HTTP_REQUEST  {
	if { [HTTP::cookie exists MRHSession] and [ACCESS::session exists -state_allow -sid [HTTP::cookie MRHSession]] } {
		set strong_auth [ACCESS::session data get session.custom.last.authtype]
		if { [class match [HTTP::path] starts_with loa3_uri] and $strong_auth == 0 } {
			HTTP::cookie encrypt "MRHSession" $passphrase
			HTTP::respond 302 noserver "Location" "/strong?return_url=[URI::encode [HTTP::uri]]" "Cache-Control" "no-cache, must-revalidate" Set-Cookie "MRHSession=deleted;expires=Thu, 01-Jan-1970 00:00:10 GMT;path=/" Set-Cookie "LastMRH_Session=deleted;expires=Thu, 01-Jan-1970 00:00:10 GMT;path=/" Set-Cookie "Session1=[HTTP::cookie MRHSession];path=/"
		}
	}
}

when ACCESS_SESSION_STARTED {
	
	# decrypt Session1 cookie value
	set decrypted [HTTP::cookie decrypt "Session1" $passphrase]
    
	if { [HTTP::cookie exists Session1] and [ACCESS::session exists -state_allow -sid $decrypted] } {
		
		## section : retrieve session variables from the first session
		
		ACCESS::session data set session.custom.last.username [ACCESS::session data get session.logon.last.username -sid $decrypted]
		ACCESS::session data set session.custom.last.password [ACCESS::session data get session.logon.last.password -sid $decrypted]
		
		## End section
		
		ACCESS::session data set session.custom.last.authresult "true"
		
		# remove the first created session during standard authentication to avoid multiple active sessions
		ACCESS::session remove -sid $decrypted
	
	} elseif { [class match [HTTP::path] starts_with loa3_uri] } {
		ACCESS::session data set session.custom.last.strong 1
	}
}