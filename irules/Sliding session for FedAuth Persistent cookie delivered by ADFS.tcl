when RULE_INIT {
	set static::timeout 900
	set static::httponly 1
	set static::debug 0
	set static::irule_name "irule-test-sliding-session"
}

when HTTP_REQUEST {
	if { $static::debug } { set event "HTTP_REQUEST" }
	set hostname [string tolower [HTTP::host]]
	switch -glob $hostname {
		"sharepoint1" - 
		"sharepoint2" {
			set key ""
			set valid 1
			if { [HTTP::cookie exists FedAuth] } {
				set key [sha1 "$hostname:[HTTP::cookie FedAuth]"]
				if { [table lookup $key] == "" } {
					if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: no valid sliding session key found for [IP::client_addr] with session FedAuth:[string range [HTTP::cookie FedAuth] 0 7] on $hostname - Action: redirect user to logout uri" }
					
					HTTP::redirect "https://[HTTP::host]/_trust/default.aspx?wa=wsignoutcleanup1.0"
				} else {
					if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: a valid key has been found for [IP::client_addr] with session FedAuth:[string range [HTTP::cookie FedAuth] 0 7] on $hostname" }
				}
			}
		}
		default { set valid 0 }
	}
}

when HTTP_RESPONSE {
	if { $static::debug } { set event "HTTP_RESPONSE" }
	if {[HTTP::cookie exists FedAuth] and $valid } {
		
		if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: set-cookie header found with FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) for [IP::client_addr]" }
		
		set key [sha1 "$hostname:[HTTP::cookie FedAuth]"]
		
		if { [table lookup $key] != "" } {
			if { [table lifetime -remaining $key] >= $static::timeout } {
				
				table timeout $key $static::timeout
				HTTP::cookie expires FedAuth $static::timeout relative
				
				if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : cookie expiration set to 300 seconds" }
			} else {
				HTTP::cookie expires FedAuth [table lifetime -remaining $key] relative
				
				if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : cookie expiration set to remaining lifetime" }
			}
		} else {
			table add $key [HTTP::cookie FedAuth] $static::timeout [HTTP::cookie expires FedAuth]
			
			if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : Add cookie to the sliding session table for [HTTP::cookie expires FedAuth] seconds" }
			
			#HTTP::cookie expires FedAuth $static::timeout relative
			
			if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : set cookie to expires within 300 seconds" }
		}
	} elseif { $key != "" } {
		if { [table lookup $key] != "" } {
			if { [table lifetime -remaining $key] >= $static::timeout } {
				
				table timeout $key $static::timeout
				
				if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : insert FedAuth session cookie with 300 seconds expiration time" }
				
				HTTP::cookie insert name FedAuth value [table lookup $key] path /
				HTTP::cookie expires FedAuth $static::timeout relative
				HTTP::cookie secure FedAuth enable
				
				if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : insert FedAuth session cookie with 300 seconds expiration time" }
				
			} else {
				HTTP::cookie insert name FedAuth value [table lookup $key] path /
				HTTP::cookie expires FedAuth [table lifetime -remaining $key] relative
				HTTP::cookie secure FedAuth enable
				
				if { $static::debug } { log local0. "$static::irule_name - [string map -nocase {"/common/" ""} [virtual name]]: FedAuth cookie ([string range [HTTP::cookie FedAuth] 0 7]) valid for [table lifetime -remaining $key] seconds - Action : insert FedAuth session cookie" }
			}
			
			#
			# insert httponly flag to FedAuth Cookie
			#
			
			if { $static::httponly } {
				set value [HTTP::cookie value FedAuth]
				set testvalue [string tolower $value]
				set valuelen [string length $value]
				switch -glob $testvalue {
				  "*;httponly*" -
				  "*; httponly*" { }
				  default { set value "$value; HttpOnly"; }
				}
				if { [string length $value] > $valuelen} {
				  HTTP::cookie value FedAuth "${value}"
				}
			}
		}
	}
}