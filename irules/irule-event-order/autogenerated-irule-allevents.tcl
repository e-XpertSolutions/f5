when RULE_INIT {
	set static::client_ip "192.168.10.1"
	set static::json 1
}

when CLIENT_ACCEPTED {
	set counter 0
	set event_type "CLIENT_ACCEPTED"
	set sessionid "[IP::client_addr][TCP::client_port][IP::local_addr][TCP::local_port][expr { int(100000000 * rand()) }]" 
    binary scan [md5 $sessionid] H* md5_string trash
	set md5_string [string range $md5_string 12 20]
	set start_time [clock clicks -milliseconds]
	log local0. "virtual=[virtual], id=$md5_string, time=0, event_order=$counter, event_type=$event_type"
	if { $static::json } {
		set json_log "\{ \"$md5_string\": \[\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"0\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
	}
}

when CLIENT_CLOSED {
	set counter [expr { $counter+1 }]
	set event_type "CLIENT_CLOSED"
	set curtime [expr { [clock clicks -milliseconds] - $start_time }]
	log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
	if { $static::json } {
		append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\}\]\}"
		log local0. "$json_log"
	}
}

when ACCESS_ACL_ALLOWED {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_ACL_ALLOWED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ACCESS_ACL_DENIED {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_ACL_DENIED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ACCESS_PER_REQUEST_AGENT_EVENT {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_PER_REQUEST_AGENT_EVENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ACCESS_POLICY_AGENT_EVENT {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_POLICY_AGENT_EVENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ACCESS_POLICY_COMPLETED {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_POLICY_COMPLETED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ACCESS_SESSION_CLOSED {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_SESSION_CLOSED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ACCESS_SESSION_STARTED {
         set counter [expr { $counter+1 }]
         set event_type "ACCESS_SESSION_STARTED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ADAPT_REQUEST_HEADERS {
         set counter [expr { $counter+1 }]
         set event_type "ADAPT_REQUEST_HEADERS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ADAPT_REQUEST_RESULT {
         set counter [expr { $counter+1 }]
         set event_type "ADAPT_REQUEST_RESULT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ADAPT_RESPONSE_HEADERS {
         set counter [expr { $counter+1 }]
         set event_type "ADAPT_RESPONSE_HEADERS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ADAPT_RESPONSE_RESULT {
         set counter [expr { $counter+1 }]
         set event_type "ADAPT_RESPONSE_RESULT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ASM_REQUEST_BLOCKING {
         set counter [expr { $counter+1 }]
         set event_type "ASM_REQUEST_BLOCKING"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ASM_REQUEST_DONE {
         set counter [expr { $counter+1 }]
         set event_type "ASM_REQUEST_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ASM_REQUEST_VIOLATION {
         set counter [expr { $counter+1 }]
         set event_type "ASM_REQUEST_VIOLATION"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ASM_RESPONSE_VIOLATION {
         set counter [expr { $counter+1 }]
         set event_type "ASM_RESPONSE_VIOLATION"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when AUTH_ERROR {
         set counter [expr { $counter+1 }]
         set event_type "AUTH_ERROR"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when AUTH_FAILURE {
         set counter [expr { $counter+1 }]
         set event_type "AUTH_FAILURE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when AUTH_RESULT {
         set counter [expr { $counter+1 }]
         set event_type "AUTH_RESULT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when AUTH_SUCCESS {
         set counter [expr { $counter+1 }]
         set event_type "AUTH_SUCCESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when AUTH_WANTCREDENTIAL {
         set counter [expr { $counter+1 }]
         set event_type "AUTH_WANTCREDENTIAL"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when AVR_CSPM_INJECTION {
         set counter [expr { $counter+1 }]
         set event_type "AVR_CSPM_INJECTION"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when BOTDEFENSE_ACTION {
         set counter [expr { $counter+1 }]
         set event_type "BOTDEFENSE_ACTION"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when BOTDEFENSE_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "BOTDEFENSE_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CACHE_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "CACHE_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CACHE_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "CACHE_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CACHE_UPDATE {
         set counter [expr { $counter+1 }]
         set event_type "CACHE_UPDATE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CATEGORY_MATCHED {
         set counter [expr { $counter+1 }]
         set event_type "CATEGORY_MATCHED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLASSIFICATION_DETECTED {
         set counter [expr { $counter+1 }]
         set event_type "CLASSIFICATION_DETECTED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLIENT_DATA {
         set counter [expr { $counter+1 }]
         set event_type "CLIENT_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLIENTSSL_CLIENTCERT {
         set counter [expr { $counter+1 }]
         set event_type "CLIENTSSL_CLIENTCERT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLIENTSSL_CLIENTHELLO {
         set counter [expr { $counter+1 }]
         set event_type "CLIENTSSL_CLIENTHELLO"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLIENTSSL_DATA {
         set counter [expr { $counter+1 }]
         set event_type "CLIENTSSL_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLIENTSSL_HANDSHAKE {
         set counter [expr { $counter+1 }]
         set event_type "CLIENTSSL_HANDSHAKE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when CLIENTSSL_SERVERHELLO_SEND {
         set counter [expr { $counter+1 }]
         set event_type "CLIENTSSL_SERVERHELLO_SEND"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when DIAMETER_EGRESS {
         set counter [expr { $counter+1 }]
         set event_type "DIAMETER_EGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when DIAMETER_INGRESS {
         set counter [expr { $counter+1 }]
         set event_type "DIAMETER_INGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when DNS_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "DNS_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when DNS_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "DNS_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ECA_REQUEST_ALLOWED {
         set counter [expr { $counter+1 }]
         set event_type "ECA_REQUEST_ALLOWED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ECA_REQUEST_DENIED {
         set counter [expr { $counter+1 }]
         set event_type "ECA_REQUEST_DENIED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when FIX_HEADER {
         set counter [expr { $counter+1 }]
         set event_type "FIX_HEADER"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when FIX_MESSAGE {
         set counter [expr { $counter+1 }]
         set event_type "FIX_MESSAGE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when FLOW_INIT {
         set counter [expr { $counter+1 }]
         set event_type "FLOW_INIT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GENERICMESSAGE_EGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GENERICMESSAGE_EGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GENERICMESSAGE_INGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GENERICMESSAGE_INGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GTP_GPDU_EGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GTP_GPDU_EGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GTP_GPDU_INGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GTP_GPDU_INGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GTP_PRIME_EGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GTP_PRIME_EGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GTP_PRIME_INGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GTP_PRIME_INGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GTP_SIGNALLING_EGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GTP_SIGNALLING_EGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when GTP_SIGNALLING_INGRESS {
         set counter [expr { $counter+1 }]
         set event_type "GTP_SIGNALLING_INGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTML_COMMENT_MATCHED {
         set counter [expr { $counter+1 }]
         set event_type "HTML_COMMENT_MATCHED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTML_TAG_MATCHED {
         set counter [expr { $counter+1 }]
         set event_type "HTML_TAG_MATCHED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_CLASS_FAILED {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_CLASS_FAILED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_CLASS_SELECTED {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_CLASS_SELECTED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_DISABLED {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_DISABLED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_PROXY_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_PROXY_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_REQUEST_DATA {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_REQUEST_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_REQUEST_RELEASE {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_REQUEST_RELEASE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_REQUEST_SEND {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_REQUEST_SEND"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_RESPONSE_CONTINUE {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_RESPONSE_CONTINUE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_RESPONSE_DATA {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_RESPONSE_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when HTTP_RESPONSE_RELEASE {
         set counter [expr { $counter+1 }]
         set event_type "HTTP_RESPONSE_RELEASE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ICAP_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "ICAP_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when ICAP_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "ICAP_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when IN_DOSL7_ATTACK {
         set counter [expr { $counter+1 }]
         set event_type "IN_DOSL7_ATTACK"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when IVS_ENTRY_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "IVS_ENTRY_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when IVS_ENTRY_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "IVS_ENTRY_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when LB_FAILED {
         set counter [expr { $counter+1 }]
         set event_type "LB_FAILED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when LB_QUEUED {
         set counter [expr { $counter+1 }]
         set event_type "LB_QUEUED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when LB_SELECTED {
         set counter [expr { $counter+1 }]
         set event_type "LB_SELECTED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when MR_EGRESS {
         set counter [expr { $counter+1 }]
         set event_type "MR_EGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when MR_FAILED {
         set counter [expr { $counter+1 }]
         set event_type "MR_FAILED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when MR_INGRESS {
         set counter [expr { $counter+1 }]
         set event_type "MR_INGRESS"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when NAME_RESOLVED {
         set counter [expr { $counter+1 }]
         set event_type "NAME_RESOLVED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when PCP_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "PCP_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when PCP_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "PCP_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when PEM_POLICY {
         set counter [expr { $counter+1 }]
         set event_type "PEM_POLICY"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when PERSIST_DOWN {
         set counter [expr { $counter+1 }]
         set event_type "PERSIST_DOWN"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when QOE_PARSE_DONE {
         set counter [expr { $counter+1 }]
         set event_type "QOE_PARSE_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when REWRITE_REQUEST_DONE {
         set counter [expr { $counter+1 }]
         set event_type "REWRITE_REQUEST_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when REWRITE_RESPONSE_DONE {
         set counter [expr { $counter+1 }]
         set event_type "REWRITE_RESPONSE_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when RTSP_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "RTSP_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when RTSP_REQUEST_DATA {
         set counter [expr { $counter+1 }]
         set event_type "RTSP_REQUEST_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when RTSP_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "RTSP_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when RTSP_RESPONSE_DATA {
         set counter [expr { $counter+1 }]
         set event_type "RTSP_RESPONSE_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVER_CLOSED {
         set counter [expr { $counter+1 }]
         set event_type "SERVER_CLOSED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVER_CONNECTED {
         set counter [expr { $counter+1 }]
         set event_type "SERVER_CONNECTED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVER_DATA {
         set counter [expr { $counter+1 }]
         set event_type "SERVER_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVERSSL_CLIENTHELLO_SEND {
         set counter [expr { $counter+1 }]
         set event_type "SERVERSSL_CLIENTHELLO_SEND"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVERSSL_DATA {
         set counter [expr { $counter+1 }]
         set event_type "SERVERSSL_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVERSSL_HANDSHAKE {
         set counter [expr { $counter+1 }]
         set event_type "SERVERSSL_HANDSHAKE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SERVERSSL_SERVERHELLO {
         set counter [expr { $counter+1 }]
         set event_type "SERVERSSL_SERVERHELLO"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SIP_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "SIP_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SIP_REQUEST_DONE {
         set counter [expr { $counter+1 }]
         set event_type "SIP_REQUEST_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SIP_REQUEST_SEND {
         set counter [expr { $counter+1 }]
         set event_type "SIP_REQUEST_SEND"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SIP_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "SIP_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SIP_RESPONSE_DONE {
         set counter [expr { $counter+1 }]
         set event_type "SIP_RESPONSE_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SIP_RESPONSE_SEND {
         set counter [expr { $counter+1 }]
         set event_type "SIP_RESPONSE_SEND"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when SOCKS_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "SOCKS_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when STREAM_MATCHED {
         set counter [expr { $counter+1 }]
         set event_type "STREAM_MATCHED"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when USER_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "USER_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when USER_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "USER_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_CLIENT_DATA {
         set counter [expr { $counter+1 }]
         set event_type "WS_CLIENT_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_CLIENT_FRAME {
         set counter [expr { $counter+1 }]
         set event_type "WS_CLIENT_FRAME"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_CLIENT_FRAME_DONE {
         set counter [expr { $counter+1 }]
         set event_type "WS_CLIENT_FRAME_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_REQUEST {
         set counter [expr { $counter+1 }]
         set event_type "WS_REQUEST"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_RESPONSE {
         set counter [expr { $counter+1 }]
         set event_type "WS_RESPONSE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_SERVER_DATA {
         set counter [expr { $counter+1 }]
         set event_type "WS_SERVER_DATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_SERVER_FRAME {
         set counter [expr { $counter+1 }]
         set event_type "WS_SERVER_FRAME"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when WS_SERVER_FRAME_DONE {
         set counter [expr { $counter+1 }]
         set event_type "WS_SERVER_FRAME_DONE"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_BEGIN_DOCUMENT {
         set counter [expr { $counter+1 }]
         set event_type "XML_BEGIN_DOCUMENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_BEGIN_ELEMENT {
         set counter [expr { $counter+1 }]
         set event_type "XML_BEGIN_ELEMENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_CDATA {
         set counter [expr { $counter+1 }]
         set event_type "XML_CDATA"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_CONTENT_BASED_ROUTING {
         set counter [expr { $counter+1 }]
         set event_type "XML_CONTENT_BASED_ROUTING"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_END_DOCUMENT {
         set counter [expr { $counter+1 }]
         set event_type "XML_END_DOCUMENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_END_ELEMENT {
         set counter [expr { $counter+1 }]
         set event_type "XML_END_ELEMENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
when XML_EVENT {
         set counter [expr { $counter+1 }]
         set event_type "XML_EVENT"
         set curtime [expr { [clock clicks -milliseconds] - $start_time }]
         log local0. "virtual=[virtual], id=$md5_string, time=$curtime, event_order=$counter, event_type=$event_type"
         if { $static::json } {
                append json_log "\{\"virtual\":\"[virtual]\", \"id\":\"$md5_string\", \"time\":\"$curtime\", \"event_order\":\"$counter\", \"event_type\":\"$event_type\"\},"
         }
}
